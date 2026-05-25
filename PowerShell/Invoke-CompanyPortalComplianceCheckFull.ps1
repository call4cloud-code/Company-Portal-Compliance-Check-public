<#
    Invoke-CompanyPortalComplianceCheckFull.ps1

    PowerShell version of the CompanyPortalComplianceCheck WinForms application.

    It follows the same flow as the GUI:
    1. Finds the Microsoft Intune MDM Device CA certificate.
    2. Reads the local device id from the certificate.
    3. Uses the MDM certificate to discover the Intune service location.
    4. Acquires the Company Portal IWService token through WAM.
    5. Queries IWService for the enrolled device object.
    6. Captures LastContact and compliance state before the trigger.
    7. Triggers local MDM sync and IME app sync.
    8. Posts Devices(guid'<id>')/CheckCompliance.
    9. Polls IWService until a newer LastContact and a final compliance state are observed, or until the timeout expires.

    Run this in the logged on user context. Running as SYSTEM is not recommended because the IWService token is user based.
#>

[CmdletBinding()]
param(
    [switch]$SilentWamOnly,

    [ValidateRange(30, 3600)]
    [int]$TimeoutSeconds = 600,

    [ValidateRange(5, 300)]
    [int]$PollSeconds = 30,

    [switch]$SkipMdmSync,
    [switch]$SkipImeSync,
    [switch]$SkipPolling,
    [switch]$NoStaRelaunch
)

if (-not $NoStaRelaunch -and [System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
    $winPs = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $winPs) {
        $args = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-NoStaRelaunch', '-TimeoutSeconds', "$TimeoutSeconds", '-PollSeconds', "$PollSeconds")
        if ($SilentWamOnly) { $args += '-SilentWamOnly' }
        if ($SkipMdmSync) { $args += '-SkipMdmSync' }
        if ($SkipImeSync) { $args += '-SkipImeSync' }
        if ($SkipPolling) { $args += '-SkipPolling' }

        $process = Start-Process -FilePath $winPs -ArgumentList $args -Wait -PassThru
        exit $process.ExitCode
    }
}

# StrictMode is intentionally not enabled here. Some WAM and WinRT objects expose dynamic properties.
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:LogFolder = Join-Path $env:TEMP 'CompanyPortalComplianceCheck'
$script:LogFile = Join-Path $script:LogFolder ("CompanyPortalComplianceCheck_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

$script:CompanyPortalClientId = '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223'
$script:IWServiceResource = 'b8066b99-6e67-41be-abfa-75db1a2c8809'
$script:IWServiceToken = $null
$script:LastIWServiceStatusCode = $null
$script:LastIWServiceStatusDescription = $null

$script:WamProviderUrl = 'https://login.microsoft.com'
$script:WamAuthority = 'https://login.microsoftonline.com/common'
$script:WamProvider = $null
$script:WamProviderAuthority = $null
$script:WamWebAccount = $null
$script:WamUserId = $null
$script:WamAsTaskMethod = $null
$script:WamWinRTRuntimePath = $null
$script:WamDesktopInteropReady = $false
$script:WamTProvider = $null
$script:WamTTokenResult = $null
$script:WamTTokenResultAsyncOperationGuid = $null
$script:WamWinRTInitialized = $false

function Write-Log {
    param([string]$Message)

    if ($null -eq $Message) { $Message = '' }

    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message

    try {
        if (-not (Test-Path $script:LogFolder)) {
            New-Item -Path $script:LogFolder -ItemType Directory -Force | Out-Null
        }
        Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    }
    catch { }

    Write-Host $line
}

function Write-TestLog {
    param(
        [ValidateSet('INFO','VERB','WARN','ERR')]
        [string]$Level = 'INFO',
        [string]$Category = 'WAM',
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Log "[$Level][$Category] $Message"
}

function Test-IsAdmin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    }
    catch {
        return $false
    }
}

function ConvertFrom-JwtPayload {
    param([Parameter(Mandatory)][string]$Jwt)

    try {
        $parts = $Jwt.Split('.')
        if ($parts.Count -lt 2) { return $null }

        $payload = $parts[1]
        switch ($payload.Length % 4) {
            0 { }
            2 { $payload += '==' }
            3 { $payload += '=' }
            default { return $null }
        }

        $payload = $payload.Replace('-', '+').Replace('_', '/')
        $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
        return $json | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function Get-JwtExpiryLocal {
    param([object]$Claims)

    if ($null -eq $Claims -or $null -eq $Claims.exp) { return $null }

    try {
        return ([DateTimeOffset]::FromUnixTimeSeconds([int64]$Claims.exp).UtcDateTime).ToLocalTime()
    }
    catch {
        return $null
    }
}

function Get-JwtClaimText {
    param(
        [Parameter(Mandatory)] [object]$Claims,
        [Parameter(Mandatory)] [string]$Name
    )

    try {
        $prop = $Claims.PSObject.Properties |
            Where-Object { $_.Name -ieq $Name } |
            Select-Object -First 1

        if (-not $prop -or $null -eq $prop.Value) { return '' }

        if ($prop.Value -is [System.Array]) {
            return (($prop.Value | ForEach-Object { "$_" }) -join ', ')
        }

        return "$($prop.Value)"
    }
    catch {
        return ''
    }
}

function Write-JwtClaimSummary {
    param(
        [Parameter(Mandatory)] [string]$Token,
        [string]$Label = 'Token'
    )

    try {
        $claims = ConvertFrom-JwtPayload -Jwt $Token
        if (-not $claims) {
            Write-Log "$Label claims could not be decoded."
            return
        }

        $expLocal = Get-JwtExpiryLocal -Claims $claims
        $aud = Get-JwtClaimText -Claims $claims -Name 'aud'
        $appid = Get-JwtClaimText -Claims $claims -Name 'appid'
        $azp = Get-JwtClaimText -Claims $claims -Name 'azp'
        $scp = Get-JwtClaimText -Claims $claims -Name 'scp'
        $roles = Get-JwtClaimText -Claims $claims -Name 'roles'
        $deviceId = Get-JwtClaimText -Claims $claims -Name 'deviceid'

        Write-Log "$Label aud: $aud"
        Write-Log "$Label appid: $appid"
        Write-Log "$Label azp: $azp"
        if ($scp) { Write-Log "$Label scp: $scp" }
        if ($roles) { Write-Log "$Label roles: $roles" }
        if ($deviceId) { Write-Log "$Label deviceid: $deviceId" }
        if ($expLocal) { Write-Log "$Label expires local: $expLocal" }
    }
    catch {
        Write-Log "Could not decode $Label claims: $($_.Exception.Message)"
    }
}

function Find-IntuneMDMCertificateInStore {
    param(
        [Parameter(Mandatory)] [ValidateSet('LocalMachine','CurrentUser')]
        [string]$StoreLocation
    )

    $mdmOid = '1.2.840.113556.5.6'
    $issuer = 'Microsoft Intune MDM Device CA'
    $store = New-Object Security.Cryptography.X509Certificates.X509Store('My', $StoreLocation)

    try {
        $store.Open('ReadOnly')

        $matches = @(
            $store.Certificates |
                Where-Object {
                    $hasMdmOid = @($_.Extensions | Where-Object { $_.Oid.Value -eq $mdmOid }).Count -gt 0
                    ($_.Issuer -like "*$issuer*") -and $hasMdmOid
                } |
                Sort-Object HasPrivateKey, NotAfter -Descending
        )

        if ($matches.Count -gt 0) { return $matches[0] }
        return $null
    }
    finally {
        try { $store.Close() } catch { }
    }
}

function Get-IntuneMDMCertAndIDs {
    Write-Log 'Searching for the Microsoft Intune MDM device certificate.'

    $cert = Find-IntuneMDMCertificateInStore -StoreLocation 'LocalMachine'
    $storeLocation = 'LocalMachine\My'

    if (-not $cert) {
        Write-Log 'Certificate not found in LocalMachine\My. Trying CurrentUser\My.'
        $cert = Find-IntuneMDMCertificateInStore -StoreLocation 'CurrentUser'
        $storeLocation = 'CurrentUser\My'
    }

    if (-not $cert) {
        throw 'No Microsoft Intune MDM Device CA certificate found in LocalMachine\My or CurrentUser\My.'
    }

    if (-not $cert.HasPrivateKey) {
        Write-Log 'WARNING: certificate found, but the private key is not available in this context. Discovery can fail.'
    }

    if ($cert.Subject -notmatch '^CN=([0-9a-fA-F-]{36})') {
        throw "Could not parse the device id from the certificate subject: $($cert.Subject)"
    }

    $deviceId = [guid]$Matches[1]
    $accountId = $null
    $mdmOid = '1.2.840.113556.5.6'

    foreach ($ext in $cert.Extensions) {
        if ($ext.Oid.Value -eq $mdmOid) {
            $bytes = $null
            if ($ext.RawData.Length -eq 16) {
                $bytes = $ext.RawData
            }
            elseif ($ext.RawData.Length -eq 18 -and $ext.RawData[0] -eq 4 -and $ext.RawData[1] -eq 16) {
                $bytes = $ext.RawData[2..17]
            }

            if ($bytes) { $accountId = [guid][byte[]]$bytes }
            break
        }
    }

    Write-Log "Using certificate from $storeLocation."
    Write-Log "MDM certificate device id: $deviceId"
    if ($accountId) { Write-Log "MDM certificate account id: $accountId" }

    return [PSCustomObject]@{
        Cert = $cert
        CertStoreLocation = $storeLocation
        DeviceId = $deviceId
        AccountId = $accountId
    }
}

function Get-IntuneLocationServiceUrls {
    $urls = @()
    $key = 'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts'

    if (Test-Path $key) {
        foreach ($sub in Get-ChildItem $key -ErrorAction SilentlyContinue) {
            $addrPath = "$($sub.PSPath)\Protected\AddrInfo"
            try {
                $addr = Get-ItemProperty -Path $addrPath -Name Addr -ErrorAction Stop
                if ($addr.Addr -and $addr.Addr -notlike '*checkin.dm.microsoft.com*') {
                    $uri = [uri]$addr.Addr
                    $fqdn = "$($uri.Scheme)://$($uri.Host)"
                    if ($urls -notcontains $fqdn) { $urls += $fqdn }
                }
            }
            catch { }
        }
    }

    if (-not $urls) {
        $urls = @('https://manage.microsoft.com')
        Write-Log "No OMADM service URL found. Using default: $($urls[0])"
    }
    else {
        Write-Log "Location service candidates: $($urls -join ', ')"
    }

    return $urls
}

function Query-LocationService {
    param(
        [Parameter(Mandatory)] [string[]]$LocationServiceUrls,
        [Parameter(Mandatory)] [Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )

    $discoPath = '/RestUserAuthLocationService/RestUserAuthLocationService/Certificate/ServiceAddresses'

    foreach ($fqdn in $LocationServiceUrls) {
        $url = "$fqdn$discoPath"
        Write-Log "Querying discovery endpoint: $url"

        try {
            $req = [Net.HttpWebRequest]::Create($url)
            $req.Method = 'GET'
            $req.Timeout = 30000
            $req.ClientCertificates.Add($Cert) | Out-Null
            $req.Headers.Add('client-request-id', ([guid]::NewGuid()).Guid)
            $req.Headers.Add('Cache-Control', 'no-cache')
            $req.Headers.Add('Pragma', 'no-cache')

            $resp = $req.GetResponse()
            $reader = New-Object IO.StreamReader $resp.GetResponseStream()
            $json = $reader.ReadToEnd()
            $reader.Close()
            $resp.Close()

            $result = $json | ConvertFrom-Json -ErrorAction Stop

            foreach ($entry in $result) {
                if ($entry.IsPrimary -eq $true) {
                    $svc = $entry.Services |
                        Where-Object { $_.ServiceName -eq 'SideCarGatewayService' } |
                        Select-Object -First 1

                    if ($svc -and $svc.Url -is [string] -and $svc.Url.Trim()) {
                        $cleanUrl = ([string]$svc.Url).Trim()
                        Write-Log "Found SideCarGatewayService URL: $cleanUrl"
                        return $cleanUrl
                    }
                }
            }
        }
        catch {
            Write-Log "Discovery request failed for $fqdn. $($_.Exception.Message)"
        }
    }

    throw 'Could not discover the Intune service location.'
}

function Get-IWServiceBaseUrlFromSideCarEndpoint {
    param([Parameter(Mandatory)] [string]$Endpoint)

    try {
        $uri = [uri]$Endpoint
        $endpointHost = $uri.Host

        if ($endpointHost -match '^fef\.') {
            return "https://$endpointHost"
        }

        if ($endpointHost -match '^agents\.(?<rest>.+)$') {
            return "https://fef.$($Matches.rest)"
        }

        if ($endpointHost -match '^(?<first>[^.]+)\.(?<rest>.+manage\.microsoft\.com)$') {
            return "https://fef.$($Matches.rest)"
        }

        if ($endpointHost -eq 'manage.microsoft.com') {
            return 'https://fef.manage.microsoft.com'
        }

        return "https://$endpointHost"
    }
    catch {
        throw "Could not derive the IWService base URL from [$Endpoint]. $($_.Exception.Message)"
    }
}

function Initialize-WinRT {
    if ($script:WamWinRTInitialized) { return }

    $clrDir = [Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
    $rtPath = Join-Path $clrDir 'System.Runtime.WindowsRuntime.dll'

    if (-not (Test-Path $rtPath)) {
        $rtPath = Get-ChildItem 'C:\Windows\Microsoft.NET' -Recurse -Filter 'System.Runtime.WindowsRuntime.dll' -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -First 1 -ExpandProperty FullName
    }

    if (-not $rtPath) { throw 'Cannot locate System.Runtime.WindowsRuntime.dll.' }

    $asm = [Reflection.Assembly]::LoadFrom($rtPath)
    $script:WamWinRTRuntimePath = $rtPath
    Write-TestLog VERB WAM "Loaded: $rtPath"

    $extType = $null
    foreach ($typeName in @('System.WindowsRuntimeSystemExtensions','System.Runtime.WindowsRuntime.WindowsRuntimeSystemExtensions')) {
        $extType = $asm.GetType($typeName, $false)
        if ($null -ne $extType) { break }
    }

    if ($null -eq $extType) {
        $extType = $asm.GetTypes() |
            Where-Object { $_.FullName -like '*WindowsRuntimeSystemExtensions' } |
            Select-Object -First 1
    }

    if ($null -eq $extType) { throw 'WindowsRuntimeSystemExtensions not found.' }

    $bf = [Reflection.BindingFlags]'Public,Static'
    $script:WamAsTaskMethod = $extType.GetMethods($bf) |
        Where-Object {
            $_.Name -eq 'AsTask' -and
            $_.IsGenericMethod -and
            $_.GetGenericArguments().Count -eq 1 -and
            $_.GetParameters().Count -eq 1
        } |
        Select-Object -First 1

    if ($null -eq $script:WamAsTaskMethod) {
        throw "AsTask<T> overload not found on $($extType.FullName)."
    }

    $null = [Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager, Windows.Security.Authentication.Web.Core, ContentType=WindowsRuntime]
    $null = [Windows.Security.Authentication.Web.Core.WebTokenRequest, Windows.Security.Authentication.Web.Core, ContentType=WindowsRuntime]
    $null = [Windows.Security.Authentication.Web.Core.WebTokenRequestStatus, Windows.Security.Authentication.Web.Core, ContentType=WindowsRuntime]
    $null = [Windows.Security.Credentials.WebAccountProvider, Windows.Security.Credentials, ContentType=WindowsRuntime]
    $null = [Windows.Security.Credentials.WebAccount, Windows.Security.Credentials, ContentType=WindowsRuntime]

    $script:WamTProvider = [Windows.Security.Credentials.WebAccountProvider, Windows.Security.Credentials, ContentType=WindowsRuntime]
    $script:WamTTokenResult = [Windows.Security.Authentication.Web.Core.WebTokenRequestResult, Windows.Security.Authentication.Web.Core, ContentType=WindowsRuntime]

    try {
        $closedAsTask = $script:WamAsTaskMethod.MakeGenericMethod($script:WamTTokenResult)
        $script:WamTTokenResultAsyncOperationGuid = $closedAsTask.GetParameters()[0].ParameterType.GUID
        Write-TestLog VERB WAM "IAsyncOperation<WebTokenRequestResult> IID: $script:WamTTokenResultAsyncOperationGuid"
    }
    catch {
        Write-TestLog WARN WAM "Could not resolve IAsyncOperation<WebTokenRequestResult> IID: $($_.Exception.Message)"
    }

    $script:WamWinRTInitialized = $true
    Write-TestLog VERB WAM 'WinRT types loaded.'
}

function Invoke-WinRTAsync {
    param(
        [Parameter(Mandatory)] $AsyncOp,
        [Parameter(Mandatory)] [Type]$ResultType
    )

    $task = $script:WamAsTaskMethod.MakeGenericMethod($ResultType).Invoke($null, @($AsyncOp))
    return $task.GetAwaiter().GetResult()
}

function Initialize-WamDesktopInterop {
    if ($script:WamDesktopInteropReady) { return $true }

    $existingHelperType = 'CompanyPortalComplianceCheck.WAM.WebAuthenticationCoreManagerDesktop' -as [type]
    if ($null -ne $existingHelperType) {
        $script:WamDesktopInteropReady = $true
        return $true
    }

    $source = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;

namespace CompanyPortalComplianceCheck.WAM
{
    [ComImport]
    [Guid("F4B8E804-811E-4436-B69C-44CB67B72084")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IWebAuthenticationCoreManagerInterop
    {
        void GetIids(out uint iidCount, out IntPtr iids);
        void GetRuntimeClassName(out IntPtr className);
        void GetTrustLevel(out int trustLevel);

        [PreserveSig]
        int RequestTokenForWindowAsync(
            IntPtr appWindow,
            [MarshalAs(UnmanagedType.IInspectable)] object request,
            [In] ref Guid riid,
            out IntPtr asyncInfo);

        [PreserveSig]
        int RequestTokenWithWebAccountForWindowAsync(
            IntPtr appWindow,
            [MarshalAs(UnmanagedType.IInspectable)] object request,
            [MarshalAs(UnmanagedType.IInspectable)] object webAccount,
            [In] ref Guid riid,
            out IntPtr asyncInfo);
    }

    public static class WebAuthenticationCoreManagerDesktop
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        public static IntPtr GetOwnerWindow()
        {
            IntPtr hwnd = GetConsoleWindow();
            if (hwnd == IntPtr.Zero) hwnd = GetForegroundWindow();
            return hwnd;
        }

        public static bool TrySetStringStringMap(object map, string key, string value, out string details)
        {
            details = "not attempted";
            if (map == null)
            {
                details = "map is null";
                return false;
            }

            try
            {
                var dict = map as IDictionary<string, string>;
                if (dict != null)
                {
                    dict[key] = value;
                    details = "IDictionary<string,string>";
                    return true;
                }
            }
            catch (Exception ex)
            {
                details = "IDictionary<string,string>: " + ex.Message;
            }

            try
            {
                object[] args = new object[] { key, value };
                map.GetType().InvokeMember("Insert", System.Reflection.BindingFlags.InvokeMethod, null, map, args);
                details = "InvokeMember Insert";
                return true;
            }
            catch (Exception ex)
            {
                details = details + " | Insert: " + ex.Message;
            }

            return false;
        }

        public static object RequestTokenForWindowAsync(Type managerType, IntPtr hwnd, object request, Guid asyncOperationGuid)
        {
            object factory = WindowsRuntimeMarshal.GetActivationFactory(managerType);
            var interop = (IWebAuthenticationCoreManagerInterop)factory;
            IntPtr asyncInfo;
            int hr = interop.RequestTokenForWindowAsync(hwnd, request, ref asyncOperationGuid, out asyncInfo);
            if (hr < 0) Marshal.ThrowExceptionForHR(hr);
            return Marshal.GetObjectForIUnknown(asyncInfo);
        }

        public static object RequestTokenWithWebAccountForWindowAsync(Type managerType, IntPtr hwnd, object request, object webAccount, Guid asyncOperationGuid)
        {
            object factory = WindowsRuntimeMarshal.GetActivationFactory(managerType);
            var interop = (IWebAuthenticationCoreManagerInterop)factory;
            IntPtr asyncInfo;
            int hr = interop.RequestTokenWithWebAccountForWindowAsync(hwnd, request, webAccount, ref asyncOperationGuid, out asyncInfo);
            if (hr < 0) Marshal.ThrowExceptionForHR(hr);
            return Marshal.GetObjectForIUnknown(asyncInfo);
        }
    }
}
'@

    try {
        Add-Type -TypeDefinition $source -Language CSharp -ReferencedAssemblies $script:WamWinRTRuntimePath -ErrorAction Stop
        $script:WamDesktopInteropReady = $true
        Write-TestLog VERB WAM 'Desktop WAM interop helper loaded.'
        return $true
    }
    catch {
        Write-TestLog WARN WAM "Desktop WAM interop helper could not be loaded: $($_.Exception.Message)"
        return $false
    }
}

function Get-WamProvider {
    if ($null -ne $script:WamProvider) { return $script:WamProvider }

    Write-TestLog INFO WAM "Locating AAD WebAccountProvider: $script:WamProviderUrl"

    $authorityCandidates = @($script:WamAuthority, 'organizations', 'common', '') | Select-Object -Unique

    foreach ($candidate in $authorityCandidates) {
        try {
            if ([string]::IsNullOrWhiteSpace($candidate)) {
                Write-TestLog VERB WAM 'Trying provider lookup without authority.'
                $provider = Invoke-WinRTAsync `
                    -AsyncOp ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::FindAccountProviderAsync($script:WamProviderUrl)) `
                    -ResultType $script:WamTProvider
            }
            else {
                Write-TestLog VERB WAM "Trying provider lookup with authority: $candidate"
                $provider = Invoke-WinRTAsync `
                    -AsyncOp ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::FindAccountProviderAsync($script:WamProviderUrl, $candidate)) `
                    -ResultType $script:WamTProvider
            }

            if ($null -ne $provider) {
                $script:WamProvider = $provider
                $script:WamProviderAuthority = $candidate
                break
            }
        }
        catch {
            Write-TestLog VERB WAM "Provider lookup failed for authority '$candidate': $($_.Exception.Message)"
        }
    }

    if ($null -eq $script:WamProvider) {
        throw 'WAM provider not found. Is this device Entra joined or signed in with a work account?'
    }

    Write-TestLog VERB WAM "Provider: $($script:WamProvider.DisplayName) Authority: $($script:WamProvider.Authority)"
    return $script:WamProvider
}

function Set-WamStringMapValue {
    param(
        [Parameter(Mandatory)] $Map,
        [Parameter(Mandatory)] [string]$Key,
        [Parameter(Mandatory)] [string]$Value
    )

    $errors = New-Object 'System.Collections.Generic.List[string]'

    if ($null -eq $Map) {
        return [PSCustomObject]@{ Success = $false; Details = 'map is null' }
    }

    $mapType = $Map.GetType().FullName

    try {
        if (Initialize-WamDesktopInterop) {
            $details = ''
            if ([CompanyPortalComplianceCheck.WAM.WebAuthenticationCoreManagerDesktop]::TrySetStringStringMap($Map, $Key, $Value, [ref]$details)) {
                return [PSCustomObject]@{ Success = $true; Details = "Desktop helper $details on $mapType" }
            }
            $errors.Add("Desktop helper: $details")
        }
    }
    catch {
        $errors.Add("Desktop helper: $($_.Exception.Message)")
    }

    try {
        if ($Map -is [System.Collections.IDictionary]) {
            $Map[$Key] = $Value
            return [PSCustomObject]@{ Success = $true; Details = "IDictionary on $mapType" }
        }
    }
    catch { $errors.Add("IDictionary: $($_.Exception.Message)") }

    try {
        $Map[$Key] = $Value
        return [PSCustomObject]@{ Success = $true; Details = "indexer on $mapType" }
    }
    catch { $errors.Add("indexer: $($_.Exception.Message)") }

    try {
        $null = $Map.Insert($Key, $Value)
        return [PSCustomObject]@{ Success = $true; Details = "Insert() on $mapType" }
    }
    catch { $errors.Add("Insert: $($_.Exception.Message)") }

    try {
        $null = $Map.Add($Key, $Value)
        return [PSCustomObject]@{ Success = $true; Details = "Add() on $mapType" }
    }
    catch { $errors.Add("Add: $($_.Exception.Message)") }

    return [PSCustomObject]@{ Success = $false; Details = (($errors | Where-Object { $_ }) -join ' | ') }
}

function Set-WamRequestResource {
    param(
        [Parameter(Mandatory)] $Request,
        [Parameter(Mandatory)] [string]$Resource
    )

    $attempts = New-Object 'System.Collections.Generic.List[string]'

    foreach ($propertyName in @('AppProperties', 'Properties')) {
        try {
            $map = $Request.$propertyName
            $result = Set-WamStringMapValue -Map $map -Key 'resource' -Value $Resource

            if ($result.Success) {
                Write-TestLog VERB WAM "Set WAM resource via WebTokenRequest.$propertyName ($($result.Details))."
                return $true
            }

            $attempts.Add("$propertyName => $($result.Details)")
        }
        catch {
            $attempts.Add("$propertyName => $($_.Exception.Message)")
        }
    }

    Write-TestLog WARN WAM "Could not set WAM resource in property bags. $($attempts -join ' || ')"
    return $false
}

function New-WamTokenRequest {
    param(
        [Parameter(Mandatory)] $Provider,
        [Parameter(Mandatory)] [string]$ClientId,
        [Parameter(Mandatory)] [string]$Resource
    )

    try {
        $req = [Windows.Security.Authentication.Web.Core.WebTokenRequest]::new($Provider, '', $ClientId)
    }
    catch {
        throw "Could not create WebTokenRequest with provider, empty scope and client ID. $($_.Exception.Message)"
    }

    if (Set-WamRequestResource -Request $req -Resource $Resource) { return $req }

    Write-TestLog WARN WAM 'Falling back to WebTokenRequest scope because the resource property bag is not writable.'
    try {
        return [Windows.Security.Authentication.Web.Core.WebTokenRequest]::new($Provider, $Resource, $ClientId)
    }
    catch {
        throw "Could not create fallback WebTokenRequest with resource as scope. $($_.Exception.Message)"
    }
}

function Get-WamFirstTokenResponse {
    param(
        [Parameter(Mandatory)] $Result,
        [Parameter(Mandatory)] [string]$Phase
    )

    if ($null -eq $Result.ResponseData) {
        throw "WAM token request returned Success but ResponseData was null. Phase: $Phase"
    }

    $data = $Result.ResponseData

    try {
        if ([int]$data.Count -lt 1) {
            throw "WAM token request returned Success but ResponseData.Count was 0. Phase: $Phase"
        }
    }
    catch { }

    try {
        $first = $data[0]
        if ($null -ne $first) { return $first }
    }
    catch { }

    try {
        $first = $data.Item(0)
        if ($null -ne $first) { return $first }
    }
    catch { }

    throw "WAM token request returned Success but the first token response could not be read. Phase: $Phase"
}

function Invoke-WamInteractiveTokenRequest {
    param(
        [Parameter(Mandatory)] $Request,
        $WebAccount
    )

    if ($null -eq $script:WamTTokenResultAsyncOperationGuid) {
        throw 'Cannot call desktop WAM interop because the IAsyncOperation<WebTokenRequestResult> IID was not resolved.'
    }

    if (-not (Initialize-WamDesktopInterop)) {
        throw 'Cannot call desktop WAM interop because the helper could not be loaded.'
    }

    $managerType = [Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager, Windows.Security.Authentication.Web.Core, ContentType=WindowsRuntime]
    $hwnd = [CompanyPortalComplianceCheck.WAM.WebAuthenticationCoreManagerDesktop]::GetOwnerWindow()

    Write-TestLog VERB WAM "Calling desktop WAM interop with HWND: $hwnd"

    if ($null -ne $WebAccount) {
        $asyncOp = [CompanyPortalComplianceCheck.WAM.WebAuthenticationCoreManagerDesktop]::RequestTokenWithWebAccountForWindowAsync(
            $managerType,
            $hwnd,
            $Request,
            $WebAccount,
            $script:WamTTokenResultAsyncOperationGuid
        )
    }
    else {
        $asyncOp = [CompanyPortalComplianceCheck.WAM.WebAuthenticationCoreManagerDesktop]::RequestTokenForWindowAsync(
            $managerType,
            $hwnd,
            $Request,
            $script:WamTTokenResultAsyncOperationGuid
        )
    }

    return Invoke-WinRTAsync -AsyncOp $asyncOp -ResultType $script:WamTTokenResult
}

function Get-WamToken {
    param(
        [Parameter(Mandatory)] [string]$ClientId,
        [Parameter(Mandatory)] [string]$Resource,
        [string]$Phase = 'AcquireToken',
        [switch]$Silent
    )

    Initialize-WinRT
    $provider = Get-WamProvider
    $corrId = [guid]::NewGuid().ToString()

    Write-TestLog INFO Identity "Requesting WAM token. ClientId: $ClientId"
    Write-TestLog INFO Identity "Resource: $Resource"
    Write-TestLog INFO Identity "Correlation ID: $corrId"

    $req = New-WamTokenRequest -Provider $provider -ClientId $ClientId -Resource $Resource

    try {
        if ($Silent -and ($null -ne $script:WamWebAccount)) {
            Write-TestLog VERB WAM 'Calling GetTokenSilentlyAsync with cached WebAccount.'
            $wamResult = Invoke-WinRTAsync `
                -AsyncOp ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::GetTokenSilentlyAsync($req, $script:WamWebAccount)) `
                -ResultType $script:WamTTokenResult
        }
        elseif ($Silent) {
            Write-TestLog VERB WAM 'Calling GetTokenSilentlyAsync without WebAccount.'
            $wamResult = Invoke-WinRTAsync `
                -AsyncOp ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::GetTokenSilentlyAsync($req)) `
                -ResultType $script:WamTTokenResult
        }
        else {
            Write-TestLog VERB WAM 'Trying silent WAM preflight first.'

            if ($null -ne $script:WamWebAccount) {
                $wamResult = Invoke-WinRTAsync `
                    -AsyncOp ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::GetTokenSilentlyAsync($req, $script:WamWebAccount)) `
                    -ResultType $script:WamTTokenResult
            }
            else {
                $wamResult = Invoke-WinRTAsync `
                    -AsyncOp ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager]::GetTokenSilentlyAsync($req)) `
                    -ResultType $script:WamTTokenResult
            }

            $successStatusForFallback = [Windows.Security.Authentication.Web.Core.WebTokenRequestStatus]::Success
            if ($wamResult.ResponseStatus -ne $successStatusForFallback) {
                Write-TestLog WARN WAM "Silent preflight returned $($wamResult.ResponseStatus). Switching to desktop interactive WAM."
                $wamResult = Invoke-WamInteractiveTokenRequest -Request $req -WebAccount $script:WamWebAccount
            }
        }
    }
    catch {
        Write-TestLog ERR Identity "WAM call threw: $($_.Exception.Message)"
        throw
    }

    $successStatus = [Windows.Security.Authentication.Web.Core.WebTokenRequestStatus]::Success

    if ($wamResult.ResponseStatus -ne $successStatus) {
        $errCode = ''
        $errMsg = ''

        if ($null -ne $wamResult.ResponseError) {
            try { $errCode = $wamResult.ResponseError.ErrorCode } catch { }
            try { $errMsg = $wamResult.ResponseError.ErrorMessage } catch { }
        }

        Write-TestLog ERR Identity "WAM token request FAILED. Status: $($wamResult.ResponseStatus) Code: $errCode $errMsg"
        throw "WAM token request failed: $($wamResult.ResponseStatus)"
    }

    $tokenResp = Get-WamFirstTokenResponse -Result $wamResult -Phase $Phase

    if ($null -eq $script:WamWebAccount -and $null -ne $tokenResp.WebAccount) {
        $script:WamWebAccount = $tokenResp.WebAccount
        try {
            $aid = $script:WamWebAccount.Id
            $shortId = $aid.Substring(0, [Math]::Min(6, $aid.Length))
            Write-TestLog INFO Identity "Cached WebAccount ID: $shortId..."
        }
        catch { }
    }

    if ($null -ne $tokenResp.WebAccount) {
        try { $script:WamUserId = $tokenResp.WebAccount.UserName } catch { }
    }

    Write-TestLog INFO Identity 'WAM authentication succeeded.'
    if ($script:WamUserId) { Write-TestLog INFO Identity "User: $script:WamUserId" }

    return [PSCustomObject]@{
        AccessToken = $tokenResp.Token
        AcquiredAt = [datetime]::UtcNow
        ClientId = $ClientId
        Resource = $Resource
    }
}

function Get-IWServiceWamBearerToken {
    param([switch]$Silent)

    if ($script:IWServiceToken) {
        Write-Log 'Using cached IWService WAM token for this session.'
        return $script:IWServiceToken
    }

    Write-Log "Requesting Company Portal IWService token with WAM. ClientId: $script:CompanyPortalClientId Resource: $script:IWServiceResource"

    $tokenResult = Get-WamToken `
        -ClientId $script:CompanyPortalClientId `
        -Resource $script:IWServiceResource `
        -Phase 'AcquireIWServiceToken' `
        -Silent:$Silent

    if ($tokenResult -and -not [string]::IsNullOrWhiteSpace($tokenResult.AccessToken)) {
        $script:IWServiceToken = $tokenResult.AccessToken
        Write-Log 'IWService WAM token acquired.'
        Write-JwtClaimSummary -Token $script:IWServiceToken -Label 'IWService token'
        return $script:IWServiceToken
    }

    throw 'IWService WAM returned no token.'
}

function Get-ObjectPropertyCI {
    param(
        [Parameter(Mandatory)] [object]$Object,
        [Parameter(Mandatory)] [string[]]$Names
    )

    foreach ($name in $Names) {
        $prop = $Object.PSObject.Properties |
            Where-Object { $_.Name -ieq $name } |
            Select-Object -First 1

        if ($prop -and $null -ne $prop.Value -and "$($prop.Value)" -ne '') {
            return $prop.Value
        }
    }

    return $null
}

function Find-ValueDeep {
    param(
        [object]$Object,
        [string[]]$Names,
        [int]$Depth = 5
    )

    if ($null -eq $Object -or $Depth -le 0) { return $null }

    $direct = Get-ObjectPropertyCI -Object $Object -Names $Names
    if ($direct) { return $direct }

    if ($Object -is [System.Collections.IEnumerable] -and -not ($Object -is [string])) {
        foreach ($item in $Object) {
            $found = Find-ValueDeep -Object $item -Names $Names -Depth ($Depth - 1)
            if ($found) { return $found }
        }
    }
    else {
        foreach ($prop in $Object.PSObject.Properties) {
            $found = Find-ValueDeep -Object $prop.Value -Names $Names -Depth ($Depth - 1)
            if ($found) { return $found }
        }
    }

    return $null
}

function Convert-IWDateTime {
    param([object]$Value)

    if ($null -eq $Value) { return $null }

    $text = "$Value"
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    if ($text -match '/Date\((\d+)\)/') {
        return [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$Matches[1]).LocalDateTime
    }

    try {
        return ([datetime]$text).ToLocalTime()
    }
    catch {
        try { return [datetime]$text } catch { return $null }
    }
}

function ConvertTo-IWServiceItems {
    param([object]$ResponseObject)

    if ($null -eq $ResponseObject) { return @() }

    if ($ResponseObject.value) { return @($ResponseObject.value) }
    if ($ResponseObject.Value) { return @($ResponseObject.Value) }
    if ($ResponseObject.d -and $ResponseObject.d.results) { return @($ResponseObject.d.results) }
    if ($ResponseObject.d -and $ResponseObject.d.value) { return @($ResponseObject.d.value) }
    if ($ResponseObject.d) { return @($ResponseObject.d) }

    return @($ResponseObject)
}

function Get-DeviceIdsFromToken {
    param([string]$Token)

    $ids = @()

    try {
        $claims = ConvertFrom-JwtPayload -Jwt $Token
        if (-not $claims) { return @() }

        foreach ($name in @('deviceid','device_id','xms_deviceid','DeviceId')) {
            $value = Get-JwtClaimText -Claims $claims -Name $name
            if (-not [string]::IsNullOrWhiteSpace($value)) { $ids += "$value" }
        }
    }
    catch {
        Write-Log "Could not read device id from token: $($_.Exception.Message)"
    }

    return @($ids | Select-Object -Unique)
}

function Get-CompanyPortalQuery {
    param(
        [string]$MgmtAgent = 'MicrosoftManagementPlatformCloudMdm',
        [string]$DeviceId,
        [switch]$IncludeDeviceId
    )

    $osVersion = '10.0.0'
    try { $osVersion = (Get-CimInstance Win32_OperatingSystem).Version } catch { }

    $arch = 'x64'
    try { if (-not [Environment]::Is64BitOperatingSystem) { $arch = 'x86' } } catch { }

    $query = @(
        'api-version=18.2',
        'ssp=WindowsUCP',
        'ssp-version=11.2.1787.0',
        'os=Windows',
        "os-version=$osVersion",
        'os-sub=None',
        "arch=$arch",
        "mgmt-agent=$MgmtAgent"
    )

    if ($IncludeDeviceId -and -not [string]::IsNullOrWhiteSpace($DeviceId)) {
        $query += "device-id=$DeviceId"
    }

    return ($query -join '&')
}

function Invoke-IWServiceRequest {
    param(
        [Parameter(Mandatory)] [string]$Url,
        [Parameter(Mandatory)] [string]$BearerToken,
        [ValidateSet('GET','POST')] [string]$Method = 'GET',
        [string]$Body = ''
    )

    Write-Log "$Method $Url"

    $req = [Net.HttpWebRequest]::Create($Url)
    $req.Method = $Method
    $req.Accept = 'application/json; odata=fullmetadata'
    $req.ContentType = 'application/json'
    $req.Timeout = 120000
    $req.UserAgent = 'CompanyPortal/11.2'
    $req.Headers['Authorization'] = "Bearer $BearerToken"
    $req.Headers['client-request-id'] = ([guid]::NewGuid()).Guid
    $req.Headers['Cache-Control'] = 'no-cache'
    $req.Headers['Pragma'] = 'no-cache'

    if ($Method -eq 'POST') {
        if ([string]::IsNullOrEmpty($Body)) {
            $req.ContentLength = 0
        }
        else {
            $bytes = [Text.Encoding]::UTF8.GetBytes($Body)
            $req.ContentLength = $bytes.Length
            $stream = $req.GetRequestStream()
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Close()
        }
    }

    try {
        $resp = $req.GetResponse()
        $statusCode = [int]$resp.StatusCode
        $statusDescription = $resp.StatusDescription
        $script:LastIWServiceStatusCode = $statusCode
        $script:LastIWServiceStatusDescription = $statusDescription

        $reader = New-Object IO.StreamReader $resp.GetResponseStream()
        $result = $reader.ReadToEnd()
        $reader.Close()
        $resp.Close()

        Write-Log "IWService status: $statusCode $statusDescription"

        if ([string]::IsNullOrWhiteSpace($result)) { return $null }
        return $result | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        $statusCode = ''
        $bodyText = ''

        try {
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                $script:LastIWServiceStatusCode = $statusCode
                $script:LastIWServiceStatusDescription = $_.Exception.Response.StatusDescription
                $reader = New-Object IO.StreamReader $_.Exception.Response.GetResponseStream()
                $bodyText = $reader.ReadToEnd()
                $reader.Close()
            }
        }
        catch { }

        if ($bodyText) {
            throw "IWService request failed. Status: $statusCode. $($_.Exception.Message)`r`n$bodyText"
        }

        throw "IWService request failed. Status: $statusCode. $($_.Exception.Message)"
    }
}

function Get-IWDevices {
    param(
        [Parameter(Mandatory)] [string]$BaseUrl,
        [Parameter(Mandatory)] [string]$BearerToken
    )

    $select = '$select=AadId,ApplicationState,CategoryId,CategorySetByEndUser,ChassisType,CoManagementFeatures,CreatedDate,DeviceActions,DeviceHWId,EasId,EBookState,ExchangeActivationItemEasId,ExchangeActivationItems,FullWipe,GetManagementState,IsExchangeActivated,IsPartnerManaged,IsReadOnly,Key,LastContact,LastContactNotification,Lock,ManagementAgent,ManagementType,Manufacturer,Model,Nickname,OfficialName,OperatingSystem,OperatingSystemId,OSSubtype,OwnerType,PartnerLocalizedSelfServicePortalName,PartnerName,PartnerRemediationUrl,PartnerSelfServicePortalUrl,PinReset,RegisterForAppPushNotifications,RemotableProperties,Retire,SetHeartBeat,SetOptIn,SetRD,SupervisedStatus,UserApprovedEnrollment,UdaStatus'

    foreach ($agent in @('Unknown','MicrosoftManagementPlatformCloudMdm')) {
        $query = Get-CompanyPortalQuery -MgmtAgent $agent
        $url = "$BaseUrl/TrafficGateway/TrafficRoutingService/IWService/StatelessIWService/Devices?$query&$select"
        $response = Invoke-IWServiceRequest -Url $url -BearerToken $BearerToken -Method GET
        $items = @(ConvertTo-IWServiceItems -ResponseObject $response)

        if ($items.Count -gt 0) {
            Write-Log "IWService returned $($items.Count) device object(s) with mgmt-agent=$agent."
            return $items
        }
    }

    return @()
}

function ConvertTo-IWGuidText {
    param([object]$Value)

    if ($null -eq $Value) { return '' }

    if ($Value -is [guid]) { return $Value.Guid }

    if ($Value -is [string]) {
        if ($Value -match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') {
            return $Matches[0]
        }
        return $Value
    }

    foreach ($name in @('GuidKey','guidKey','Id','id','Key','key','Value','value')) {
        $prop = $Value.PSObject.Properties |
            Where-Object { $_.Name -ieq $name } |
            Select-Object -First 1

        if ($prop -and $null -ne $prop.Value) {
            $found = ConvertTo-IWGuidText -Value $prop.Value
            if ($found) { return $found }
        }
    }

    $text = "$Value"
    if ($text -match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') {
        return $Matches[0]
    }

    return $text
}

function Resolve-LocalIWDevice {
    param(
        [Parameter(Mandatory)] [array]$Devices,
        [string[]]$CandidateDeviceIds
    )

    $computerName = $env:COMPUTERNAME
    Write-Log "Local computer name: $computerName"

    foreach ($candidate in $CandidateDeviceIds) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }

        $candidateLower = "$candidate".ToLowerInvariant()

        $matches = @(
            $Devices | Where-Object {
                $aadId = ConvertTo-IWGuidText -Value (Find-ValueDeep -Object $_ -Names @('AadId','AzureADDeviceId','AzureAdDeviceId','DeviceId'))
                $key = ConvertTo-IWGuidText -Value (Find-ValueDeep -Object $_ -Names @('Key','GuidKey','Id'))
                $hwid = ConvertTo-IWGuidText -Value (Find-ValueDeep -Object $_ -Names @('DeviceHWId'))

                ($aadId -and $aadId.ToLowerInvariant() -eq $candidateLower) -or
                ($key -and $key.ToLowerInvariant() -eq $candidateLower) -or
                ($hwid -and $hwid.ToLowerInvariant() -eq $candidateLower)
            }
        )

        if ($matches.Count -eq 1) {
            Write-Log "Matched local device by id: $candidate"
            return $matches[0]
        }
    }

    $nameMatches = @(
        $Devices | Where-Object {
            $officialName = Find-ValueDeep -Object $_ -Names @('OfficialName','DeviceName','Name')
            $nickName = Find-ValueDeep -Object $_ -Names @('Nickname')

            ($officialName -and "$officialName".ToLowerInvariant() -eq $computerName.ToLowerInvariant()) -or
            ($nickName -and "$nickName".ToLowerInvariant() -eq $computerName.ToLowerInvariant())
        }
    )

    if ($nameMatches.Count -eq 1) {
        Write-Log 'Matched local device by computer name.'
        return $nameMatches[0]
    }

    if ($Devices.Count -eq 1) {
        Write-Log 'Only one device was returned. Using that object.'
        return $Devices[0]
    }

    Write-Log 'Could not uniquely detect the local device. Returned devices:'
    foreach ($dev in $Devices) {
        $name = Find-ValueDeep -Object $dev -Names @('OfficialName','DeviceName','Name','Nickname')
        $aadId = ConvertTo-IWGuidText -Value (Find-ValueDeep -Object $dev -Names @('AadId','AzureADDeviceId','AzureAdDeviceId','DeviceId'))
        $key = ConvertTo-IWGuidText -Value (Find-ValueDeep -Object $dev -Names @('Key','GuidKey','Id'))
        Write-Log "Device: Name=$name AadId=$aadId Key=$key"
    }

    throw "Could not uniquely detect this device from IWService. Found $($Devices.Count) device objects."
}

function Get-IWDeviceKey {
    param([Parameter(Mandatory)] [object]$Device)

    $rawKey = Find-ValueDeep -Object $Device -Names @('Key','GuidKey','Id')
    $key = ConvertTo-IWGuidText -Value $rawKey

    if ([string]::IsNullOrWhiteSpace($key)) {
        throw 'Could not find the IWService device key on the matched device object.'
    }

    if ($key -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        throw "The detected IWService device key does not look like a GUID: $key"
    }

    return $key
}

function Get-IWDeviceByKey {
    param(
        [Parameter(Mandatory)] [string]$BaseUrl,
        [Parameter(Mandatory)] [string]$BearerToken,
        [Parameter(Mandatory)] [string]$DeviceKey
    )

    $query = Get-CompanyPortalQuery -MgmtAgent 'MicrosoftManagementPlatformCloudMdm'
    $url = "$BaseUrl/TrafficGateway/TrafficRoutingService/IWService/StatelessIWService/Devices(guid'$DeviceKey')?$query"

    return Invoke-IWServiceRequest -Url $url -BearerToken $BearerToken -Method GET
}

function Invoke-IWCheckCompliance {
    param(
        [Parameter(Mandatory)] [string]$BaseUrl,
        [Parameter(Mandatory)] [string]$BearerToken,
        [Parameter(Mandatory)] [string]$DeviceKey
    )

    $query = Get-CompanyPortalQuery -MgmtAgent 'MicrosoftManagementPlatformCloudMdm'
    $url = "$BaseUrl/TrafficGateway/TrafficRoutingService/IWService/StatelessIWService/Devices(guid'$DeviceKey')/CheckCompliance?$query"

    Invoke-IWServiceRequest -Url $url -BearerToken $BearerToken -Method POST -Body '' | Out-Null

    if ($script:LastIWServiceStatusCode -eq 204) {
        Write-Log 'CheckCompliance accepted by IWService. HTTP 204 No Content is expected for this action.'
    }
    elseif ($script:LastIWServiceStatusCode -eq 200) {
        Write-Log 'CheckCompliance returned HTTP 200 OK. The request succeeded, but final status still depends on LastContact changing.'
    }
    else {
        Write-Log "CheckCompliance returned HTTP $($script:LastIWServiceStatusCode) $($script:LastIWServiceStatusDescription)."
    }

    return [PSCustomObject]@{
        StatusCode = $script:LastIWServiceStatusCode
        StatusDescription = $script:LastIWServiceStatusDescription
    }
}

function Get-IWDeviceFriendlyValues {
    param([Parameter(Mandatory)] [object]$Device)

    $deviceName = Find-ValueDeep -Object $Device -Names @('OfficialName','DeviceName','Name','Nickname')
    $lastContactRaw = Find-ValueDeep -Object $Device -Names @('LastContact')
    $lastContact = Convert-IWDateTime -Value $lastContactRaw
    $compliance = Find-ValueDeep -Object $Device -Names @('ComplianceState','DeviceComplianceState','ManagementState','State','GetManagementState')
    $failedApps = Find-ValueDeep -Object $Device -Names @('FailedApps','FailedApplicationCount','FailedAppCount')

    return [PSCustomObject]@{
        DeviceName = $deviceName
        LastContactRaw = $lastContactRaw
        LastContact = $lastContact
        ComplianceState = $compliance
        FailedApps = $failedApps
    }
}


function Get-OmaDmAccountIds {
    $path = 'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts'
    if (-not (Test-Path $path)) {
        Write-Log "OMA-DM account registry path not found: $path"
        return @()
    }

    @(Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName }) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
}

function Invoke-LocalMdmCheckInLikeSyncMLViewer {
    [CmdletBinding()]
    param()

    Write-Log 'Triggering local MDM check in using the same style as SyncMLViewer.'

    $started = $false

    try {
        [Windows.Management.MdmSessionManager,Windows.Management,ContentType=WindowsRuntime] | Out-Null
        $session = [Windows.Management.MdmSessionManager]::TryCreateSession()
        if ($null -ne $session) {
            $null = $session.StartAsync()
            Write-Log 'MdmSessionManager StartAsync called.'
            $started = $true
        }
        else {
            Write-Log 'MdmSessionManager TryCreateSession returned null.'
        }
    }
    catch {
        Write-Log "MdmSessionManager trigger failed: $($_.Exception.Message)"
    }

    $accountIds = @(Get-OmaDmAccountIds)
    if ($accountIds.Count -eq 0) {
        Write-Log 'No OMA-DM account IDs found. Skipping EnterpriseMgmt Schedule #3 trigger.'
    }

    foreach ($accountId in $accountIds) {
        $taskName = "\Microsoft\Windows\EnterpriseMgmt\$accountId\Schedule #3 created by enrollment client"
        try {
            Write-Log "Starting EnterpriseMgmt task: $taskName"
            $output = & schtasks.exe /Run /I /TN $taskName 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "EnterpriseMgmt Schedule #3 started for enrollment $accountId."
                if ($output) { Write-Log (($output | Out-String).Trim()) }
                $started = $true
            }
            else {
                Write-Log "EnterpriseMgmt Schedule #3 failed for enrollment $accountId. Exit code $LASTEXITCODE. $($output | Out-String)"
            }
        }
        catch {
            Write-Log "EnterpriseMgmt Schedule #3 failed for enrollment $accountId. $($_.Exception.Message)"
        }
    }

    if ($started) {
        Write-Log 'Local MDM sync trigger was started.'
    }
    else {
        Write-Log 'Local MDM sync trigger did not start.'
    }

    return $started
}



function Invoke-ImeSyncAppProtocol {
    [CmdletBinding()]
    param()

    $imeService = Get-Service -Name 'IntuneManagementExtension' -ErrorAction SilentlyContinue
    $imePath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Intune Management Extension'

    if (-not $imeService -and -not (Test-Path $imePath)) {
        Write-Log 'Intune Management Extension service or installation folder was not found. Skipping IME syncapp trigger.'
        return $false
    }

    try {
        Write-Log 'Triggering Intune Management Extension app sync using intunemanagementextension://syncapp.'
        $shell = New-Object -ComObject Shell.Application
        $shell.Open('intunemanagementextension://syncapp')
        Write-Log 'IME syncapp protocol opened through Shell.Application.'
        return $true
    }
    catch {
        Write-Log "IME syncapp protocol trigger failed: $($_.Exception.Message)"
        return $false
    }
}


function Test-LastContactChanged {
    param(
        [object]$Before,
        [object]$After
    )

    if ($null -ne $Before -and $null -ne $After) {
        try { return ([datetime]$After -gt [datetime]$Before) } catch { return $false }
    }

    if ($null -eq $Before -and $null -ne $After) { return $true }
    return $false
}

function Test-CompliantState {
    param([object]$State)

    if ($null -eq $State -or [string]::IsNullOrWhiteSpace([string]$State)) { return $false }

    $clean = ([string]$State).Trim().ToLowerInvariant()
    if ($clean.Contains('noncompliant') -or $clean.Contains('non compliant') -or $clean.Contains('not compliant')) { return $false }

    return ($clean -eq 'compliant' -or $clean.Contains('compliant'))
}

function Test-NonCompliantState {
    param([object]$State)

    if ($null -eq $State -or [string]::IsNullOrWhiteSpace([string]$State)) { return $false }

    $clean = ([string]$State).Trim().ToLowerInvariant()
    return ($clean.Contains('noncompliant') -or $clean.Contains('non compliant') -or $clean.Contains('not compliant') -or $clean.Contains('fail') -or $clean.Contains('error'))
}

function Get-SafeStateText {
    param([object]$State)

    if ($null -eq $State -or [string]::IsNullOrWhiteSpace([string]$State)) { return 'Unknown' }
    return ([string]$State).Trim()
}

function Format-NullableDateText {
    param([object]$Value)

    if ($null -eq $Value) { return 'Unknown' }
    try { return ([datetime]$Value).ToString('G') } catch { return [string]$Value }
}

function Invoke-CompanyPortalStyleSync {
    param(
        [switch]$SkipMdmSync,
        [switch]$SkipImeSync
    )

    Write-Log 'Triggering Company Portal style sync sequence.'

    $mdmStarted = $false
    $imeStarted = $false

    if (-not $SkipMdmSync) {
        $mdmStarted = Invoke-LocalMdmCheckInLikeSyncMLViewer
    }
    else {
        Write-Log 'MDM sync trigger skipped by parameter.'
    }

    if (-not $SkipImeSync) {
        $imeStarted = Invoke-ImeSyncAppProtocol
    }
    else {
        Write-Log 'IME syncapp trigger skipped by parameter.'
    }

    if ($mdmStarted -or $imeStarted) {
        Write-Log 'Explicit device sync trigger was started.'
        return $true
    }

    Write-Log 'Explicit device sync trigger did not start. Check MdmSessionManager, EnterpriseMgmt tasks and IME protocol availability.'
    return $false
}

function Invoke-CompanyPortalComplianceCheckFull {
    param(
        [switch]$SilentWamOnly,
        [int]$TimeoutSeconds = 600,
        [int]$PollSeconds = 30,
        [switch]$SkipMdmSync,
        [switch]$SkipImeSync,
        [switch]$SkipPolling
    )

    $operationStart = Get-Date

    Write-Log 'Starting Company Portal style device sync and Check access flow.'
    Write-Log "Log file: $script:LogFile"

    if (Test-IsAdmin) {
        Write-Log 'Running elevated. That is fine, as long as this is still the logged on user and not SYSTEM.'
    }

    $mdm = Get-IntuneMDMCertAndIDs
    $cert = $mdm.Cert
    $mdmDeviceId = "$($mdm.DeviceId)"

    $token = Get-IWServiceWamBearerToken -Silent:$SilentWamOnly
    if (-not $token) { throw 'Could not acquire the Company Portal IWService token.' }

    $locationUrls = Get-IntuneLocationServiceUrls
    $sideCarEndpoint = Query-LocationService -LocationServiceUrls $locationUrls -Cert $cert
    $baseUrl = Get-IWServiceBaseUrlFromSideCarEndpoint -Endpoint $sideCarEndpoint
    Write-Log "IWService base URL: $baseUrl"

    $tokenDeviceIds = @(Get-DeviceIdsFromToken -Token $token)
    $candidateIds = @($tokenDeviceIds + $mdmDeviceId) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique

    Write-Log "Candidate local device ids: $($candidateIds -join ', ')"

    $devices = @(Get-IWDevices -BaseUrl $baseUrl -BearerToken $token)
    if ($devices.Count -eq 0) { throw 'IWService returned no device objects.' }

    $device = Resolve-LocalIWDevice -Devices $devices -CandidateDeviceIds $candidateIds
    $deviceKey = Get-IWDeviceKey -Device $device
    $beforeValues = Get-IWDeviceFriendlyValues -Device $device

    Write-Log "Matched local device: $($beforeValues.DeviceName)"
    Write-Log "IWService device key: $deviceKey"
    Write-Log "LastContact before explicit sync: $(Format-NullableDateText -Value $beforeValues.LastContact)"
    Write-Log "Compliance before explicit sync: $(Get-SafeStateText -State $beforeValues.ComplianceState)"

    Write-Log 'Triggering explicit device sync before CheckCompliance.'
    Invoke-CompanyPortalStyleSync -SkipMdmSync:$SkipMdmSync -SkipImeSync:$SkipImeSync | Out-Null

    $headStart = [Math]::Min(10, [Math]::Max(3, $PollSeconds))
    Write-Log "Giving the local sync trigger a short head start before posting CheckCompliance. Sleeping $headStart seconds."
    Start-Sleep -Seconds $headStart

    $postResult = Invoke-IWCheckCompliance -BaseUrl $baseUrl -BearerToken $token -DeviceKey $deviceKey
    Write-Log 'CheckCompliance request sent after the explicit sync trigger.'

    if ($SkipPolling) {
        Write-Log 'LastContact polling skipped by parameter.'
        return [PSCustomObject]@{
            DeviceName = $beforeValues.DeviceName
            DeviceKey = $deviceKey
            LastContactBefore = $beforeValues.LastContact
            LastContactAfter = $null
            ComplianceState = $beforeValues.ComplianceState
            FailedApps = $beforeValues.FailedApps
            PostStatusCode = $postResult.StatusCode
            PostStatusDescription = $postResult.StatusDescription
            LastContactChanged = $false
            DurationSeconds = [int]((Get-Date) - $operationStart).TotalSeconds
            StatusText = Get-SafeStateText -State $beforeValues.ComplianceState
            Summary = 'Explicit sync and CheckCompliance were triggered. Polling was skipped.'
            Result = 'Posted'
            LogFile = $script:LogFile
        }
    }

    Write-Log 'Waiting for a new LastContact and a compliant state.'

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastValues = $null

    do {
        Start-Sleep -Seconds $PollSeconds

        $current = Get-IWDeviceByKey -BaseUrl $baseUrl -BearerToken $token -DeviceKey $deviceKey
        if ($null -eq $current) { throw 'IWService returned an empty device object while polling.' }

        $lastValues = Get-IWDeviceFriendlyValues -Device $current
        Write-Log "Current LastContact: $(Format-NullableDateText -Value $lastValues.LastContact)"
        Write-Log "Current compliance value: $(Get-SafeStateText -State $lastValues.ComplianceState)"

        $lastContactChanged = Test-LastContactChanged -Before $beforeValues.LastContact -After $lastValues.LastContact
        $isCompliant = Test-CompliantState -State $lastValues.ComplianceState
        $isNonCompliant = Test-NonCompliantState -State $lastValues.ComplianceState

        if ($lastContactChanged -and $isCompliant) {
            $duration = [int]((Get-Date) - $operationStart).TotalSeconds
            $summary = "Explicit sync was triggered. CheckCompliance was accepted. New contact was received after $duration seconds and the device is Compliant."
            if (-not [string]::IsNullOrWhiteSpace([string]$lastValues.FailedApps)) { $summary += " Failed apps: $($lastValues.FailedApps)." }

            Write-Log 'New contact received after CheckCompliance and compliance state is Compliant.'
            Write-Log "Summary: $summary"

            return [PSCustomObject]@{
                DeviceName = $beforeValues.DeviceName
                DeviceKey = $deviceKey
                LastContactBefore = $beforeValues.LastContact
                LastContactAfter = $lastValues.LastContact
                ComplianceState = $lastValues.ComplianceState
                FailedApps = $lastValues.FailedApps
                PostStatusCode = $postResult.StatusCode
                PostStatusDescription = $postResult.StatusDescription
                LastContactChanged = $true
                DurationSeconds = $duration
                StatusText = 'Compliant'
                Summary = $summary
                Result = 'Compliant'
                LogFile = $script:LogFile
            }
        }

        if ($lastContactChanged -and $isNonCompliant) {
            $duration = [int]((Get-Date) - $operationStart).TotalSeconds
            $stateText = Get-SafeStateText -State $lastValues.ComplianceState
            $summary = "Explicit sync was triggered and a new contact was received after $duration seconds, but the current compliance state is $stateText."
            if (-not [string]::IsNullOrWhiteSpace([string]$lastValues.FailedApps)) { $summary += " Failed apps: $($lastValues.FailedApps)." }

            Write-Log 'New contact received after CheckCompliance, but compliance state is not compliant.'
            Write-Log "Summary: $summary"

            return [PSCustomObject]@{
                DeviceName = $beforeValues.DeviceName
                DeviceKey = $deviceKey
                LastContactBefore = $beforeValues.LastContact
                LastContactAfter = $lastValues.LastContact
                ComplianceState = $lastValues.ComplianceState
                FailedApps = $lastValues.FailedApps
                PostStatusCode = $postResult.StatusCode
                PostStatusDescription = $postResult.StatusDescription
                LastContactChanged = $true
                DurationSeconds = $duration
                StatusText = $stateText
                Summary = $summary
                Result = 'NonCompliant'
                LogFile = $script:LogFile
            }
        }

        if ($lastContactChanged) {
            Write-Log 'New contact was received, but compliance state is not final yet. Continuing to poll until timeout.'
        }
    }
    while ((Get-Date) -lt $deadline)

    $durationTimedOut = [int]((Get-Date) - $operationStart).TotalSeconds
    $finalValues = if ($null -ne $lastValues) { $lastValues } else { $beforeValues }
    $finalCompliance = Get-SafeStateText -State $finalValues.ComplianceState
    $finalLastContactChanged = Test-LastContactChanged -Before $beforeValues.LastContact -After $finalValues.LastContact
    $summaryTimedOut = "Explicit sync and CheckCompliance were triggered, but the script did not observe both a new LastContact and a Compliant state within $TimeoutSeconds seconds. Last known compliance state: $finalCompliance."

    Write-Log 'Timed out waiting for new LastContact and Compliant state.'
    Write-Log "Summary: $summaryTimedOut"

    return [PSCustomObject]@{
        DeviceName = $beforeValues.DeviceName
        DeviceKey = $deviceKey
        LastContactBefore = $beforeValues.LastContact
        LastContactAfter = $finalValues.LastContact
        ComplianceState = $finalValues.ComplianceState
        FailedApps = $finalValues.FailedApps
        PostStatusCode = $postResult.StatusCode
        PostStatusDescription = $postResult.StatusDescription
        LastContactChanged = $finalLastContactChanged
        DurationSeconds = $durationTimedOut
        StatusText = $finalCompliance
        Summary = $summaryTimedOut
        Result = 'TimedOut'
        LogFile = $script:LogFile
    }
}

try {
    $result = Invoke-CompanyPortalComplianceCheckFull -SilentWamOnly:$SilentWamOnly -TimeoutSeconds $TimeoutSeconds -PollSeconds $PollSeconds -SkipMdmSync:$SkipMdmSync -SkipImeSync:$SkipImeSync -SkipPolling:$SkipPolling
    Write-Host ''
    Write-Host 'Result:'
    $result | Format-List

    if ($result.Result -eq 'Compliant' -or $result.Result -eq 'Posted') { exit 0 }
    if ($result.Result -eq 'NonCompliant') { exit 2 }
    exit 3
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Host "ERROR: $($_.Exception.Message)"
    exit 1
}
