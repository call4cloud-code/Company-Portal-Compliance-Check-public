 Company Portal Compliance Check

A small PowerShell GUI tool that triggers the same high level flow as the **Check access** button in Company Portal.

The tool uses the local Intune MDM device certificate, gets a user based Company Portal IWService token through WAM, finds the local device in IWService, sends the `CheckCompliance` action, and waits until `LastContact` changes.

## What it does

* Finds the local Microsoft Intune MDM Device CA certificate
* Discovers the correct Intune service location
* Gets a Company Portal IWService token through WAM
* Matches the local device in IWService
* Sends `Devices(guid'<id>')/CheckCompliance`
* Polls the device until `LastContact` changes
* Shows the compliance state, HTTP result, device name and log output in a simple GUI

## Important

Run this tool in the logged on user context.

Running elevated is fine, but running as `SYSTEM` is not recommended. The IWService token is user based, so the tool needs access to the same user context Company Portal uses.

This tool does not bypass compliance, assignments or Intune policies. It only triggers the same kind of compliance check flow and waits for the service data to update.

## Requirements

* Windows  Windows 11
* Microsoft Entra/ Intune enrolled device
* Company Portal available for the signed in user
* Windows PowerShell 5.1
* A valid Microsoft Intune MDM device certificate
* User must be signed in with the account used for Company Portal

## How to run

Download the application and run it as the logged on user:


## PowerShell script version

The repository also includes a PowerShell version:

```powershell
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File .\Invoke-CompanyPortalComplianceCheckFull.ps1 -TimeoutSeconds 900 -PollSeconds 20
OR to skippolling and show the restults
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File .\Invoke-CompanyPortalComplianceCheckFull.ps1 -SkipPolling


