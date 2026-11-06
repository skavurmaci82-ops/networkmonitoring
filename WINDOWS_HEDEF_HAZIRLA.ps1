param([Parameter(Mandatory=$true)][System.Net.IPAddress]$MonitoringIP)
# Run only on a Windows target you administer, from elevated PowerShell.
# Opens WMI/DCOM only to the monitoring computer; does not grant account rights.
$ErrorActionPreference='Stop'
if ($MonitoringIP.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {throw 'IPv4 address required.'}
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'Run elevated PowerShell.'}
Set-Service -Name Winmgmt -StartupType Automatic
Start-Service -Name Winmgmt
$remote=$MonitoringIP.ToString()
if (Get-NetFirewallRule -Name 'AgAtlas-WMI-RPC' -ErrorAction SilentlyContinue) {
    Set-NetFirewallRule -Name 'AgAtlas-WMI-RPC' -RemoteAddress $remote -Enabled True
} else {
    New-NetFirewallRule -Name 'AgAtlas-WMI-RPC' -DisplayName 'AgAtlas WMI RPC' -Direction Inbound -Protocol TCP -LocalPort 135 -RemoteAddress $remote -Action Allow | Out-Null
}
if (Get-NetFirewallRule -Name 'AgAtlas-WMI-Service' -ErrorAction SilentlyContinue) {
    Set-NetFirewallRule -Name 'AgAtlas-WMI-Service' -RemoteAddress $remote -Enabled True
} else {
    New-NetFirewallRule -Name 'AgAtlas-WMI-Service' -DisplayName 'AgAtlas WMI service' -Direction Inbound -Protocol TCP -LocalPort RPC -Service Winmgmt -RemoteAddress $remote -Action Allow | Out-Null
}
Write-Host 'WMI service and firewall rules prepared for monitoring IP only.'
Write-Host 'Use an account with WMI/DCOM read access. No account rights or UAC policies were changed.'
