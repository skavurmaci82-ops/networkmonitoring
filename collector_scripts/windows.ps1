$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$session = $null
try {
    $p = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $localIPs = @([Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | ForEach-Object { $_.GetIPProperties().UnicastAddresses } | ForEach-Object { $_.Address.ToString() })
    $local = $localIPs -contains $p.target
    if ($local -and -not $p.use_current_user) {
        @{ok=$false;error_code='local_current_account_required'} | ConvertTo-Json -Compress
        exit 2
    }
    if (-not $local) {
        # DcomParameterSet: -Protocol belongs to a separate parameter set.
        $option = New-CimSessionOption -Impersonation Impersonate -PacketPrivacy -PacketIntegrity
        $arguments = @{ComputerName=$p.target;SessionOption=$option;OperationTimeoutSec=12}
        if (-not $p.use_current_user) {
            $secure = ConvertTo-SecureString $p.password -AsPlainText -Force
            $arguments.Credential = [Management.Automation.PSCredential]::new($p.username,$secure)
        }
        $session = New-CimSession @arguments
    }
    function Query([string]$class,[string]$filter='') {
        $arguments = @{ClassName=$class;OperationTimeoutSec=12}
        if ($session) {$arguments.CimSession=$session}
        if ($filter) {$arguments.Filter=$filter}
        @(Get-CimInstance @arguments)
    }
    $computer = (Query 'Win32_ComputerSystem')[0]
    $bios = (Query 'Win32_BIOS')[0]
    $os = (Query 'Win32_OperatingSystem')[0]
    $processors = @(Query 'Win32_Processor')
    $loads = @($processors | Where-Object { $null -ne $_.LoadPercentage } | ForEach-Object { [double]$_.LoadPercentage })
    $cpu = $null
    if ($loads.Count) {$cpu=[math]::Round(($loads | Measure-Object -Average).Average,1)}
    $memory = [double]$os.TotalVisibleMemorySize * 1024
    $memoryUsed = $null
    if ($memory -gt 0) {$memoryUsed=[math]::Round(100*(1-([double]$os.FreePhysicalMemory*1024/$memory)),1)}
    $disks = @(Query 'Win32_LogicalDisk' 'DriveType=3' | Where-Object {$_.Size -gt 0} | ForEach-Object {
        @{name=$_.DeviceID;total_bytes=[double]$_.Size;free_bytes=[double]$_.FreeSpace;used_percent=[math]::Round(100*(1-$_.FreeSpace/[double]$_.Size),1)}
    })
    $adapters = @(Query 'Win32_NetworkAdapterConfiguration' 'IPEnabled=True')
    $hardware = @(Query 'Win32_NetworkAdapter')
    $interfaces = @($adapters | ForEach-Object {
        $adapter=$_
        $nic=$hardware | Where-Object {$_.Index -eq $adapter.Index} | Select-Object -First 1
        $state=if ($nic.NetConnectionStatus -eq 2) {1} elseif ($nic.NetConnectionStatus -in @(0,7)) {2} else {4}
        @{name=$adapter.Description;mac=$adapter.MACAddress;addresses=@($adapter.IPAddress);oper_status=$state}
    })
    $network = @()
    try {
        $network = @(Query 'Win32_PerfFormattedData_Tcpip_NetworkInterface' | ForEach-Object {
            @{name=$_.Name;rx_bps=[double]$_.BytesReceivedPersec*8;tx_bps=[double]$_.BytesSentPersec*8}
        })
    } catch {}
    @{ok=$true;source='Windows CIM/DCOM';name=$computer.Name;manufacturer=$computer.Manufacturer;model=$computer.Model;
      serial=$bios.SerialNumber;os=($os.Caption+' '+$os.Version);cpu_name=($processors | Select-Object -First 1).Name;
      cpu_percent=$cpu;memory_total_bytes=$memory;memory_percent=$memoryUsed;disks=$disks;
      macs=@($adapters | Where-Object {$_.MACAddress} | ForEach-Object {$_.MACAddress});interfaces=$interfaces;network=$network
    } | ConvertTo-Json -Depth 8 -Compress
} catch {
    $code = if ($_.Exception.HResult -eq -2147023570) {'authentication_failed'} elseif ($_.Exception.HResult -eq -2147024891 -or $_.CategoryInfo.Category -in @('PermissionDenied','SecurityError')) {'access_denied'} else {'windows_connection_failed'}
    @{ok=$false;error_code=$code} | ConvertTo-Json -Compress
    exit 2
} finally {
    if ($session) {Remove-CimSession $session -ErrorAction SilentlyContinue}
    $p=$null;$secure=$null
}
