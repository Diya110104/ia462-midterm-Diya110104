#Requires -RunAsAdministrator
<#
.SYNOPSIS
  IA 462 midterm - Section 2: Windows baseline + event log analysis.

.DESCRIPTION
  Run in an ELEVATED PowerShell from the repo's midterm\scripts folder:

      Set-ExecutionPolicy -Scope Process Bypass -Force
      .\section2-windows-baseline.ps1

  Writes everything to midterm\section2\. The script pauses where a screenshot
  is due. Use -NoPause to run straight through.

  PRIVACY: the repo is public. By default the outputs are redacted: your
  computer name, Windows username and user SID are replaced with placeholders.
  Use -NoRedact only if your instructor requires raw values.

.PARAMETER AppDir
  Directory to add as a Defender exclusion (your Python app). Default: ..\app
#>
[CmdletBinding()]
param(
  [string]$AppDir = (Join-Path $PSScriptRoot '..\app'),
  [switch]$NoPause,
  [switch]$NoRedact
)

$ErrorActionPreference = 'Continue'
$Out = (Resolve-Path (Join-Path $PSScriptRoot '..\section2')).Path
$AppDir = (Resolve-Path $AppDir).Path
New-Item -ItemType Directory -Force -Path (Join-Path $Out 'screenshots') | Out-Null

function Step($t) { Write-Host "`n==================================================================" -ForegroundColor Cyan
                    Write-Host ("[{0}] {1}" -f (Get-Date -Format 's'), $t) -ForegroundColor Cyan
                    Write-Host "==================================================================" -ForegroundColor Cyan }
function Shot($name) { if (-not $NoPause) { Read-Host ">> Take screenshot screenshots\$name now, then press Enter" | Out-Null } }

$Transcript = Join-Path $Out 'windows-transcript.txt'
Start-Transcript -Path $Transcript -Force | Out-Null

# ---------------------------------------------------------------------------
Step '1. Microsoft Defender status'
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled,
  BehaviorMonitorEnabled, IoavProtectionEnabled, IsTamperProtected, AntivirusSignatureVersion,
  AntivirusSignatureLastUpdated | Format-List
Shot '05-defender-status.png'

# ---------------------------------------------------------------------------
Step '2. Windows Firewall profiles'
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction,
  LogBlocked, LogFileName | Format-Table -AutoSize
$off = Get-NetFirewallProfile | Where-Object { -not $_.Enabled }
if ($off) { Write-Warning "Profiles disabled: $($off.Name -join ', ') - enable with Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True" }
else { Write-Host 'PASS: Domain, Private and Public profiles are all enabled' -ForegroundColor Green }
Shot '06-firewall-profiles.png'

# ---------------------------------------------------------------------------
Step '3. SMBv1 disabled'
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol | Format-List
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object FeatureName, State | Format-List
Shot '07-smb1-disabled.png'

# ---------------------------------------------------------------------------
Step '4. Audit policy: 4688 with command line + PowerShell script-block logging (4104)'
# Subcategory GUIDs are language-independent.
auditpol /set /subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable   # Process Creation -> 4688
auditpol /set /subcategory:'{0CCE9235-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable   # User Account Management -> 4720/4726
auditpol /set /subcategory:'{0CCE9215-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable   # Logon -> 4624/4625
$audit = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Path $audit -Force | Out-Null
Set-ItemProperty -Path $audit -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
$sbl = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $sbl -Force | Out-Null
Set-ItemProperty -Path $sbl -Name EnableScriptBlockLogging -Value 1 -Type DWord
Get-ItemProperty $audit | Select-Object ProcessCreationIncludeCmdLine_Enabled | Format-List
Get-ItemProperty $sbl   | Select-Object EnableScriptBlockLogging | Format-List
auditpol /get /subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030},{0CCE9235-69AE-11D9-BED3-505054503030},{0CCE9215-69AE-11D9-BED3-505054503030}'

# ---------------------------------------------------------------------------
Step '5. Install Sysmon with the SwiftOnSecurity config (commit-pinned + hash-verified)'
$cfgCommit = '1836897f12fbd6a0a473665ef6abc34a6b497e31'
$cfgSha256 = '055FEBC600E6D7448CDF3812307275912927A62B1F94D0D933B64B294BC87162'
$cfgPath   = Join-Path $Out 'sysmonconfig.xml'
Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/$cfgCommit/sysmonconfig-export.xml" -OutFile $cfgPath
$h = (Get-FileHash $cfgPath -Algorithm SHA256).Hash
if ($h -ne $cfgSha256) { Stop-Transcript; throw "sysmonconfig.xml hash mismatch: $h" }
Write-Host "sysmonconfig.xml SHA256 verified: $h" -ForegroundColor Green

$sysDir = Join-Path $env:TEMP 'ia462-sysmon'
New-Item -ItemType Directory -Force -Path $sysDir | Out-Null
Invoke-WebRequest -UseBasicParsing -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile "$sysDir\Sysmon.zip"
Expand-Archive "$sysDir\Sysmon.zip" -DestinationPath $sysDir -Force
$exe = Join-Path $sysDir 'Sysmon64.exe'
$sig = Get-AuthenticodeSignature $exe
"Sysmon64.exe signature: $($sig.Status) / $($sig.SignerCertificate.Subject)"
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
  Stop-Transcript; throw 'Sysmon64.exe is not validly signed by Microsoft - aborting.' }
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) { & $exe -c $cfgPath } else { & $exe -accepteula -i $cfgPath }
Get-Service Sysmon64 | Select-Object Name, Status, StartType | Format-List
& $exe -c | Select-Object -First 12
Shot '08-sysmon-service.png'

# ---------------------------------------------------------------------------
Step '6. Generate 4624 / 4625 / 4688 / 4720 / 4104 test events'
$testUser = 'ia462test'
# Random password generated in memory (works in Windows PowerShell 5.1 and PowerShell 7); never written to disk.
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 24; $rng.GetBytes($bytes)
$plain = 'Aa1!' + (([Convert]::ToBase64String($bytes)) -replace '[+/=]', 'x')
$secure = ConvertTo-SecureString $plain -AsPlainText -Force
Get-LocalUser $testUser -ErrorAction SilentlyContinue | Remove-LocalUser

# 4720 - user account created
New-LocalUser -Name $testUser -Password $secure -Description 'IA462 midterm test account' | Out-Null
Write-Host "Created local user $testUser (4720)"

# 4625 x6 - failed network logons (brute-force pattern for the Sigma rule)
1..6 | ForEach-Object { net use \\127.0.0.1\IPC$ /user:$testUser WrongPassword$_ 2>&1 | Out-Null }
Write-Host 'Generated 6 failed logons (4625)'

# 4624 + 4688 - successful logon as the test user, launching a process
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$testUser", $secure)
try { Start-Process -FilePath "$env:windir\System32\whoami.exe" -Credential $cred -WorkingDirectory $env:windir -WindowStyle Hidden -Wait
      Write-Host 'Generated successful logon (4624) + process creation (4688)' }
catch { Write-Warning "Start-Process as $testUser failed ($_). 4624s from your own session will still be present." }
net use \\127.0.0.1\IPC$ /delete 2>&1 | Out-Null

# 4688 - process creation with command lines
whoami /groups | Out-Null; ipconfig /all | Out-Null; net user | Out-Null

# 4104 (+ 4688 with -EncodedCommand) - encoded PowerShell, benign payload
$payload = "Write-Output 'IA462 encoded command test'; Get-Date"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
powershell.exe -NoProfile -NonInteractive -EncodedCommand $enc
Write-Host 'Generated encoded PowerShell (4104 + 4688 -EncodedCommand)'

# cleanup (4726 - user account deleted)
Remove-LocalUser $testUser
$plain = $null; $secure = $null; $cred = $null
Start-Sleep -Seconds 3

# ---------------------------------------------------------------------------
Step '7. Export the last 100 Security-log entries to JSON'
$ids = 4624, 4625, 4688, 4720, 4726
$sel = { $_ | Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, MachineName, RecordId, Message,
                            @{n='EventData'; e={ $_.Properties | ForEach-Object { $_.Value } }} }
$sec = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $ids } -MaxEvents 100
$sec | ForEach-Object $sel | ConvertTo-Json -Depth 5 | Out-File -Encoding utf8 (Join-Path $Out 'security-events.json')
$sec | Group-Object Id | Select-Object @{n='EventId';e={$_.Name}}, Count | Sort-Object EventId | Format-Table -AutoSize

# Supporting exports: 4104 script blocks and Sysmon process-create (EID 1)
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104 } -MaxEvents 25 |
  ForEach-Object $sel | ConvertTo-Json -Depth 5 | Out-File -Encoding utf8 (Join-Path $Out 'powershell-4104-events.json')
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1 } -MaxEvents 25 -ErrorAction SilentlyContinue |
  ForEach-Object $sel | ConvertTo-Json -Depth 5 | Out-File -Encoding utf8 (Join-Path $Out 'sysmon-events.json')

Write-Host "`nSample: failed logons (4625) and encoded PowerShell process creation (4688)"
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625 } -MaxEvents 3 | Format-Table TimeCreated, Id, Message -Wrap
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688 } -MaxEvents 200 |
  Where-Object { $_.Message -match 'EncodedCommand' } | Select-Object -First 1 | Format-List TimeCreated, Id, Message
Shot '09-events-sample.png'

# ---------------------------------------------------------------------------
Step '8. Defender exclusion for the Python application directory'
Write-Host "Adding exclusion: $AppDir"
Write-Host 'Note: exclusions are a blind spot attackers look for (T1562.001). Keep it to this one folder.'
Add-MpPreference -ExclusionPath $AppDir
Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess | Format-List |
  Out-String -Width 200 | Tee-Object -FilePath (Join-Path $Out 'defender-exclusions.txt')
Shot '10-defender-exclusions.png'

Stop-Transcript | Out-Null

# ---------------------------------------------------------------------------
if (-not $NoRedact) {
  $sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
  $map = [ordered]@{ $sid = 'S-1-5-21-REDACTED'; $env:COMPUTERNAME = 'LAB-HOST'; $env:USERNAME = 'student'
                     $env:USERPROFILE = 'C:\Users\student' }
  Get-ChildItem $Out -File | Where-Object { $_.Extension -in '.txt', '.json' } | ForEach-Object {
    $c = Get-Content $_.FullName -Raw
    foreach ($k in $map.Keys) { if ($k -and $k.Length -ge 3) { $c = $c -replace [regex]::Escape($k), $map[$k]
                                          $c = $c -replace [regex]::Escape(($k -replace '\\','\\')), ($map[$k] -replace '\\','\\') } }
    Set-Content -Path $_.FullName -Value $c -Encoding utf8
  }
  Write-Host "Redacted computer name, username and SID in $Out" -ForegroundColor Yellow
}
Write-Host "`nSection 2 complete. Evidence is in $Out" -ForegroundColor Green
