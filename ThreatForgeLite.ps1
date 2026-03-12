# =========================================================
# ThreatForgeLite 1.0
# Made by shadownight4000 | Powered by BloxTuan
# =========================================================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# System Info

$ComputerName = $env:COMPUTERNAME
$UserName = $env:USERNAME
$ScanTime = Get-Date
$ComputerID = "$ComputerName-$UserName-" + (Get-Date -Format "yyyyMMddHHmmss")

# Logging

$logDir = "C:\ProgramData\ThreatScope"
$logFile = "$logDir\ThreatScope.log"

if(!(Test-Path $logDir)){
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

function Write-Log($msg){
    $time = Get-Date -Format "HH:mm:ss"
    $line = "[$time] $msg"
    Add-Content $logFile $line
    $logBox.AppendText($line + "`r`n")
}

# Threat Score

$global:RiskScore = 0

# =========================================================
# Detection Modules
# =========================================================

function Check-Defender {

    Write-Log "Checking Windows Defender..."

    try{
        $def = Get-MpComputerStatus

        if(!$def.AntivirusEnabled){
            Write-Log "WARNING: Defender disabled"
            $global:RiskScore += 40
        }else{
            Write-Log "OK: Defender enabled"
        }

    }catch{
        Write-Log "ERROR: Defender status unavailable"
    }
}

function Check-Processes {

    Write-Log "Analyzing running processes..."

    $procs = Get-Process | Sort CPU -Descending | Select -First 15

    foreach($p in $procs){
        Write-Log "Process: $($p.ProcessName) CPU: $([math]::Round($p.CPU,2))"
    }

    $miners = $procs | Where { $_.ProcessName -match "miner|xmrig|cryptonight" }

    if($miners){
        Write-Log "WARNING: Possible crypto miner detected"
        $global:RiskScore += 40
    }
}

function Check-RegistryPersistence {

    Write-Log "Scanning registry autorun keys..."

    $run = Get-ItemProperty `
    HKCU:\Software\Microsoft\Windows\CurrentVersion\Run `
    HKLM:\Software\Microsoft\Windows\CurrentVersion\Run `
    -ErrorAction SilentlyContinue

    foreach($p in $run.PSObject.Properties){
        Write-Log "Autorun entry: $($p.Name)"
    }

    if($run.PSObject.Properties.Count -gt 6){
        Write-Log "WARNING: Large number of autorun entries"
        $global:RiskScore += 25
    }
}

function Check-StartupFolder {

    Write-Log "Checking Startup Folder..."

    $path = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"

    $items = Get-ChildItem $path -ErrorAction SilentlyContinue

    foreach($i in $items){
        Write-Log "Startup file: $($i.Name)"
    }

    if($items.Count -gt 3){
        Write-Log "WARNING: Multiple startup programs"
        $global:RiskScore += 20
    }
}

function Check-ScheduledTasks {

    Write-Log "Checking Scheduled Tasks..."

    $tasks = Get-ScheduledTask

    foreach($t in $tasks | Select -First 10){
        Write-Log "Task: $($t.TaskName)"
    }

    if($tasks.Count -gt 150){
        Write-Log "WARNING: Unusually high number of tasks"
        $global:RiskScore += 20
    }
}

function Check-PowerShellPersistence {

    Write-Log "Scanning for PowerShell persistence..."

    $tasks = Get-ScheduledTask | Where { $_.Actions.Execute -match "powershell" }

    if($tasks){
        Write-Log "WARNING: PowerShell scheduled task detected"
        $global:RiskScore += 35
    }
}

function Check-NetworkConnections {

    Write-Log "Analyzing network connections..."

    $conns = Get-NetTCPConnection -State Established

    Write-Log "Active connections: $($conns.Count)"

    if($conns.Count -gt 30){
        Write-Log "WARNING: High number of active connections"
        $global:RiskScore += 15
    }
}

function Check-SystemErrors {

    Write-Log "Checking system error logs..."

    $errors = Get-WinEvent -LogName System -MaxEvents 50 |
    Where {$_.LevelDisplayName -eq "Error"}

    Write-Log "System errors found: $($errors.Count)"

    if($errors.Count -gt 10){
        $global:RiskScore += 10
    }
}

# Graphical User Interface (J)

$form = New-Object System.Windows.Forms.Form
$form.Text = "ThreatScope Security Analyzer"
$form.Size = New-Object System.Drawing.Size(900,600)
$form.StartPosition = "CenterScreen"

$title = New-Object System.Windows.Forms.Label
$title.Text = "ThreatScope Security Analyzer"
$title.Font = New-Object System.Drawing.Font("Segoe UI",18,[System.Drawing.FontStyle]::Bold)
$title.Size = New-Object System.Drawing.Size(880,40)
$title.Location = New-Object System.Drawing.Point(10,10)
$title.TextAlign = "MiddleCenter"

$form.Controls.Add($title)

$info = New-Object System.Windows.Forms.Label
$info.Text = "Computer: $ComputerName | User: $UserName | ID: $ComputerID"
$info.Size = New-Object System.Drawing.Size(880,20)
$info.Location = New-Object System.Drawing.Point(10,60)
$info.TextAlign = "MiddleCenter"

$form.Controls.Add($info)

$scanBtn = New-Object System.Windows.Forms.Button
$scanBtn.Text = "Start Threat Scan"
$scanBtn.Size = New-Object System.Drawing.Size(200,40)
$scanBtn.Location = New-Object System.Drawing.Point(350,100)

$form.Controls.Add($scanBtn)

$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Size = New-Object System.Drawing.Size(700,25)
$progress.Location = New-Object System.Drawing.Point(100,160)

$form.Controls.Add($progress)

$logBox = New-Object System.Windows.Forms.TextBox
$logBox.Multiline = $true
$logBox.ScrollBars = "Vertical"
$logBox.Size = New-Object System.Drawing.Size(850,350)
$logBox.Location = New-Object System.Drawing.Point(20,200)

$form.Controls.Add($logBox)

# Scan Execute

$scanBtn.Add_Click({

Write-Log "ThreatScope Scan Started"
Write-Log "Scan Time: $ScanTime"

$progress.Value = 10
Check-Defender

$progress.Value = 25
Check-Processes

$progress.Value = 40
Check-RegistryPersistence

$progress.Value = 55
Check-StartupFolder

$progress.Value = 65
Check-ScheduledTasks

$progress.Value = 75
Check-PowerShellPersistence

$progress.Value = 85
Check-NetworkConnections

$progress.Value = 95
Check-SystemErrors

$progress.Value = 100

Write-Log "--------------------------------"
Write-Log "Threat Score: $RiskScore / 100"

if($RiskScore -lt 20){
    $level="LOW"
}elseif($RiskScore -lt 50){
    $level="MEDIUM"
}else{
    $level="HIGH"
}

Write-Log "Threat Level: $level"

[System.Windows.Forms.MessageBox]::Show(
"ThreatScope Scan Complete`nThreat Score: $RiskScore`nThreat Level: $level",
"ThreatScope Security Report"
)

})

$form.ShowDialog()

# This product is licensed under MIT License and is made for basic scans. This is not as reliable as ThreatScope Standard or ThreatScopePlus