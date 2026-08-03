<#
.SYNOPSIS
  RESUME the LLM Gateway after pause.ps1.

  Starts the stopped EC2 instance (data-preserving). The llm-gateway.service systemd unit
  auto-boots the docker-compose stack on start, so the gateway comes back with all its data —
  no rebuild, no lost secrets, admin password unchanged.

  NOTE: the public IP CHANGES on each start (no Elastic IP attached), so the URL changes too.
  This prints the new URL and writes it back into the state file. If you want a stable URL,
  attach an Elastic IP (adds ~$3.6/mo) or put a DNS name in front.
#>
param([string]$Region = "us-east-1")

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$stateFile = Join-Path $scriptDir ".deployment-state.json"
if (-not (Test-Path $stateFile)) {
    Write-Host "No deployment state file at $stateFile." -ForegroundColor Yellow
    exit 1
}
$state = Get-Content $stateFile | ConvertFrom-Json

Write-Host "Starting $($state.InstanceId)..." -ForegroundColor Cyan
aws ec2 start-instances --instance-ids $state.InstanceId --region $Region | Out-Null
aws ec2 wait instance-running --instance-ids $state.InstanceId --region $Region

$ip = aws ec2 describe-instances --instance-ids $state.InstanceId --region $Region `
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text
$state.PublicIp = $ip
$state | ConvertTo-Json | Set-Content $stateFile

Write-Host "Instance running at $ip - the app takes ~1-2 min to boot the stack..." -ForegroundColor Cyan
$deadline = (Get-Date).AddMinutes(4)
while ((Get-Date) -lt $deadline) {
    try {
        $r = Invoke-RestMethod -Uri "http://${ip}:8080/actuator/health" -TimeoutSec 5
        if ($r.status -eq 'UP') {
            Write-Host ""
            Write-Host "Gateway is UP:  http://${ip}:8080" -ForegroundColor Green
            Write-Host "Dashboard:      http://${ip}:8080/admin-dashboard.html" -ForegroundColor Green
            Write-Host "IP changed to $ip - update any app's LLM_GATEWAY_URL accordingly." -ForegroundColor Yellow
            exit 0
        }
    } catch { }
    Start-Sleep -Seconds 10
    Write-Host "  still booting..."
}
Write-Host "Running at $ip but health didn't confirm within 4 min - check .\status.ps1 or the app logs." -ForegroundColor Yellow
