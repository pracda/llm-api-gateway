<#
.SYNOPSIS
  Quick health check for the current LLM Gateway EC2 deployment (if any).
#>
param([string]$Region = "us-east-1")

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$stateFile = Join-Path $scriptDir ".deployment-state.json"

if (-not (Test-Path $stateFile)) {
    Write-Host "No deployment is currently up (no state file at $stateFile)." -ForegroundColor Yellow
    exit 0
}

$state = Get-Content $stateFile | ConvertFrom-Json
$instState = aws ec2 describe-instances --instance-ids $state.InstanceId --region $state.Region --query 'Reservations[0].Instances[0].State.Name' --output text

Write-Host "Instance $($state.InstanceId): $instState @ $($state.PublicIp) (launched $($state.LaunchedAt))"

if ($instState -eq "running") {
    try {
        $resp = Invoke-WebRequest -Uri "http://$($state.PublicIp):8080/actuator/health" -TimeoutSec 5 -UseBasicParsing
        Write-Host "App health: $($resp.StatusCode) $($resp.Content)" -ForegroundColor Green
    } catch {
        Write-Host "App not responding yet (still building/booting on first launch, or crashed)." -ForegroundColor Yellow
        Write-Host "SSH in and check /var/log/llm-gateway-bootstrap.log:  ssh -i `"$($state.KeyName).pem`" ec2-user@$($state.PublicIp)" -ForegroundColor Yellow
    }
}
