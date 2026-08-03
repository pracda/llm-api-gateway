<#
.SYNOPSIS
  PAUSE the LLM Gateway to stop recurring cost WITHOUT losing data.

  Stops (not terminates) the EC2 instance: compute billing halts, but the EBS volume and all
  Postgres data (users, orgs, API keys, audit logs) persist. Reverse with resume.ps1.

  This is deliberately NOT down.ps1 — down.ps1 runs TerminateInstances and destroys the volume
  and every secret. Use pause/resume for cost control; use up/down only to fully recreate.

  Stopped cost is just the 8 GiB gp3 disk (~$0.64/mo) plus $0 for the (released) public IP.
#>
param([string]$Region = "us-east-1")

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$stateFile = Join-Path $scriptDir ".deployment-state.json"
if (-not (Test-Path $stateFile)) {
    Write-Host "No deployment state file at $stateFile - nothing to pause." -ForegroundColor Yellow
    exit 1
}
$state = Get-Content $stateFile | ConvertFrom-Json

Write-Host "Stopping $($state.InstanceId) (data preserved)..." -ForegroundColor Cyan
aws ec2 stop-instances --instance-ids $state.InstanceId --region $Region | Out-Null
aws ec2 wait instance-stopped --instance-ids $state.InstanceId --region $Region

Write-Host "Paused. Compute billing halted (~`$0.64/mo for the disk only, data intact)." -ForegroundColor Green
Write-Host "Bring it back with:  .\resume.ps1" -ForegroundColor Green
