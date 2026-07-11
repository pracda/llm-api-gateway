<#
.SYNOPSIS
  Tears down the LLM Gateway EC2 deployment created by up.ps1. Plain
  TerminateInstances on the single instance up.ps1 created - no ASG/ELB/
  CloudFormation stack involved, so there's nothing else that can be left
  dangling behind it.
#>
param(
    [string]$Region = "us-east-1",
    [switch]$DeleteSecurityGroup
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$stateFile = Join-Path $scriptDir ".deployment-state.json"

if (Test-Path $stateFile) {
    $state = Get-Content $stateFile | ConvertFrom-Json
    $instanceIds = $state.InstanceId
    $Region = $state.Region
} else {
    Write-Host "No local state file - falling back to tag-based lookup." -ForegroundColor Yellow
    $instanceIds = aws ec2 describe-instances --region $Region `
        --filters "Name=tag:Project,Values=llm-api-gateway" "Name=instance-state-name,Values=running,pending,stopped,stopping" `
        --query 'Reservations[].Instances[].InstanceId' --output text
}

if (-not $instanceIds) {
    Write-Host "No llm-gateway instances found to terminate - nothing to do." -ForegroundColor Green
    exit 0
}

Write-Host "Terminating instance(s): $instanceIds" -ForegroundColor Yellow
aws ec2 terminate-instances --instance-ids $instanceIds --region $Region | Out-Null
aws ec2 wait instance-terminated --instance-ids $instanceIds --region $Region
Write-Host "Terminated." -ForegroundColor Green

if ($DeleteSecurityGroup) {
    $vpcId = (aws ec2 describe-vpcs --filters Name=isDefault,Values=true --region $Region --query 'Vpcs[0].VpcId' --output text)
    $sgId  = (aws ec2 describe-security-groups --region $Region --filters "Name=group-name,Values=llm-gateway-sg" "Name=vpc-id,Values=$vpcId" --query 'SecurityGroups[0].GroupId' --output text)
    if ($sgId -and $sgId -ne "None") {
        aws ec2 delete-security-group --group-id $sgId --region $Region
        Write-Host "Deleted security group $sgId" -ForegroundColor Green
    }
}

Remove-Item $stateFile -Force -ErrorAction SilentlyContinue
Write-Host "Down complete. (.deployment-secrets.env kept for reference - delete it yourself for a fully clean slate.)" -ForegroundColor Cyan
