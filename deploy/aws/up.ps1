<#
.SYNOPSIS
  Brings up the LLM Gateway on a single plain EC2 instance (no Elastic
  Beanstalk/Auto Scaling/load balancer) running the existing docker-compose
  stack (app + Postgres + Redis together). Pair with down.ps1.

.PARAMETER InstanceType
  Defaults to t3.small (2GB RAM - enough headroom for JVM+Postgres+Redis
  together). t3.micro is cheaper but tight; override if you want to try it.
#>
param(
    [string]$InstanceType = "t3.small",
    [string]$Region = "us-east-1",
    [string]$KeyName = "llm-gateway-key"
)

$ErrorActionPreference = "Stop"
$scriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoEnvPath = Join-Path $scriptDir "..\..\.env"
$stateFile   = Join-Path $scriptDir ".deployment-state.json"

if (Test-Path $stateFile) {
    Write-Host "A deployment already exists (state file present at $stateFile)." -ForegroundColor Yellow
    Write-Host "Run down.ps1 first, or delete the state file yourself if it's stale." -ForegroundColor Yellow
    exit 1
}

# Real provider keys come from your local dev .env - everything else is freshly generated
if (-not (Test-Path $repoEnvPath)) { throw "Local .env not found at $repoEnvPath - needed for OPENAI_API_KEY/ANTHROPIC_API_KEY." }
$localEnv = @{}
Get-Content $repoEnvPath | ForEach-Object {
    if ($_ -match '^([^#=]+)=(.*)$') { $localEnv[$matches[1].Trim()] = $matches[2].Trim() }
}
$openAiKey    = $localEnv["OPENAI_API_KEY"]
$anthropicKey = $localEnv["ANTHROPIC_API_KEY"]
if (-not $openAiKey -or -not $anthropicKey) { throw "OPENAI_API_KEY/ANTHROPIC_API_KEY missing from local .env" }

function New-RandomSecret([int]$Length = 32) {
    -join ((48..57) + (65..90) + (97..122) | Get-Random -Count $Length | ForEach-Object { [char]$_ })
}
$jwtSecret     = New-RandomSecret 48
$pgPassword    = New-RandomSecret 24
$redisPassword = New-RandomSecret 24
$adminPassword = New-RandomSecret 16
$canaryToken   = "cnry-" + [guid]::NewGuid().ToString()

# VPC / subnet / AMI lookup (no hardcoded IDs - always resolves fresh)
$vpcId    = (aws ec2 describe-vpcs --filters Name=isDefault,Values=true --region $Region --query 'Vpcs[0].VpcId' --output text)
$subnetId = (aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpcId" --region $Region --query 'Subnets[0].SubnetId' --output text)
$amiId    = (aws ec2 describe-images --owners amazon --filters "Name=name,Values=al2023-ami-2023*-x86_64" "Name=state,Values=available" --region $Region --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)
Write-Host "Using VPC=$vpcId Subnet=$subnetId AMI=$amiId InstanceType=$InstanceType" -ForegroundColor Cyan

# SSH is scoped to whoever runs this script, not the whole internet - resolve that IP once up front.
$callerIp = (Invoke-RestMethod -Uri "https://checkip.amazonaws.com").Trim()
if ($callerIp -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') { throw "Could not resolve caller's public IP (got '$callerIp')." }
$sshCidr = "$callerIp/32"
Write-Host "Scoping SSH (port 22) to $sshCidr - re-run this script if your IP changes and you need SSH access again." -ForegroundColor Cyan

# Security group (reuse if it already exists from a prior run)
$sgId = (aws ec2 describe-security-groups --region $Region --filters "Name=group-name,Values=llm-gateway-sg" "Name=vpc-id,Values=$vpcId" --query 'SecurityGroups[0].GroupId' --output text)
if (-not $sgId -or $sgId -eq "None") {
    $sgId = (aws ec2 create-security-group --group-name llm-gateway-sg --description "LLM Gateway - app (8080, public) + SSH (22, caller IP only)" --vpc-id $vpcId --region $Region --query 'GroupId' --output text)
    aws ec2 authorize-security-group-ingress --group-id $sgId --protocol tcp --port 8080 --cidr 0.0.0.0/0 --region $Region | Out-Null
    aws ec2 authorize-security-group-ingress --group-id $sgId --protocol tcp --port 22   --cidr $sshCidr   --region $Region | Out-Null
    Write-Host "Created security group $sgId (8080 open to 0.0.0.0/0 - no domain/TLS yet, so the app itself must be publicly reachable; 22 restricted to $sshCidr)." -ForegroundColor Yellow
} else {
    Write-Host "Reusing existing security group $sgId - re-scoping its SSH rule to $sshCidr..." -ForegroundColor Cyan
    # Revoke every existing port-22 rule (may be the old wide-open 0.0.0.0/0 from a prior version
    # of this script, or a stale IP from a previous run) and re-authorize scoped to the current IP.
    # Single-quoted so PowerShell passes the JMESPath backticks through literally instead of
    # trying to interpret them as its own escape character (that combination previously produced
    # "Bad jmespath expression: Unknown token" and silently no-opped the revoke below).
    $existingSshRanges = aws ec2 describe-security-groups --group-ids $sgId --region $Region `
        --query 'SecurityGroups[0].IpPermissions[?ToPort==`22`].IpRanges[].CidrIp' --output text
    foreach ($cidr in ($existingSshRanges -split "\s+" | Where-Object { $_ })) {
        if ($cidr -ne $sshCidr) {
            aws ec2 revoke-security-group-ingress --group-id $sgId --protocol tcp --port 22 --cidr $cidr --region $Region | Out-Null
            Write-Host "  revoked stale SSH rule for $cidr" -ForegroundColor Yellow
        }
    }
    if ($existingSshRanges -notmatch [regex]::Escape($sshCidr)) {
        aws ec2 authorize-security-group-ingress --group-id $sgId --protocol tcp --port 22 --cidr $sshCidr --region $Region | Out-Null
        Write-Host "  authorized SSH for $sshCidr" -ForegroundColor Yellow
    }
}

# Key pair (create if missing; private key saved locally, gitignored)
$pemPath = Join-Path $scriptDir "$KeyName.pem"
$existingKey = $null
try {
    $existingKey = aws ec2 describe-key-pairs --key-names $KeyName --region $Region --query 'KeyPairs[0].KeyName' --output text 2>$null
} catch { $existingKey = $null }
if (-not $existingKey -or $existingKey -eq "None") {
    aws ec2 create-key-pair --key-name $KeyName --region $Region --query 'KeyMaterial' --output text | Out-File -FilePath $pemPath -Encoding ascii
    Write-Host "Created new key pair, private key saved to $pemPath (gitignored - back it up if you want SSH access later)." -ForegroundColor Yellow
}

# Render user-data from the template (explicit ASCII in/out - avoids PS 5.1
# misdecoding a BOM-less UTF8 file and corrupting bytes on the round-trip)
$template = [System.IO.File]::ReadAllText((Join-Path $scriptDir "user-data.sh.template"), [System.Text.Encoding]::ASCII)
$userData = $template `
    -replace "__OPENAI_API_KEY__", $openAiKey `
    -replace "__ANTHROPIC_API_KEY__", $anthropicKey `
    -replace "__JWT_SECRET__", $jwtSecret `
    -replace "__POSTGRES_PASSWORD__", $pgPassword `
    -replace "__REDIS_PASSWORD__", $redisPassword `
    -replace "__ADMIN_PASSWORD__", $adminPassword `
    -replace "__CANARY_TOKEN__", $canaryToken

$userDataFile = Join-Path $scriptDir ".rendered-user-data.sh"
[System.IO.File]::WriteAllText($userDataFile, $userData, [System.Text.Encoding]::ASCII)

# Launch the instance
$ErrorActionPreference = "Continue"
$instanceId = aws ec2 run-instances `
    --image-id $amiId `
    --instance-type $InstanceType `
    --key-name $KeyName `
    --security-group-ids $sgId `
    --subnet-id $subnetId `
    --associate-public-ip-address `
    --user-data "file://$userDataFile" `
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=llm-gateway-prod},{Key=Project,Value=llm-api-gateway}]" `
    --region $Region `
    --query 'Instances[0].InstanceId' --output text
$ErrorActionPreference = "Stop"

if (-not $instanceId -or $instanceId -eq "None" -or $instanceId -notmatch '^i-') {
    Write-Host "run-instances did not return a valid instance ID (got: '$instanceId'). Aborting before writing state." -ForegroundColor Red
    Remove-Item $userDataFile -Force -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "Launched instance $instanceId - waiting for it to enter 'running' state..." -ForegroundColor Cyan
aws ec2 wait instance-running --instance-ids $instanceId --region $Region

$publicIp = aws ec2 describe-instances --instance-ids $instanceId --region $Region --query 'Reservations[0].Instances[0].PublicIpAddress' --output text

@{
    InstanceId      = $instanceId
    PublicIp        = $publicIp
    Region          = $Region
    SecurityGroupId = $sgId
    KeyName         = $KeyName
    LaunchedAt      = (Get-Date).ToString("o")
} | ConvertTo-Json | Set-Content $stateFile

@"
JWT_SECRET=$jwtSecret
POSTGRES_PASSWORD=$pgPassword
REDIS_PASSWORD=$redisPassword
ADMIN_PASSWORD=$adminPassword
CANARY_TOKEN=$canaryToken
"@ | Set-Content (Join-Path $scriptDir ".deployment-secrets.env")

Remove-Item $userDataFile -Force

Write-Host ""
Write-Host "Instance is up at $publicIp - the app itself takes ~2-4 more minutes to build and boot." -ForegroundColor Green
Write-Host "Check progress:  .\status.ps1" -ForegroundColor Green
Write-Host ("Health check:    http://" + $publicIp + ":8080/actuator/health") -ForegroundColor Green
Write-Host ("Dashboard:       http://" + $publicIp + ":8080/admin-dashboard.html") -ForegroundColor Green
Write-Host "Admin login:     admin / $adminPassword" -ForegroundColor Green
Write-Host "(All generated secrets are also saved in .deployment-secrets.env, gitignored.)" -ForegroundColor Cyan
