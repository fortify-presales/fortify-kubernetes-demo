
# Set IsWindows or IsLinux/IsMacOs variable accordingly
function Set-PSPlatform
{
    switch ([System.Environment]::OSVersion.Platform)
    {
        'Win32NT' {
            New-Variable -Option Constant -Name IsWindows -Scope global -Value $True -ErrorAction SilentlyContinue
            New-Variable -Option Constant -Name IsLinux   -Scope global -Value $false -ErrorAction SilentlyContinue
            New-Variable -Option Constant -Name IsMacOs   -Scope global -Value $false -ErrorAction SilentlyContinue
        }
    }
}
Export-ModuleMember -Function Set-PSPlatform

function Set-JavaTools
{
    Set-PSPlatform
    $RootPath = Split-Path $PSScriptRoot -Parent
    #Write-Host "RootPath=${RootPath}"
    if ($IsLinux)
    {
        Write-Host "Running on Linux ..."
        $JavaHome = Join-Path $RootPath -ChildPath "jdk-17-jre-linux-x64"
        if (-not(Test-Path -PathType container $JavaHome))
        {
            Write-Host "Installing local JRE ..."
            $DownloadUri = "https://builds.openlogic.com/downloadJDK/openlogic-openjdk-jre/17.0.8+7/openlogic-openjdk-jre-17.0.8+7-linux-x64.tar.gz"
            Invoke-WebRequest -Uri $DownloadUri -OutFile jdk-17-jre-linux-x64.tar.gz
            Expand-Archive -Path jdk-17-jre-linux-x64.zip -DestinationPath jdk-17-jre-linux-x64.zip
        }
        $JavaBin = Join-Path $JavaHome -ChildPath "bin"
        $JavaExe = Join-Path $JavaBin -ChildPath "java"
        $KeytoolExe = Join-Path $JavaBin -ChildPath "keytool"
    }
    elseif ($IsWindows)
    {
        Write-Host "Running on Windows ..."
        $JavaHome = Join-Path $RootPath -ChildPath "jdk-17-jre-windows-x64"
        if (-not(Test-Path -PathType container $JavaHome))
        {
            Write-Host "Installing local JRE ..."
        }
        $JavaBin = Join-Path $JavaHome -ChildPath "bin"
        $JavaExe = Join-Path $JavaBin -ChildPath "java.exe"
        $KeytoolExe = Join-Path $JavaBin -ChildPath "keytool.exe"
    }
    else
    {
        throw "Unsupported platform"
    }
    $FcliDir = Join-Path $RootPath -ChildPath "fcli"
    $FcliJar = Join-Path $FcliDir -ChildPath "fcli.jar"
    New-Variable -Option Constant -Name JavaHome -Scope global -Value $JavaHome -ErrorAction SilentlyContinue
    New-Variable -Option Constant -Name JavaBin  -Scope global -Value $JavaBin -ErrorAction SilentlyContinue
    New-Variable -Option Constant -Name JavaExe  -Scope global -Value $JavaExe -ErrorAction SilentlyContinue
    New-Variable -Option Constant -Name KeytoolExe  -Scope global -Value $KeytoolExe -ErrorAction SilentlyContinue
    New-Variable -Option Constant -Name FcliDir  -Scope global -Value $FcliDir -ErrorAction SilentlyContinue
    New-Variable -Option Constant -Name FcliJar  -Scope global -Value $FcliJar -ErrorAction SilentlyContinue
}
Export-ModuleMember -Function Set-JavaTools

function Invoke-Fcli
{
    $ArgumentList = @("-jar", $FcliJar)
    ForEach ($a in $args) { $ArgumentList += $a}
    Write-Host "Executing fcli: java $ArgumentList"
    $params = @{
        FilePath = $JavaExe
        WorkingDirectory = $PSScriptRoot
        ArgumentList = $ArgumentList
        PassThru = $true
        Wait = $true
    }
    $p = Start-Process @params
}
Export-ModuleMember -Function Invoke-Fcli

function Get-PodStatus
{
    param (
        [Parameter(Mandatory=$true)]
        [String]$PodName
    )
    # Try explicit default namespace first
    try {
        $Status = (kubectl get pods -n default $PodName -o jsonpath="{.status.phase}") 2>$null
        if (-not [string]::IsNullOrEmpty($Status)) { return $Status }
    } catch {}

    # Try current namespace (no -n) - respects current kubectl context/namespace
    try {
        $Status = (kubectl get pods $PodName -o jsonpath="{.status.phase}") 2>$null
        if (-not [string]::IsNullOrEmpty($Status)) { return $Status }
    } catch {}

    # Fallback: search all namespaces for a pod whose name equals or starts with the provided name
    try {
        $json = (kubectl get pods --all-namespaces -o json) 2>$null
        if ($json) {
            $objs = $json | ConvertFrom-Json
            $match = $objs.items | Where-Object { $_.metadata.name -eq $PodName -or $_.metadata.name -like "$PodName*" } | Select-Object -First 1
            if ($match) { return $match.status.phase }
        }
    } catch {}

    return $null
}
Export-ModuleMember Get-PodStatus

function Wait-UntilPodStatus
{
    param (
        [Parameter(Mandatory=$true)]
        [String]$PodName,
        [Parameter(Mandatory=$false)]
        [String]$UntilStatus = "Running"
    )
    $Status = $Null
    Write-Host -n "Waiting until ${PodName} is ${UntilStatus} "
    While ($Status -ne $UntilStatus)
    {
        $Status = Get-PodStatus -PodName $PodName
        Write-Host -n "."
        Start-Sleep -Seconds 5
    }
    Write-Host ""
    return $Status
}
Export-ModuleMember Wait-UntilPodStatus

function Update-EnvFile
{
    param (
        [Parameter(Mandatory=$true)]
        [String]$File,
        [Parameter(Mandatory=$true)]
        [String]$Find,
        [Parameter(Mandatory=$true)]
        [String]$Replace
    )
    (Get-Content -Path $File) | ForEach-Object{$_ -replace $Find,$Replace} | Set-Content -Path $File
}
Export-ModuleMember Update-EnvFile

function Install-ScanCentralClient
{
    param (
        [Parameter(Mandatory=$false)]
        [String]$Version = "25.4.0",
        [Parameter(Mandatory=$false)]
        [String]$InstallDir = "scancentral-client",
        [Parameter(Mandatory=$true)]
        [String]$ClientAuthToken
    )
    $DownloadUri = "https://tools.fortify.com/scancentral/Fortify_ScanCentral_Client_$($Version)_x64.zip"
    Invoke-WebRequest -Uri $DownloadUri -OutFile Fortify_ScanCentral_Client_Latest_x64.zip
    Expand-Archive -Path Fortify_ScanCentral_Client_Latest_x64.zip -DestinationPath $InstallDir
    $ClientProperties = Join-Path -Path $InstallDir -ChildPath "Core" | Join-Path -ChildPath "config" | Join-Path -ChildPath "client.properties"
    $Find = "^client_auth_token=.*$"
    $Replace = "client_auth_token=$($ClientAuthToken)"
    (Get-Content -Path $ClientProperties) | ForEach-Object{$_ -replace $Find,$Replace} | Set-Content -Path $ClientProperties
}
Export-ModuleMember Install-ScanCentralClient

function New-FortifyToken
{
    param (
        [Parameter(Mandatory=$true)]
        [String]$SSCUri,
        [Parameter(Mandatory=$true)]
        [String]$Username,
        [Parameter(Mandatory=$true)]
        [String]$Password,
        [Parameter(Mandatory=$false)]
        [String]$TokenType = "CIToken"
    )
    $Base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $Username,$Password)))
    $Headers = @{
        'Accept' = "*/*"
        'Content-Type' = "application/json"
        'Authorization' = "Basic $Base64AuthInfo"
    }
    $Body = @{
        'type' = "$TokenType"
        'description' = "generated from New-FortifyToken"
    }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True }
    try  {
        $Response = Invoke-RestMethod -Method Post -Uri "$SSCUri/api/v1/tokens" -Headers $Headers -Body $Body
        Write-Host $Response
        return $Response.data.token
    } catch {
        Write-Error -Exception $_.Exception -Message "SSC API call failed: $_"
    }
}
Export-ModuleMember New-FortifyToken

function Wait-ForSSCReady
{
    param(
        [Parameter(Mandatory=$false)]
        [string]$PodName = 'ssc-webapp-0',
        [Parameter(Mandatory=$false)]
        [string]$ProbeUrl = 'https://localhost:8443/',
        [Parameter(Mandatory=$false)]
        [string]$HostHeader = 'ssc.127-0-0-1.nip.io',
        [Parameter(Mandatory=$false)]
        [int]$TimeoutSeconds = 600,
        [Parameter(Mandatory=$false)]
        [int]$PollIntervalSeconds = 5
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    Write-Host "Waiting for pod $PodName to be Running and ready (timeout ${TimeoutSeconds}s) ..."

    while ((Get-Date) -lt $deadline) {
        try {
            $ready = kubectl get pod $PodName -o jsonpath='{.status.containerStatuses[0].ready}' 2>$null
        } catch { $ready = $null }
        if ($ready -eq 'true') { break }
        Start-Sleep -Seconds $PollIntervalSeconds
    }

    if ((Get-Date) -ge $deadline) { throw "Timed out waiting for pod $PodName to be ready" }

    Write-Host "Pod $PodName reports container ready. Probing HTTP(s) endpoint $ProbeUrl ..."
    # Probe loop
    while ((Get-Date) -lt $deadline) {
        try {
            $headers = @{ Host = $HostHeader }
            # Use -SkipCertificateCheck for local certs
            $resp = Invoke-WebRequest -Uri $ProbeUrl -Headers $headers -Method Head -UseBasicParsing -SkipCertificateCheck -TimeoutSec 10 -ErrorAction Stop
            if ($resp.StatusCode -eq 200) { Write-Host "SSC is available (HTTP 200)." -ForegroundColor Green; return $true }
        } catch {
            # swallow and retry
        }
        Start-Sleep -Seconds $PollIntervalSeconds
    }

    throw "Timed out waiting for SSC HTTP endpoint to return 200"
}
Export-ModuleMember -Function Wait-ForSSCReady
