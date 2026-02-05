<#
.SYNOPSIS
   Create and manage a local kind (Kubernetes IN Docker) cluster and deploy Fortify components.

.DESCRIPTION
   This PowerShell script provisions a local kind cluster (with ingress), deploys Fortify
   components (LIM, SSC, ScanCentral SAST/DAST) via Helm charts, manages TLS certificates,
   and provides helper operations for starting, stopping, cleaning up, and checking status.

   The script is intended to be run on Windows or Linux with PowerShell Core and requires
   Docker, kubectl, helm, kind and OpenSSL (for certificate generation). It can also
   optionally use mkcert to create a locally-trusted CA for development.

.PARAMETER Start
   Create/start the kind cluster and install the Fortify services specified via `-Services`.
.PARAMETER Stop
   Stop (but do not delete) the kind cluster. Containers are stopped so the cluster can be
   restarted without rebuilding.

.PARAMETER Delete
   Delete the kind cluster and remove generated certificates and artifacts.

.PARAMETER Status
   Show status of the kind cluster and deployed Fortify services.

.PARAMETER RecreateCertificates
   Forcefully recreate TLS certificates, keystores and truststores used by the demo and
   recreate the `ssc` secret if necessary.

.PARAMETER AutoSyncCerts
   When present the script will automatically detect differences between the local
   `certificate.pem` and the cluster `wildcard-certificate` secret and sync them.

.PARAMETER WhatIfConfig
   Print the resolved configuration (env variables and fortify.config) and exit.

.PARAMETER Services
   Comma-separated list of services to install. Values: LIM, SSC, SCSAST, SCDAST, SCDASTScanner, All

.EXAMPLE
   .\demo.ps1 -Start -Services LIM,SSC

.EXAMPLE
   .\demo.ps1 -Delete

.NOTES
   See README.md for more usage details and prerequisites.
#>

[CmdletBinding()]
# Parameters
param (
	[Parameter(Mandatory=$false, HelpMessage="Create a kind cluster and install the Fortify services specified")]
	[switch]$Start,
	[Parameter(Mandatory=$false, HelpMessage="Stop (but do not delete) the kind cluster")]
	[switch]$Stop,
	[Parameter(Mandatory=$false, HelpMessage="Stop and delete kind cluster and remove certificates and artifacts")]
	[switch]$Delete,
    [Parameter(Mandatory=$false, HelpMessage="Show status of kind cluster and Fortify services")]
    [switch]$Status,
	[Parameter(Mandatory=$false, HelpMessage="Forcefully recreate certificates")]
    [switch]$RecreateCertificates,
	[Parameter(Mandatory=$false, HelpMessage="Auto-detect and sync local certificates to cluster on startup (opt-in)")]
	[switch]$AutoSyncCerts,
	[Parameter(Mandatory=$false, HelpMessage="Show resolved configuration and exit")]
	[switch]$WhatIfConfig,
	[Parameter(Mandatory=$false, HelpMessage="Show this help and exit")]
	[switch]$Help,
	[Parameter(Mandatory=$false, HelpMessage="Services to install. One or more of: LIM, SSC, SCSAST, SCDAST, SCDASTScanner, All")]
	[ValidateSet('LIM','SSC','SCSAST','SCDAST','SCDASTScanner','All')]
	[string[]]$Services = @()
)

# Helper to determine whether a named service should be installed
function ServiceSelected {
    param([string]$Name)
    if (-not $Services) { return $false }
    return ($Services -contains 'All' -or $Services -contains $Name)
}

# Ensure Docker engine is available and running; exit with helpful message otherwise
function Ensure-DockerRunning {
	Progress "Checking Docker availability..."
	$dockerOutput = & docker info 2>&1
	if ($LASTEXITCODE -ne 0) {
		Fail "Docker does not appear to be running or the Docker CLI is not available. Start Docker Desktop (or the Docker engine) and re-run this script.`nDocker error: $dockerOutput"
	}
}

# Resolve config values: prefer environment variable of same name, otherwise fall back to existing variable
function Resolve-ConfigValue {
	param([string]$Name)
	$envVal = $null
	try { $envVal = Get-ChildItem env:$Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Value -ErrorAction SilentlyContinue } catch { $envVal = $null }
	if (-not [string]::IsNullOrEmpty($envVal)) { return $envVal }

	$var = Get-Variable -Name $Name -ErrorAction SilentlyContinue
	if ($var) { return $var.Value }

	return $null
}

# Display script help/usage
function Show-Help {
	Write-Host "" -ForegroundColor Yellow
	Write-Host "demo.ps1 - Help" -ForegroundColor Cyan
	Write-Host "Usage: .\demo.ps1 [-Start] [-Stop] [-Delete] [-Status] [-RecreateCertificates] [-WhatIfConfig] [-Help] [-Services <list>] [-Debug] [-Verbose]" -ForegroundColor Green
	Write-Host "" 
	Write-Host "Options:" -ForegroundColor Cyan
	Write-Host "  -Start                  : Create a kind cluster and install the Fortify services specified" 
	Write-Host "  -Stop                   : Stop (but do not delete) the kind cluster" 
	Write-Host "  -Delete                 : Stop and delete kind cluster and remove certificates and artifacts" 
	Write-Host "  -Status                 : Show status of kind cluster and Fortify services" 
	Write-Host "  -RecreateCertificates   : Forcefully recreate TLS certificates" 
	Write-Host "  -WhatIfConfig           : Show resolved configuration (env / fortify.config) and exit" 
	Write-Host "  -Help                   : Show this help and exit" 
	Write-Host "  -Services <list>        : Comma-separated list of services to install. Values: LIM, SSC, SCSAST, SCDAST, SCDASTScanner, All" 
	Write-Host "  -Debug                  : Show unmasked secret values in WhatIfConfig (for debugging only)" 
	Write-Host "  -Verbose                : Show which environment variable names were checked for each key" 
	Write-Host "" 
	Write-Host "Examples:" -ForegroundColor Cyan
	Write-Host "  .\demo.ps1 -Start -Services LIM,SSC            # start cluster and install LIM and SSC" 
	Write-Host "  .\demo.ps1 -Start -Services All                # start cluster and install all services" 
	Write-Host "  .\demo.ps1 -WhatIfConfig -Verbose -Debug         # show resolved config, list env names checked, unmasked" 
	Write-Host ""
}

# Console helpers for colored progress messages (like deploy.ps1)
function Fail([string]$msg) { Write-Error $msg; Exit 1 }
function Info([string]$msg) { Write-Host $msg -ForegroundColor Cyan }
function Progress([string]$msg) { Write-Host $msg -ForegroundColor Yellow }
function Success([string]$msg) { Write-Host $msg -ForegroundColor Green }

# Resolve common configuration keys from environment (preferred) or existing variables
$ConfigKeys = @(
	'LIM_ADMIN_USER','LIM_ADMIN_PASSWORD','LIM_POOL_NAME','LIM_POOL_PASSWORD',
	'DOCKERHUB_USERNAME','DOCKERHUB_PASSWORD','CERTIFICATE_SIGNING_PASSWORD',
	'SSC_ADMIN_USER','SSC_ADMIN_PASSWORD','DEBRICKED_TOKEN',
	'LIM_HELM_VERSION','MYSQL_HELM_VERSION','SSC_HELM_VERSION','SCSAST_HELM_VERSION',
	'POSTGRES_HELM_VERSION','SCDAST_HELM_VERSION','SCDAST_SCANNER_HELM_VERSION',
	'OPENSSL_PATH','OPENSSL_WINDOWS_PATH','OPENSSL_LINUX_PATH',
	'HOST_HTTP_PORT','HOST_HTTPS_PORT'
)
function Load-FortifyConfig {
	$cfgPath = Join-Path $PSScriptRoot 'fortify.config'
	if (-not (Test-Path $cfgPath)) { return }
	$script:FortifyConfig = @{}
	Get-Content $cfgPath | ForEach-Object {
		$line = $_.Trim()
		if (-not $line -or $line.StartsWith('#')) { return }
		if ($line -match '^(.*?)=(.*)$') {
			$k = $matches[1].Trim()
			$v = $matches[2].Trim()
			if ($v -eq '') { return }
			# Set variable with same name as key
			try { Set-Variable -Name $k -Value $v -Scope Script -ErrorAction SilentlyContinue } catch {}
			# record in hashtable for fallback display
			$script:FortifyConfig[$k] = $v
			# Map common alternate names
			if ($k -eq 'OPENSSL_PATH' -and -not (Get-Variable -Name 'OPENSSL' -Scope Script -ErrorAction SilentlyContinue)) {
				Set-Variable -Name 'OPENSSL' -Value $v -Scope Script
			}
			if ($k -eq 'DEBRICKED_TOKEN' -and -not (Get-Variable -Name 'DEBRICKED_ACCESS_TOKEN' -Scope Script -ErrorAction SilentlyContinue)) {
				Set-Variable -Name 'DEBRICKED_ACCESS_TOKEN' -Value $v -Scope Script
			}
		}
	}
}

# Load fortify.config so variables are available as script vars
Load-FortifyConfig

foreach ($k in $ConfigKeys) {
	$v = Resolve-ConfigValue $k
	if ($v -ne $null) { Set-Variable -Name $k -Value $v -Scope Script }
}

# Backwards compatibility: keep older logic using $Start/$Stop only

# Import helper functions (Get-PodStatus, Wait-UntilPodStatus, etc.)
$FortifyModule = Join-Path $PSScriptRoot 'modules\FortifyFunctions.psm1'
if (Test-Path $FortifyModule) {
	Import-Module $FortifyModule -Scope Global -Force
} else {
	Write-Host "Warning: helper module not found: $FortifyModule" -ForegroundColor Yellow
}

# Ensure $EnvFile has a sensible default and the file exists
if (-not (Get-Variable -Name EnvFile -Scope Script -ErrorAction SilentlyContinue) -or [string]::IsNullOrEmpty($EnvFile)) {
	$EnvFile = Join-Path $PSScriptRoot 'fortify.env'
}
if (-not (Test-Path -Path $EnvFile)) {
	New-Item -Path $EnvFile -ItemType File -Force | Out-Null
}

# If user requested help, or no CLI options were provided, show help and exit
if ($Help.IsPresent -or ($PSBoundParameters.Count -eq 0)) {
    Show-Help
    exit 0
}

# Choose platform-specific OpenSSL path if provided
$runningOnWindows = $false
if ($env:OS -and $env:OS -ieq 'Windows_NT') { $runningOnWindows = $true }

if ($runningOnWindows) {
	$osOpenSsl = Resolve-ConfigValue 'OPENSSL_WINDOWS_PATH'
	if (-not $osOpenSsl) { $osOpenSsl = Resolve-ConfigValue 'OPENSSL_PATH' }
} else {
	$osOpenSsl = Resolve-ConfigValue 'OPENSSL_LINUX_PATH'
	if (-not $osOpenSsl) { $osOpenSsl = Resolve-ConfigValue 'OPENSSL_PATH' }
}
if ($osOpenSsl) { Set-Variable -Name 'OPENSSL' -Value $osOpenSsl -Scope Script }

# Support -WhatIfConfig: display resolved configuration and exit (masked)
if ($WhatIfConfig.IsPresent) {
	# Determine whether to show unmasked values (user passed -Debug or debug preference enabled)
	$ShowUnmasked = $false
	if ($PSBoundParameters.ContainsKey('Debug') -or $DebugPreference -ne 'SilentlyContinue') { $ShowUnmasked = $true }

	function MaskVal([string]$name, [object]$val) {
		if (-not $val) { return '<not set>' }
		if ($ShowUnmasked) { return $val }
		$lower = $name.ToLower()
		if ($lower -like '*pass*' -or $lower -like '*secret*' -or $lower -like '*token*') { return '****(masked)' }
		return $val
	}

	$showKeys = @()
	$showKeys += $ConfigKeys
	# Ensure host port keys are included in WhatIfConfig
	$showKeys += @('HOST_HTTP_PORT','HOST_HTTPS_PORT')

	$report = @()
	foreach ($k in $showKeys | Sort-Object -Unique) {
		# prefer env var
		$envVal = (Get-Item -Path "Env:\$k" -ErrorAction SilentlyContinue).Value
		$src = $null
		$val = $null
		if ($envVal -and $envVal -ne '') { $val = $envVal; $src = "env:$k" }
		else {
			# check script variable
			$gv = Get-Variable -Name $k -Scope Script -ErrorAction SilentlyContinue
			if ($gv) { $val = $gv.Value; $src = 'script' }
			# fallback to fortify.config parsed values
			if (-not $val -and $script:FortifyConfig -and $script:FortifyConfig.ContainsKey($k)) { $val = $script:FortifyConfig[$k]; $src = 'fortify.config' }
		}
		if (-not $src) { $src = '<not set>' }

		$display = MaskVal $k $val
		$report += [PSCustomObject]@{ Key=$k; Value=$display; Source=$src }
	}

	Write-Host "=== Effective demo configuration (WhatIfConfig) ===" -ForegroundColor Yellow
	$report | Format-Table -Property @{Label='Key';Expression={$_.Key}}, @{Label='Value';Expression={$_.Value}}, @{Label='Source';Expression={$_.Source}} -AutoSize
	Write-Host "Note: keys containing 'pass', 'secret', or 'token' are masked." -ForegroundColor Yellow
	# If verbose requested, show which environment variable names were checked for each key
	if ($PSBoundParameters.ContainsKey('Verbose')) {
		Write-Host "`nEnvironment variables checked (per key):" -ForegroundColor Yellow
		# Alternate env names to check for certain keys
		$alternate = @{ 'OPENSSL' = @('OPENSSL_PATH'); 'DEBRICKED_ACCESS_TOKEN' = @('DEBRICKED_TOKEN') }

		foreach ($k in $showKeys | Sort-Object) {
			$candidates = @()
			$candidates += $k
			if ($alternate.ContainsKey($k)) { $candidates += $alternate[$k] }

			foreach ($envName in $candidates) {
				if (-not $envName) { continue }
				$e = Get-Item -Path "Env:\$envName" -ErrorAction SilentlyContinue
				if ($e -and $e.Value -ne '') {
					if ($ShowUnmasked) { $valShown = $e.Value } else { $valShown = MaskVal $k $e.Value }
					Write-Host ('    {0,-25} -> {1, -40} (present)' -f $envName, $valShown) -ForegroundColor DarkGreen
				} else {
					Write-Host ('    {0,-25} -> {1, -40} (absent)' -f $envName, '<not set>') -ForegroundColor DarkGray
				}
			}
		}
	}
	exit 0
}

if (ServiceSelected 'LIM')
{
    if ([string]::IsNullOrEmpty($LIM_ADMIN_USER)) { throw "LIM_ADMIN_USER needs to be set in fortify.config" }
    if ([string]::IsNullOrEmpty($LIM_ADMIN_PASSWORD)) { throw "LIM_ADMIN_PASSWORD needs to be set in fortify.config" }
    if ([string]::IsNullOrEmpty($LIM_POOL_NAME)) { throw "LIM_POOL_NAME needs to be set in fortify.config" }
    if ([string]::IsNullOrEmpty($LIM_POOL_PASSWORD)) { throw "LIM_POOL_PASSWORD needs to be set in fortify.config" }
}
if (ServiceSelected 'SSC')
{
    # any other required SSC settings
}
if (ServiceSelected 'SCSAST')
{
    # any other required SCSAST settings
}
if (ServiceSelected 'SCDAST')
{
    #if ([string]::IsNullOrEmpty($LIM_API_URL)) { throw "LIM_API_URL needs to be set in fortify.config" }
    if ([string]::IsNullOrEmpty($LIM_ADMIN_USER)) { throw "LIM_ADMIN_USER needs to be set in fortify.config" }
    if ([string]::IsNullOrEmpty($LIM_ADMIN_PASSWORD)) { throw "LIM_ADMIN_PASSWORD needs to be set in fortify.config" }
    if ([string]::IsNullOrEmpty($LIM_POOL_NAME)) { throw "LIM_POOL_NAME needs to be set in fortify.config" }
    if ([string]::IsNullOrEmpty($LIM_POOL_PASSWORD)) { throw "LIM_POOL_PASSWORD needs to be set in fortify.config" }
}
if (ServiceSelected 'SCDASTScanner')
{
    # any other required SCDAST Scanner settings
}

# check if kind cluster is running
# Verify Docker is running before invoking kind
Ensure-DockerRunning

$KindClusterName = "fortify-demo"
$KindClusters = (kind get clusters)

# Set kubectl context to kind cluster
& kubectl config use-context "kind-$KindClusterName"

$KindIP = "127.0.0.1"
$LIMUrl = "lim.$( $KindIP.Replace('.','-') ).nip.io"
$LIMInternalUrl = "https://lim:37562/"
$SSCUrl = "ssc.$( $KindIP.Replace('.','-') ).nip.io"
$SCSASTUrl = "scsast.$( $KindIP.Replace('.','-') ).nip.io"
$SCSASTInternalUrl = "http://scancentral-sast-controller:80"
$SCDASTAPIUrl = "scdastapi.$( $KindIP.Replace('.','-') ).nip.io"
$SCDASTAPIInternalUrl = "https://scancentral-dast-core-api:34785"
$CertUrl = "/CN=*.$( $KindIP.Replace('.','-') ).nip.io"

# Internal container ports (used when referencing services inside the cluster)
$InternalHttpsPort = 443
$SSCInternalUrl = "https://ssc-service:$InternalHttpsPort"

# Host ports mapped by kind (hostPort -> containerPort)
# Allow overriding via HOST_HTTP_PORT and HOST_HTTPS_PORT (env or fortify.config)
$cfgHostHttp = Resolve-ConfigValue 'HOST_HTTP_PORT'
if ($cfgHostHttp -and $cfgHostHttp -ne '') { $HostHttpPort = [int]$cfgHostHttp } else { $HostHttpPort = 80 }
$cfgHostHttps = Resolve-ConfigValue 'HOST_HTTPS_PORT'
if ($cfgHostHttps -and $cfgHostHttps -ne '') { $HostHttpsPort = [int]$cfgHostHttps } else { $HostHttpsPort = 443 }

# Helper functions copied from startup.ps1
function Show-Status {
	Progress "Checking kind cluster and Fortify service status..."
	$KindClusters = (kind get clusters) 2>$null
	$isRunning = $false
	if ($KindClusters -and ($KindClusters -contains $KindClusterName)) {
		# Check control-plane container state
		$controlPlaneName = "$KindClusterName-control-plane"
		$runningContainer = (& docker ps --filter "name=$controlPlaneName" --format "{{.Names}}") 2>$null
		$allContainers = (& docker ps -a --filter "name=$KindClusterName" --format "{{.Names}}") 2>$null

		if (-not $allContainers) {
			Info "kind cluster '$KindClusterName' not found (no containers)."
			return
		}

		$isRunning = -not [string]::IsNullOrEmpty($runningContainer)
		if ($isRunning) {
			Success "kind cluster '$KindClusterName' is running."
			& kubectl cluster-info --context "kind-$KindClusterName" 2>$null
		}
		else {
			Write-Host "kind cluster '$KindClusterName' exists but control-plane container is STOPPED." -ForegroundColor Yellow
		}
	}
	else {
		Write-Host "kind cluster '$KindClusterName' is NOT running."
		return
	}

	# Show pod statuses for known Fortify components in a table
	$knownServices = @{
		LIM = 'lim-0';
		SSC = 'ssc-webapp-0';
		SCSAST = 'scancentral-sast-controller-0';
		SCDAST = 'scancentral-dast-core-api-0';
		SCDAST_SCANNER = 'scancentral-dast-scanner-0'
	}

	# Determine which services to display: use provided -Services if present, otherwise show all
	if ($Services -and $Services.Count -gt 0) {
		$requested = $Services | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
		$showKeys = $requested | Where-Object { $knownServices.Keys -contains $_ }
		if (-not $showKeys -or $showKeys.Count -eq 0) {
			Write-Host "No matching services found for: $($requested -join ', ')" -ForegroundColor Yellow
			return
		}
	}
	else {
		$showKeys = $knownServices.Keys
	}

	function Get-PodInfo {
		param([string]$PodName)
		# Try default namespace first
		try {
			$out = & kubectl get pod $PodName -n default -o jsonpath='{.metadata.name}||{.metadata.namespace}||{.status.podIP}' 2>$null
			if ($LASTEXITCODE -eq 0 -and $out) {
				$parts = $out -split '\|\|'
				return [PSCustomObject]@{ Name=$parts[0]; Namespace=$parts[1]; PodIP=$parts[2] }
			}
		} catch {}

		# Try current namespace / context
		try {
			$out = & kubectl get pod $PodName -o jsonpath='{.metadata.name}||{.metadata.namespace}||{.status.podIP}' 2>$null
			if ($LASTEXITCODE -eq 0 -and $out) {
				$parts = $out -split '\|\|'
				return [PSCustomObject]@{ Name=$parts[0]; Namespace=$parts[1]; PodIP=$parts[2] }
			}
		} catch {}

		# Fallback: search all namespaces for exact or prefix match
		try {
			$json = & kubectl get pods --all-namespaces -o json 2>$null
			if ($json) {
				$j = $json | ConvertFrom-Json
				foreach ($item in $j.items) {
					if ($item.metadata.name -eq $PodName -or $item.metadata.name.StartsWith($PodName)) {
						return [PSCustomObject]@{ Name=$item.metadata.name; Namespace=$item.metadata.namespace; PodIP=$item.status.podIP }
					}
				}
			}
		} catch {}

		return [PSCustomObject]@{ Name=$PodName; Namespace=''; PodIP='' }
	}

	$fmt = "{0,-16}{1,-30}{2,-12}{3,-16}{4,-12}"
	Write-Host ""
	Write-Host ($fmt -f 'Service', 'Pod', 'Namespace', 'Pod IP', 'Status')
	Write-Host ($fmt -f '-------', '---', '---------', '------', '------')

	foreach ($k in $showKeys) {
		$pod = $knownServices[$k]
		$podInfo = Get-PodInfo -PodName $pod
		if ($isRunning) {
			$status = $null
			try { $status = Get-PodStatus -PodName $pod -ErrorAction Stop } catch { $status = $null }
			if ([string]::IsNullOrEmpty($status)) { $status = 'Not found' }
		}
		else {
			$status = 'Cluster stopped'
		}
		Write-Host ($fmt -f $k, $podInfo.Name, $podInfo.Namespace, $podInfo.PodIP, $status)
	}

	# Display external URLs only for the services requested (or all if none requested)
	Write-Host ""
	Write-Host "External URLs (use host ports if configured):"
	if ($showKeys -contains 'LIM' -and $LIMUrl) { Write-Host "  LIM:        https://$($LIMUrl):$($HostHttpsPort)" }
	if ($showKeys -contains 'SSC' -and $SSCUrl) { Write-Host "  SSC:        https://$($SSCUrl):$($HostHttpsPort)" }
	if ($showKeys -contains 'SCSAST' -and $SCSASTUrl) { Write-Host "  SCSAST:     https://$($SCSASTUrl):$($HostHttpsPort)/scancentral-ctrl" }
	if ($showKeys -contains 'SCDAST' -and $SCDASTAPIUrl) { Write-Host "  SCDAST API: https://$($SCDASTAPIUrl):$($HostHttpsPort)" }
}

function Do-Shutdown {
	Progress "Stopping kind cluster containers (will not delete the cluster)..."
	$containers = (& docker ps -aq --filter "name=$KindClusterName") 2>$null
	if ($containers) {
		foreach ($c in $containers) { & docker stop $c | Out-Null; Write-Host "Stopped container $c" }
	}
	else { Write-Host "No kind containers found for '$KindClusterName'." }
}

function Do-Delete {
	Progress "Cleaning up kind cluster and artifacts..."

	# Stop any running containers for the cluster
	$containers = (& docker ps -aq --filter "name=$KindClusterName") 2>$null
	if ($containers) {
		Info "Stopping containers..."
		foreach ($c in $containers) { & docker stop $c | Out-Null; Info "Stopped container $c" }
	}
	else {
		Write-Host "No running KIND containers found for '$KindClusterName'."
	}

	# Delete kind cluster if it exists
	$KindClustersNow = (kind get clusters) 2>$null
	if ($KindClustersNow -and ($KindClustersNow -contains $KindClusterName)) {
		Progress "Deleting cluster \"$KindClusterName\" ..."
		& kind delete cluster --name $KindClusterName
	}
	else {
		Write-Host "No kind cluster named '$KindClusterName' found."
	}

	# Remove certificates directory if present
	$CertDir = Join-Path $PSScriptRoot -ChildPath "certificates"
	if (Test-Path $CertDir) {
		Info "Removing certificates directory: $CertDir"
		Remove-Item -LiteralPath $CertDir -Force -Recurse
	}
	else { Write-Host "Certificates directory not present. Skipping." }

	# Remove ssc-secret dir if present
	$SSCSecretDir = Join-Path $PSScriptRoot -ChildPath "ssc-secret"
	if (Test-Path $SSCSecretDir) {
		Info "Removing SSC secret directory: $SSCSecretDir"
		Remove-Item -LiteralPath $SSCSecretDir -Force -Recurse
	}
	else { Write-Host "SSC secret directory not present. Skipping." }

	Success "Cleanup complete."
}
function Do-Startup {
	if ($KindClusters -contains $KindClusterName)
	{
		# Check whether the control-plane container is running; if stopped, start it instead of recreating the cluster
		$controlPlaneName = "$KindClusterName-control-plane"
		$runningContainer = (& docker ps --filter "name=$controlPlaneName" --format "{{.Names}}") 2>$null
		if (-not [string]::IsNullOrEmpty($runningContainer)) {
			Success "kind cluster '$KindClusterName' is running ..."
		}
		else {
			Write-Host "kind cluster '$KindClusterName' exists but control-plane container is STOPPED." -ForegroundColor Yellow
			Progress "Starting existing kind control-plane container..."
			try {
				& docker start $controlPlaneName | Out-Null
				# start any other stopped cluster containers matching the cluster name
				$allContainers = (& docker ps -a --filter "name=$KindClusterName" --format "{{.Names}}") 2>$null
				foreach ($c in $allContainers) {
					if ($c -ne $controlPlaneName) { & docker start $c | Out-Null }
				}
			} catch {
				Write-Host "Failed to start kind containers: $_" -ForegroundColor Red
			}

			# Wait for Kubernetes API to become responsive
			function Test-KubeApiAvailable {
				param([string]$Context, [int]$TimeoutSeconds = 60)
				$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
				while ((Get-Date) -lt $deadline) {
					try {
						& kubectl get ns --context $Context 2>$null | Out-Null
						if ($LASTEXITCODE -eq 0) { return $true }
					} catch {}
					Start-Sleep -Seconds 2
				}
				return $false
			}

			if (-not (Test-KubeApiAvailable -Context "kind-$KindClusterName" -TimeoutSeconds 60)) {
				Write-Host "Kubernetes API did not become available after starting containers; attempt cluster recreate." -ForegroundColor Yellow
				& kind delete cluster --name $KindClusterName
				Start-Sleep -Seconds 3
				# fall through to create the cluster below
			} else {
				Success "kind cluster '$KindClusterName' started and API is available."
				return
			}
		}
	}
	else
    {
		Progress "kind cluster '$KindClusterName' not running ... creating ..."
        
            # Create kind cluster with ingress support
            # Use a preconfigured kind config file checked into the repository
            $KindConfigFile = Join-Path $PSScriptRoot -ChildPath "kind-config.yaml"
            if (-not (Test-Path $KindConfigFile)) {
                throw "kind-config.yaml not found in repository. Add a preconfigured kind-config.yaml to the repo root before running this script."
            }

	    # Check that kind-config.yaml hostPort mappings align with HOST_HTTP_PORT / HOST_HTTPS_PORT
	    function Get-KindHostPortForContainerPort {
	        param([string]$FilePath, [int]$ContainerPort)
	        try {
	            $lines = Get-Content -Path $FilePath -ErrorAction Stop
	        } catch { return $null }
	        for ($i = 0; $i -lt $lines.Count; $i++) {
	            if ($lines[$i] -match "containerPort:\s*${ContainerPort}\b") {
	                for ($j = 1; $j -le 6; $j++) {
	                    if ($i + $j -lt $lines.Count) {
	                        if ($lines[$i + $j] -match "hostPort:\s*(\d+)") {
	                            return [int]$matches[1]
	                        }
	                    }
	                }
	            }
	        }
	        return $null
	    }

	    function Check-KindConfigPorts {
	        param([string]$FilePath, [int]$ExpectedHttpPort, [int]$ExpectedHttpsPort)
	        $hp80 = Get-KindHostPortForContainerPort -FilePath $FilePath -ContainerPort 80
	        $hp443 = Get-KindHostPortForContainerPort -FilePath $FilePath -ContainerPort 443
	        if ($hp80 -and $hp80 -ne $ExpectedHttpPort) {
	            Write-Host "Warning: kind-config.yaml maps containerPort 80 to hostPort $hp80, but HOST_HTTP_PORT is $ExpectedHttpPort." -ForegroundColor Yellow
	            Write-Host "  Suggestion: update kind-config.yaml extraPortMappings hostPort for containerPort 80 or set HOST_HTTP_PORT in fortify.config to match." -ForegroundColor Yellow
	        }
	        if ($hp443 -and $hp443 -ne $ExpectedHttpsPort) {
	            Write-Host "Warning: kind-config.yaml maps containerPort 443 to hostPort $hp443, but HOST_HTTPS_PORT is $ExpectedHttpsPort." -ForegroundColor Yellow
	            Write-Host "  Suggestion: update kind-config.yaml extraPortMappings hostPort for containerPort 443 or set HOST_HTTPS_PORT in fortify.config to match." -ForegroundColor Yellow
	        }
	        if (($hp80 -and $hp80 -lt 1024) -or ($hp443 -and $hp443 -lt 1024)) {
	            Write-Host "Note: mapping host ports <1024 may require elevated privileges when creating the kind cluster." -ForegroundColor Yellow
	        }
	    }

	    Check-KindConfigPorts -FilePath $KindConfigFile -ExpectedHttpPort $HostHttpPort -ExpectedHttpsPort $HostHttpsPort
        
        & kind create cluster --name $KindClusterName --config $KindConfigFile
        
        Start-Sleep -Seconds 5
        
        # Install NGINX Ingress Controller
        Write-Host "Installing NGINX Ingress Controller ..."
        & kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
        
        Write-Host "Waiting for ingress controller to be ready ..."
        & kubectl wait --namespace ingress-nginx --for=condition=ready pod --selector=app.kubernetes.io/component=controller --timeout=90s
        
        Write-Host "kind cluster is running ..."
    }

	Write-Host "Starting up kind and Fortify components..."

	& kubectl delete secret docker-registry fortifydocker --ignore-not-found
	& kubectl create secret docker-registry fortifydocker --docker-username $DOCKERHUB_USERNAME --docker-password $DOCKERHUB_PASSWORD

	$CertDir = Join-Path $PSScriptRoot -ChildPath "certificates"
	if ($RecreateCertificates)
	{
		Write-Host "Deleting existing certificates ..."
		if ((Test-Path -PathType container $CertDir))
		{
			Remove-Item -LiteralPath $CertDir -Force -Recurse
		}
	}

	if ((Test-Path -PathType container $CertDir))
	{
		Write-Host "Certificates already exist, not creating ..."
	}
	else
	{
		Write-Host "Creating certificates ..."

		New-Item -ItemType Directory -Path $CertDir

		Set-Location $CertDir

		# Prefer mkcert when available (creates a locally-trusted CA and certs)
		$mkcert = Get-Command mkcert -ErrorAction SilentlyContinue
		if ($mkcert) {
			Write-Host "mkcert found - creating locally-trusted certificate..."
			# Ensure local CA is installed
			& mkcert -install

			# Hostnames to include (wildcard + specific service hostnames)
			$wildcard = "*.$( $KindIP.Replace('.','-') ).nip.io"
			$hosts = @($LIMUrl, $SSCUrl, $SCSASTUrl, $SCDASTAPIUrl, $wildcard)

			# Create cert and key
			& mkcert -cert-file certificate.pem -key-file key.pem $hosts

			# Create kubernetes TLS secret
			kubectl delete secret wildcard-certificate --ignore-not-found
			kubectl create secret tls wildcard-certificate --cert=certificate.pem --key=key.pem

			# Create PKCS12 keystore and PFX for services that expect them
			if ($OPENSSL) {
				& "$OPENSSL" pkcs12 -export -name ssc -in certificate.pem -inkey key.pem -out keystore.p12 -password pass:changeit
				& "$OPENSSL" pkcs12 -export -name lim -in certificate.pem -inkey key.pem -out certificate.pfx -password pass:changeit
			} else {
				Write-Host "Warning: OPENSSL not set - skipping pkcs12/pfx generation" -ForegroundColor Yellow
			}

			# Import keystore into Java keystore for SSC and create truststore from mkcert root CA
			if (Test-Path keystore.p12) {
				& keytool -importkeystore -destkeystore ssc-service.jks -srckeystore keystore.p12 -srcstoretype pkcs12 -alias ssc -srcstorepass changeit -deststorepass changeit
			}

			# Import mkcert root CA into truststore so Java trusts services
			try {
				$caroot = (& mkcert -CAROOT).Trim()
				$carootCert = Join-Path $caroot 'rootCA.pem'
				if (-not (Test-Path $carootCert)) { $carootCert = Join-Path $caroot 'rootCA.pem' }
				if (Test-Path $carootCert) {
					& keytool -import -trustcacerts -file $carootCert -alias mkcert-root -keystore truststore -storepass changeit -noprompt
				} else {
					Write-Host "mkcert CAROOT certificate not found at $carootCert" -ForegroundColor Yellow
				}
			} catch {
				Write-Host "Failed to import mkcert root CA into truststore: $_" -ForegroundColor Yellow
			}

		}
		else {
			Write-Host "mkcert not found - generating SAN certificate with OpenSSL..."
			# Create an OpenSSL config to include SANs
			$opensslConf = @"
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
CN = *.$( $KindIP.Replace('.','-') ).nip.io

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = *.$( $KindIP.Replace('.','-') ).nip.io
DNS.2 = $LIMUrl
DNS.3 = $SSCUrl
DNS.4 = $SCSASTUrl
DNS.5 = $SCDASTAPIUrl
"@

			$confPath = Join-Path $CertDir 'openssl-san.cnf'
			$opensslConf | Out-File -FilePath $confPath -Encoding ascii

			if (-not $OPENSSL) { Fail "OpenSSL path not configured (OPENSSL) - cannot create certificates." }

			& "$OPENSSL" req -new -nodes -newkey rsa:2048 -keyout key.pem -out req.pem -config $confPath
			& "$OPENSSL" x509 -req -days 3650 -in req.pem -signkey key.pem -out certificate.pem -extensions req_ext -extfile $confPath
			& "$OPENSSL" x509 -inform PEM -in certificate.pem -outform DER -out certificate.cer
			& "$OPENSSL" pkcs12 -export -name ssc -in certificate.pem -inkey key.pem -out keystore.p12 -password pass:changeit
			& "$OPENSSL" pkcs12 -export -name lim -in certificate.pem -inkey key.pem -out certificate.pfx -password pass:changeit

			kubectl delete secret wildcard-certificate --ignore-not-found
			kubectl create secret tls wildcard-certificate --cert=certificate.pem --key=key.pem

			& keytool -importkeystore -destkeystore ssc-service.jks -srckeystore keystore.p12 -srcstoretype pkcs12 -alias ssc -srcstorepass changeit -deststorepass changeit
			& keytool -import -trustcacerts -file certificate.pem -alias "wildcard-cert" -keystore truststore -storepass changeit -noprompt
		}

		Set-Location $PSScriptRoot
	}

		# Auto-detect: ensure cluster wildcard-certificate matches local certificate.pem
		function Get-CertSha256FromPemFile {
			param([string]$Path)
			if (-not (Test-Path $Path)) { return $null }
			$txt = Get-Content -Raw -Path $Path
			if ($txt -match '(?s)-----BEGIN CERTIFICATE-----(.*)-----END CERTIFICATE-----') {
				$inner = $matches[1] -replace '\s+',''
				try { $bytes = [Convert]::FromBase64String($inner) } catch { return $null }
				$sha = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
				return ([System.BitConverter]::ToString($sha)).Replace('-','').ToLower()
			}
			return $null
		}

		function Get-CertSha256FromSecret {
			param([string]$SecretName)
			try {
				$val = & kubectl get secret $SecretName -o jsonpath='{.data.tls\.crt}' 2>$null
			} catch { $val = $null }
			if (-not $val -or $val -eq '') { return $null }
			try { $bytes = [Convert]::FromBase64String($val) } catch { return $null }
			$sha = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
			return ([System.BitConverter]::ToString($sha)).Replace('-','').ToLower()
		}

		function Sync-WildcardCertificateAndSscSecretIfNeeded {
			param([string]$CertDir)
			$localPem = Join-Path $CertDir 'certificate.pem'
			$localKey = Join-Path $CertDir 'key.pem'
			$localHash = Get-CertSha256FromPemFile -Path $localPem
			$secretHash = Get-CertSha256FromSecret -SecretName 'wildcard-certificate'
			if (-not $localHash) { Write-Host 'No local certificate.pem found to compare.'; return }
			if ($localHash -ne $secretHash) {
				Write-Host 'Wildcard certificate in cluster differs from local certificate.pem — updating cluster secret...' -ForegroundColor Yellow
				& kubectl delete secret wildcard-certificate --ignore-not-found
				& kubectl create secret tls wildcard-certificate --cert=$localPem --key=$localKey
				# Recreate SSC secret only if both keystore and truststore exist
				$ks = Join-Path $CertDir 'ssc-service.jks'
				$trust = Join-Path $CertDir 'truststore'
				if (-not (Test-Path $ks) -or -not (Test-Path $trust)) {
					Write-Host 'Keystore or truststore missing; skipping SSC secret recreation to avoid creating incomplete secret.' -ForegroundColor Yellow
				} else {
					$SSCSecretDir = Join-Path $PSScriptRoot -ChildPath 'ssc-secret'
					if ((Test-Path -PathType Container $SSCSecretDir)) { Remove-Item -LiteralPath $SSCSecretDir -Force -Recurse }
					New-Item -ItemType Directory -Path $SSCSecretDir | Out-Null
					Copy-Item -Path (Join-Path $PSScriptRoot 'ssc.autoconfig') -Destination $SSCSecretDir -Force
					Copy-Item -Path (Join-Path $PSScriptRoot 'fortify.license') -Destination $SSCSecretDir -Force
					Copy-Item -Path $ks -Destination $SSCSecretDir -Force
					Copy-Item -Path $trust -Destination $SSCSecretDir -Force
					& kubectl delete secret ssc --ignore-not-found
					& kubectl create secret generic ssc --from-file=$SSCSecretDir --from-literal=ssc-service.jks.password=changeit --from-literal=ssc-service.jks.key.password=changeit --from-literal=truststore.password=changeit
					# restart the pod to pick up changes
					& kubectl delete pod ssc-webapp-0 --ignore-not-found
				}
			} else {
				Write-Host 'Wildcard certificate in cluster matches local certificate.pem.' -ForegroundColor Green
			}
		}

		# Run auto-detect sync on startup only if user opted in via -AutoSyncCerts
		if ($AutoSyncCerts) {
			Sync-WildcardCertificateAndSscSecretIfNeeded -CertDir $CertDir
		} else {
			Write-Host 'Certificate auto-sync is disabled. Use -AutoSyncCerts to enable.' -ForegroundColor Cyan
		}

		# If user requested certificate recreation, refresh the SSC secret so the webapp picks up new keystore/truststore
		if ($RecreateCertificates) {
			Write-Host "Recreating SSC secret from updated certificates..."
			$SSCSecretDir = Join-Path $PSScriptRoot -ChildPath "ssc-secret"
			if ((Test-Path -PathType Container $SSCSecretDir)) { Remove-Item -LiteralPath $SSCSecretDir -Force -Recurse }
			New-Item -ItemType Directory -Path $SSCSecretDir | Out-Null

			# Copy required secret files
			Copy-Item -Path (Join-Path $PSScriptRoot 'ssc.autoconfig') -Destination $SSCSecretDir -Force
			Copy-Item -Path (Join-Path $PSScriptRoot 'fortify.license') -Destination $SSCSecretDir -Force
			Copy-Item -Path (Join-Path $CertDir 'ssc-service.jks') -Destination $SSCSecretDir -Force
			Copy-Item -Path (Join-Path $CertDir 'truststore') -Destination $SSCSecretDir -Force

			# Recreate Kubernetes secret and restart the webapp pod to pick up new files
			& kubectl delete secret ssc --ignore-not-found
			& kubectl create secret generic ssc `
				--from-file=$SSCSecretDir `
				--from-literal=ssc-service.jks.password=changeit `
				--from-literal=ssc-service.jks.key.password=changeit `
				--from-literal=truststore.password=changeit

			# If SSC is already running, delete the pod so it restarts with new secret
			$sscPod = & kubectl get pods --no-headers -o custom-columns=":metadata.name" 2>$null | Select-String '^ssc-webapp-0$'  
			if ($sscPod) { & kubectl delete pod ssc-webapp-0 --ignore-not-found }
		}

	# Add Bitnami repo for MySQL and PostgreSQL charts
	& helm repo add bitnami https://charts.bitnami.com/bitnami 2>$null

	# run update to prevent spurious errors
	helm repo update

	$PersistentVolumeDir = Join-Path $PSScriptRoot -ChildPath "persistent_volume"
	$ResourceOverrideDir = Join-Path $PSScriptRoot -ChildPath "resource_override"
	$ValuesDir = Join-Path $PSScriptRoot -ChildPath "values"

	#
	# License Infrastructure Manager (LIM)
	#

	if (ServiceSelected 'LIM')
	{
		# check if LIM is already running
		$LIMStatus = Get-PodStatus -PodName lim-0
		if ($LIMStatus -eq "Running")
		{
			Write-Host "LIM is already running ..."
		}
		else
		{

			$CertPem = Join-Path $CertDir -ChildPath "certificate.pem"
			$CertKey = Join-Path $CertDir -ChildPath "key.pem"
			$CertPfx = Join-Path $CertDir -ChildPath "certificate.pfx"
			$LimPv = Join-Path $PersistentVolumeDir -ChildPath "lim-pv.yaml"
			$LimPvc = Join-Path $PersistentVolumeDir -ChildPath "lim-pvc.yaml"

			& kubectl delete secret lim-admin-credentials --ignore-not-found
			& kubectl create secret generic lim-admin-credentials `
				--type=basic-auth `
				--from-literal=username=$LIM_ADMIN_USER `
				--from-literal=password="$LIM_ADMIN_PASSWORD"

			& kubectl delete secret lim-jwt-security-key --ignore-not-found
			& kubectl create secret generic lim-jwt-security-key `
				--type=Opaque `
				--from-literal=token="$CERTIFICATE_SIGNING_PASSWORD"
                
			& kubectl delete secret lim-server-certificate --ignore-not-found    
			& kubectl create secret generic lim-server-certificate `
				--type=TLS `
				--from-file=tls.crt=$CertPem `
				--from-file=tls.key=$CertKey

			& kubectl delete secret lim-signing-certificate --ignore-not-found    
			& kubectl create secret generic lim-signing-certificate `
				--type=Opaque `
				--from-file=tls.pfx=$CertPfx

			& kubectl delete secret lim-signing-certificate-password --ignore-not-found    
			& kubectl create secret generic lim-signing-certificate-password `
				--type=Opaque `
				--from-literal=pfx.password=changeit

			& kubectl apply --filename=$LimPv
			& kubectl apply --filename=$LimPvc

			helm install lim oci://registry-1.docker.io/fortifydocker/helm-lim --version $LIM_HELM_VERSION `
				--set imagePullSecrets[0].name=fortifydocker `
				--set dataPersistence.existingClaim=fortify-lim `
				--set dataPersistence.storeLogs=true `
				--set defaultAdministrator.credentialsSecretName=lim-admin-credentials `
				--set defaultAdministrator.fullName="LIM Administrator" `
				--set defaultAdministrator.email="limadm@ftfydemo.local" `
				--set allowNonTrustedServerCertificate=true `
				--set jwt.securityKeySecretName=lim-jwt-security-key `
				--set serverCertificate.certificateSecretName=lim-server-certificate `
				--set serverCertificate.certificatePasswordSecretName=lim-signing-server-certificate `
				--set signingCertificate.certificateSecretName=lim-signing-certificate `
				--set signingCertificate.certificatePasswordSecretName=lim-signing-certificate-password
                
			Write-Host
			$LIMStatus = Wait-UntilPodStatus -PodName lim-0

			& kubectl create ingress lim-ingress `
				--rule="$( $LIMUrl )/*=lim:37562,tls=wildcard-certificate" `
				--annotation nginx.ingress.kubernetes.io/backend-protocol=HTTPS `
				--annotation nginx.ingress.kubernetes.io/proxy-body-size='0' `
				--annotation nginx.ingress.kubernetes.io/client-max-body-size='512M'

			if ($LIMStatus -eq "Running")
			{
				Update-EnvFile -File $EnvFile -Find "^LIM_URL=.*$" -Replace "LIM_URL=https://$( $LIMUrl ):$( $HostHttpsPort )"
				Update-EnvFile -File $EnvFile -Find "^LIM_API_URL=.*$" -Replace "LIM_API_URL=https://$( $LIMUrl ):$( $HostHttpsPort )/LIM.API"
			}
		}
	}

	#
	# Software Security Center (SSC)
	#

	if (ServiceSelected 'SSC')
	{
		# check if SSC is already running
		$SSCStatus = Get-PodStatus -PodName ssc-webapp-0
		if ($SSCStatus -eq "Running")
		{
			Write-Host "SSC is already running ..."
		}
		else
		{
			# check if a database is already running (MySQL or MSSQL)
			$DbStatus = Get-PodStatus -PodName mysql-0
			if ($DbStatus -ne "Running") { $DbStatus = Get-PodStatus -PodName mssql-0 }
			if ($DbStatus -eq "Running")
			{
				Write-Host "Database is already running ..."
			}
			else
			{
				Write-Host "Installing database (MSSQL preferred) ..."
				$MySqlValues = Join-Path $ValuesDir -ChildPath "mysql-values.yaml"
				$MssqlValues = Join-Path $ValuesDir -ChildPath "mssql-values.yaml"
				# Prefer a local Microsoft SQL Server chart if present, then local MySQL chart, otherwise use Bitnami
				$LocalChartMssql = Join-Path $PSScriptRoot 'charts\mssql-official'
				$LocalChart = Join-Path $PSScriptRoot 'charts\mysql-official'
				if (Test-Path $LocalChartMssql) {
					& helm upgrade --install mssql $LocalChartMssql -f $MssqlValues
					$dbPodName = 'mssql-0'
				}
				elseif (Test-Path $LocalChart) {
					& helm upgrade --install mysql $LocalChart -f $MySqlValues
					$dbPodName = 'mysql-0'
				}
				else {
					& helm install mysql bitnami/mysql -f $MySqlValues --version $MYSQL_HELM_VERSION
					$dbPodName = 'mysql-0'
				}
				Start-Sleep -Seconds 30
				Write-Host
				$MySqlStatus = Wait-UntilPodStatus -PodName $dbPodName
			}

			Write-Host "Installing SSC ..."

			$SSCSecretDir = Join-Path $PSScriptRoot -ChildPath "ssc-secret"
			If ((Test-Path -PathType container $SSCSecretDir))
			{
				Remove-Item -LiteralPath $SSCSecretDir -Force -Recurse
			}
			New-Item -ItemType Directory -Path $SSCSecretDir

			Join-Path $PSScriptRoot -ChildPath "ssc.autoconfig" | Copy-Item -Destination $SSCSecretDir
			Join-Path $PSScriptRoot -ChildPath "fortify.license" | Copy-Item -Destination $SSCSecretDir
			Join-Path $CertDir -ChildPath "ssc-service.jks" |  Copy-Item -Destination $SSCSecretDir
			Join-Path $CertDir -ChildPath "truststore" | Copy-Item -Destination $SSCSecretDir

			Set-Location $SSCSecretDir

			& kubectl create secret generic ssc `
				--from-file=. `
				--from-literal=ssc-service.jks.password=changeit `
				--from-literal=ssc-service.jks.key.password=changeit `
				--from-literal=truststore.password=changeit

			Set-Location $PSScriptRoot

			$ResourceOverride = Join-Path $ResourceOverrideDir -ChildPath "ssc.yaml"
			helm install ssc oci://registry-1.docker.io/fortifydocker/helm-ssc --version $SSC_HELM_VERSION `
				--timeout 60m -f $ResourceOverride `
				--set urlHost="$( $SSCUrl )" `
				--set imagePullSecrets[0].name=fortifydocker `
				--set secretRef.name=ssc `
				--set secretRef.keys.sscLicenseEntry=fortify.license `
				--set secretRef.keys.sscAutoconfigEntry=ssc.autoconfig `
				--set secretRef.keys.httpCertificateKeystoreFileEntry=ssc-service.jks `
				--set secretRef.keys.httpCertificateKeystorePasswordEntry=ssc-service.jks.password `
				--set secretRef.keys.httpCertificateKeyPasswordEntry=ssc-service.jks.key.password `
				--set secretRef.keys.jvmTruststoreFileEntry=truststore `
				--set secretRef.keys.jmvTruststorePasswordEntry=truststore.password

			Write-Host 
			$SSCStatus = Wait-UntilPodStatus -PodName ssc-webapp-0

			kubectl create ingress ssc-ingress `
				--rule="$( $SSCUrl )/*=ssc-service:$( $InternalHttpsPort ),tls=wildcard-certificate" `
				--annotation nginx.ingress.kubernetes.io/backend-protocol=HTTPS `
				--annotation nginx.ingress.kubernetes.io/proxy-body-size='0' `
				--annotation nginx.ingress.kubernetes.io/client-max-body-size='512M'

			if ($SSCStatus -eq "Running")
			{
				Update-EnvFile -File $EnvFile -Find "^SSC_URL=.*$" -Replace "SSC_URL=https://$( $SSCUrl ):$( $HostHttpsPort )"
			}

		}
	}    

	#
	# ScanCentral SAST
	#

	if (ServiceSelected 'SCSAST')
	{
		$SCSastControllerStatus = Get-PodStatus -PodName scancentral-sast-controller-0
		if ($SCSastControllerStatus -eq "Running")
		{
			Write-Host "ScanCentral SAST is already running ..."
		}
		else
		{
			Write-Host "Installing ScanCentral SAST ..."

			$SSCServiceIP = (kubectl get service/ssc-service -o jsonpath='{.spec.clusterIP}')
			$CertPem = Join-Path $CertDir -ChildPath "certificate.pem"
			$ResourceOverride = Join-Path $ResourceOverrideDir -ChildPath "sast.yaml"
			helm install scancentral-sast oci://registry-1.docker.io/fortifydocker/helm-scancentral-sast --version $SCSAST_HELM_VERSION `
				--timeout 60m -f $ResourceOverride `
				--set imagePullSecrets[0].name=fortifydocker `
				--set-file secrets.fortifyLicense=fortify.license `
				--set controller.thisUrl="$( $SCSASTInternalUrl )" `
				--set controller.sscUrl="$( $SSCInternalUrl )" `
				--set controller.sscRemoteIp="10.0.0.0/8" `
				--set-file trustedCertificates[0]=$CertPem `
				--set controller.persistence.enabled=false `
				--set controller.ingress.enabled=true `
				--set controller.ingress.hosts[0].host="$( $SCSASTUrl )" `
				--set controller.ingress.hosts[0].paths[0].path=/ `
				--set controller.ingress.hosts[0].paths[0].pathType=Prefix `
				--set controller.ingress.tls[0].secretName=wildcard-certificate `
				--set controller.ingress.tls[0].hosts[0]="$( $SCSASTUrl )" `
				--set-string controller.ingress.annotations.'nginx\\.ingress\\.kubernetes\\.io\\/proxy-body-size'="512M"
                
			Write-Host
			$SCSastControllerStatus = Wait-UntilPodStatus -PodName scancentral-sast-controller-0

			if ($SCSastControllerStatus -eq "Running")
			{
				$ClientAuthTokenBase64 = (& kubectl get secret scancentral-sast -o jsonpath="{.data.scancentral-client-auth-token}")
				$ClientAuthToken = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($ClientAuthTokenBase64))
				$WorkerAuthTokenBase64 = (& kubectl get secret scancentral-sast -o jsonpath="{.data.scancentral-worker-auth-token}")
				$WorkerAuthToken = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($WorkerAuthTokenBase64))
				$ScanCentralCtrlSecretBase64 = (& kubectl get secret scancentral-sast -o jsonpath="{.data.scancentral-ssc-scancentral-ctrl-secret}")
				$ScanCentralCtrlSecret = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($ScanCentralCtrlSecretBase64))

				Update-EnvFile -File $EnvFile -Find "^SCSAST_URL=.*$" -Replace "SCSAST_URL=https://$( $SCSASTUrl )/scancentral-ctrl"
				# include host https port
				Update-EnvFile -File $EnvFile -Find "^SCSAST_URL=.*$" -Replace "SCSAST_URL=https://$( $SCSASTUrl ):$( $HostHttpsPort )/scancentral-ctrl"
				Update-EnvFile -File $EnvFile -Find "^CLIENT_AUTH_TOKEN=.*$" -Replace "CLIENT_AUTH_TOKEN=$( $ClientAuthToken )"
				Update-EnvFile -File $EnvFile -Find "^WORKER_AUTH_TOKEN=.*$" -Replace "WORKER_AUTH_TOKEN=$( $WorkerAuthToken )"
				Update-EnvFile -File $EnvFile -Find "^SHARED_SECRET=.*$" -Replace "SHARED_SECRET=$( $ScanCentralCtrlSecret )"
			}

			$SCSastWorkerStatus = Wait-UntilPodStatus -PodName scancentral-sast-worker-linux-0

		}
	}

	#
	# ScanCentral DAST
	#

	if (ServiceSelected 'SCDAST')
	{
		$PostgresStatus = Get-PodStatus -PodName postgresql-0
		if ($PostgresStatus -eq "Running")
		{
			Write-Host "Postgres is already running ..."
		}
		else
		{
			Write-Host "Installing Postgres ..."
			& helm install postgresql bitnami/postgresql --version $POSTGRES_HELM_VERSION `
				--set auth.postgresPassword=password `
				--set auth.database=scdast_db
			Start-Sleep -Seconds 30
			$PostgrSQLStatus = Wait-UntilPodStatus -PodName postgresql-0
		}

		$SCDastApiStatus = Get-PodStatus -PodName scancentral-dast-core-api-0
		if ($SCDastApiStatus -eq "Running")
		{
			Write-Host "ScanCentral DAST is already running ..."
		}
		else
		{
			Write-Host "Installing ScanCentral DAST ..."

			$CertPem = Join-Path $CertDir -ChildPath "certificate.pem"
			$CertKey = Join-Path $CertDir -ChildPath "key.pem"
			$CertPfx = Join-Path $CertDir -ChildPath "certificate.pfx"

			& kubectl delete secret lim-pool --ignore-not-found
			& kubectl create secret generic lim-pool `
				--type='basic-auth' `
				--from-literal=username=$LIM_POOL_NAME `
				--from-literal=password="$LIM_POOL_PASSWORD"

			& kubectl delete secret scdast-db-owner --ignore-not-found
			& kubectl create secret generic scdast-db-owner `
				--type='basic-auth' `
				--from-literal=username=postgres `
				--from-literal=password=password

			& kubectl delete secret scdast-db-standard --ignore-not-found
			& kubectl create secret generic scdast-db-standard `
				--type='basic-auth' `
				--from-literal=username=postgres `
				--from-literal=password=password
                
			& kubectl delete secret scdast-service-token --ignore-not-found
			& kubectl create secret generic scdast-service-token `
				--type='opaque' `
				--from-literal=service-token="$CERTIFICATE_SIGNING_PASSWORD"

			& kubectl delete secret scdast-ssc-serviceaccount --ignore-not-found
			& kubectl create secret generic scdast-ssc-serviceaccount `
				--type='basic-auth' `
				--from-literal=username=$SSC_ADMIN_USER `
				--from-literal=password="$SSC_ADMIN_PASSWORD"

			& kubectl delete secret api-server-certificate --ignore-not-found
			& kubectl create secret generic api-server-certificate `
				--type=Opaque `
				--from-file=tls.pfx=$CertPfx

			& kubectl delete secret api-server-certificate-password --ignore-not-found    
			& kubectl create secret generic api-server-certificate-password `
				--type=Opaque `
				--from-literal=pfx.password=changeit

			& kubectl delete secret utilityservice-server-certificate --ignore-not-found        
			& kubectl create secret generic utilityservice-server-certificate `
				--type=Opaque `
				--from-file=tls.pfx=$CertPfx

			& kubectl delete secret utilityservice-server-certificate-password --ignore-not-found        
			& kubectl create secret generic utilityservice-server-certificate-password `
				--type=Opaque `
				--from-literal=pfx.password=changeit

			$ResourceOverride = Join-Path $ResourceOverrideDir -ChildPath "dast-core.yaml"
			helm install scancentral-dast-core oci://registry-1.docker.io/fortifydocker/helm-scancentral-dast-core --version $SCDAST_HELM_VERSION `
				--timeout 60m -f $ResourceOverride `
				--set imagePullSecrets[0].name=fortifydocker `
				--set appsettings.lIMSettings.limUrl="$( $LIMInternalUrl )" `
				--set appsettings.sSCSettings.sSCRootUrl="$( $SSCInternalUrl )" `
				--set appsettings.debrickedSettings.accessToken="$( $DEBRICKED_TOKEN )" `
				--set appsettings.dASTApiSettings.disableCorsOrigins=true `
				--set appsettings.dASTApiSettings.corsOrigins[0]="=https://$( $SSCUrl )" `
				--set appsettings.environmentSettings.allowNonTrustedServerCertificate=true `
				--set appsettings.databaseSettings.databaseProvider=PostgreSQL `
				--set appsettings.databaseSettings.server=postgresql `
				--set database.dboLevelAccountCredentialsSecret=scdast-db-owner `
				--set database.standardAccountCredentialsSecret=scdast-db-standard `
				--set sscServiceAccountSecretName=scdast-ssc-serviceaccount `
				--set serviceTokenSecretName=scdast-service-token `
				--set limServiceAccountSecretName=lim-admin-credentials `
				--set limDefaultPoolSecretName=lim-pool `
				--set api.certificate.certificateSecretName=api-server-certificate `
				--set api.certificate.certificatePasswordSecretName=api-server-certificate-password `
				--set api.certificate.certificatePasswordSecretKey=pfx.password `
				--set utilityService.certificate.certificateSecretName=utilityservice-server-certificate `
				--set utilityService.certificate.certificatePasswordSecretName=utilityservice-server-certificate-password `
				--set utilityService.certificate.certificatePasswordSecretKey=pfx.password
                
			Write-Host
			$SCDastControllerStatus = Wait-UntilPodStatus -PodName scancentral-dast-core-api-0

			kubectl create ingress scdastapi-ingress `
				--rule="$( $SCDASTAPIUrl )/*=scancentral-dast-core-api:34785,tls=wildcard-certificate" `
				--annotation nginx.ingress.kubernetes.io/backend-protocol=HTTPS `
				--annotation nginx.ingress.kubernetes.io/proxy-body-size='0' `
				--annotation nginx.ingress.kubernetes.io/client-max-body-size='512M'

			if ($SCDastControllerStatus -eq "Running")
			{
				Update-EnvFile -File $EnvFile -Find "^SCDAST_API_URL=.*$" -Replace "SCDAST_API_URL=https://$( $SCDASTAPIUrl ):$( $HostHttpsPort )"
			}

		}
	}

	#
	# ScanCentral DAST Scanner
	#

	if (ServiceSelected 'SCDASTScanner')
	{
		$SCDastScannerStatus = Get-PodStatus -PodName scancentral-dast-scanner-0
		if ($SCDastScannerStatus -eq "Running")
		{
			Write-Host "ScanCentral DAST Scanner is already running ..."
		}
		else
		{
			Write-Host "Installing ScanCentral DAST Scanner ..."

			$ResourceOverride = Join-Path $ResourceOverrideDir -ChildPath "dast-sensor.yaml"
			helm install scancentral-dast-scanner oci://registry-1.docker.io/fortifydocker/helm-scancentral-dast-scanner --version $SCDAST_SCANNER_HELM_VERSION `
				--timeout 60m -f $ResourceOverride `
				--set imagePullSecrets[0].name=fortifydocker `
				--set scannerDescription="Linux DAST Scanner" `
				--set allowNonTrustedServerCertificate=true `
				--set dastApiServiceURL=$( $SCDASTAPIInternalUrl ) `
				--set serviceTokenSecretName=scdast-service-token
                
			Write-Host
			$SCDastScannerStatus = Wait-UntilPodStatus -PodName scancentral-dast-scanner-0
		}

	}

}

# If user requested status or shutdown, perform those and exit
if ($Status) {Show-Status; return}
if ($Start) { Do-Startup; return }
if ($Stop)  { Do-Shutdown; return }
if ($Delete) { Do-Delete; return }

Show-Help
exit 0
