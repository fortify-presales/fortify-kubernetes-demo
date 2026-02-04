# Example script to start kind and install Fortify LIM, SSC and ScanCentral SAST/DAST

# Parameters
param (
    [Parameter(Mandatory=$false, HelpMessage="Start and install the environment")]
    [switch]$Startup,
    [Parameter(Mandatory=$false, HelpMessage="Stop (but do not delete) the kind cluster")]
    [switch]$Shutdown,
    [Parameter(Mandatory=$false, HelpMessage="Cleanup: stop, delete cluster and remove certs")]
    [switch]$Cleanup,
    [Parameter(Mandatory=$false, HelpMessage="Show status (default)")]
    [switch]$Status,
	[Parameter(Mandatory=$false, HelpMessage="Recreate certificates")]
    [switch]$RecreateCertificates,
	[Parameter(Mandatory=$false, HelpMessage="Install LIM")]
	[switch]$InstallLIM,
	[Parameter(Mandatory=$false, HelpMessage="Install SSC")]
	[switch]$InstallSSC,
	[Parameter(Mandatory=$false, HelpMessage="Install SCSAST")]
	[switch]$InstallSCSAST,
	[Parameter(Mandatory=$false, HelpMessage="Install SCDAST")]
	[switch]$InstallSCDAST,
	[Parameter(Mandatory=$false, HelpMessage="Install SCDAST Scanner")]
	[switch]$InstallSCDASTScanner
)

if ($InstallLIM)
{
    if ([string]::IsNullOrEmpty($LIM_ADMIN_USER)) { throw "LIM_ADMIN_USER needs to be set in fortify.config" }
    if ([string]::IsNullOrEmpty($LIM_ADMIN_PASSWORD)) { throw "LIM_ADMIN_PASSWORD needs to be set in fortify.config" }
    if ([string]::IsNullOrEmpty($LIM_POOL_NAME)) { throw "LIM_POOL_NAME needs to be set in fortify.config" }
    if ([string]::IsNullOrEmpty($LIM_POOL_PASSWORD)) { throw "LIM_POOL_PASSWORD needs to be set in fortify.config" }
}
if ($InstallSSC)
{
    # any other required SSC settings
}
if ($InstallSCSAST)
{
    # any other required SCSAST settings
}
if ($InstallSCDAST)
{
    #if ([string]::IsNullOrEmpty($LIM_API_URL)) { throw "LIM_API_URL needs to be set in fortify.config" }
    if ([string]::IsNullOrEmpty($LIM_ADMIN_USER)) { throw "LIM_ADMIN_USER needs to be set in fortify.config" }
    if ([string]::IsNullOrEmpty($LIM_ADMIN_PASSWORD)) { throw "LIM_ADMIN_PASSWORD needs to be set in fortify.config" }
    if ([string]::IsNullOrEmpty($LIM_POOL_NAME)) { throw "LIM_POOL_NAME needs to be set in fortify.config" }
    if ([string]::IsNullOrEmpty($LIM_POOL_PASSWORD)) { throw "LIM_POOL_PASSWORD needs to be set in fortify.config" }
}
if ($InstallSCDASTScanner)
{
    # any other required SCDAST Scanner settings
}

# check if kind cluster is running
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
$HostHttpPort = 8080
$HostHttpsPort = 8443

& helm repo add bitnami https://charts.bitnami.com/bitnami 2>$null

# Helper functions copied from startup.ps1
function Show-Status {
	Write-Host "Checking kind cluster and Fortify service status..."
	$KindClusters = (kind get clusters) 2>$null
	$isRunning = $false
	if ($KindClusters -and ($KindClusters -contains $KindClusterName)) {
		# Check control-plane container state
		$controlPlaneName = "$KindClusterName-control-plane"
		$runningContainer = (& docker ps --filter "name=$controlPlaneName" --format "{{.Names}}") 2>$null
		$allContainers = (& docker ps -a --filter "name=$KindClusterName" --format "{{.Names}}") 2>$null

		if (-not $allContainers) {
			Write-Host "kind cluster '$KindClusterName' not found (no containers)."
			return
		}

		$isRunning = -not [string]::IsNullOrEmpty($runningContainer)
		if ($isRunning) {
			Write-Host "kind cluster '$KindClusterName' is running."
			& kubectl cluster-info --context "kind-$KindClusterName" 2>$null
		}
		else {
			Write-Host "kind cluster '$KindClusterName' exists but control-plane container is STOPPED."
		}
	}
	else {
		Write-Host "kind cluster '$KindClusterName' is NOT running."
		return
	}

	# Show pod statuses for known Fortify components in a table
	$services = @{
		LIM = 'lim-0';
		SSC = 'ssc-webapp-0';
		SCSAST = 'scancentral-sast-controller-0';
		SCDAST = 'scancentral-dast-core-api-0';
		SCDAST_SCANNER = 'scancentral-dast-scanner-0'
	}

	$fmt = "{0,-18}{1,-36}{2,-12}"
	Write-Host ""
	Write-Host ($fmt -f 'Service', 'Pod', 'Status')
	Write-Host ($fmt -f '-------', '---', '------')

	foreach ($k in $services.Keys) {
		$pod = $services[$k]
		if ($isRunning) {
			$status = $null
			try { $status = Get-PodStatus -PodName $pod -ErrorAction Stop } catch { $status = $null }
			if ([string]::IsNullOrEmpty($status)) { $status = 'Not found' }
		}
		else {
			$status = 'Cluster stopped'
		}
		Write-Host ($fmt -f $k, $pod, $status)
	}

	# Display external URLs
	Write-Host ""
	Write-Host "External URLs (use host ports if configured):"
	if ($LIMUrl) { Write-Host "  LIM:        https://$($LIMUrl):$($HostHttpsPort)" }
	if ($SSCUrl) { Write-Host "  SSC:        https://$($SSCUrl):$($HostHttpsPort)" }
	if ($SCSASTUrl) { Write-Host "  SCSAST:     https://$($SCSASTUrl):$($HostHttpsPort)/scancentral-ctrl" }
	if ($SCDASTAPIUrl) { Write-Host "  SCDAST API: https://$($SCDASTAPIUrl):$($HostHttpsPort)" }
}

function Do-Shutdown {
	Write-Host "Stopping kind cluster containers (will not delete the cluster)..."
	$containers = (& docker ps -aq --filter "name=$KindClusterName") 2>$null
	if ($containers) {
		foreach ($c in $containers) { & docker stop $c | Out-Null; Write-Host "Stopped container $c" }
	}
	else { Write-Host "No kind containers found for '$KindClusterName'." }
}

function Do-Cleanup {
	Write-Host "Cleaning up kind cluster and artifacts..."

	# Stop any running containers for the cluster
	$containers = (& docker ps -aq --filter "name=$KindClusterName") 2>$null
	if ($containers) {
		Write-Host "Stopping containers..."
		foreach ($c in $containers) { & docker stop $c | Out-Null; Write-Host "Stopped container $c" }
	}
	else {
		Write-Host "No running KIND containers found for '$KindClusterName'."
	}

	# Delete kind cluster if it exists
	$KindClustersNow = (kind get clusters) 2>$null
	if ($KindClustersNow -and ($KindClustersNow -contains $KindClusterName)) {
		Write-Host "Deleting cluster \"$KindClusterName\" ..."
		& kind delete cluster --name $KindClusterName
	}
	else {
		Write-Host "No kind cluster named '$KindClusterName' found."
	}

	# Remove certificates directory if present
	$CertDir = Join-Path $PSScriptRoot -ChildPath "certificates"
	if (Test-Path $CertDir) {
		Write-Host "Removing certificates directory: $CertDir"
		Remove-Item -LiteralPath $CertDir -Force -Recurse
	}
	else { Write-Host "Certificates directory not present. Skipping." }

	# Remove ssc-secret dir if present
	$SSCSecretDir = Join-Path $PSScriptRoot -ChildPath "ssc-secret"
	if (Test-Path $SSCSecretDir) {
		Write-Host "Removing SSC secret directory: $SSCSecretDir"
		Remove-Item -LiteralPath $SSCSecretDir -Force -Recurse
	}
	else { Write-Host "SSC secret directory not present. Skipping." }

	Write-Host "Cleanup complete."
}
function Do-Startup {
	if ($KindClusters -contains $KindClusterName)
    {
        Write-Host "kind cluster '$KindClusterName' is running ..."
    }
    else
    {
        Write-Host "kind cluster '$KindClusterName' not running ... creating ..."
        
            # Create kind cluster with ingress support
            # Use a preconfigured kind config file checked into the repository
            $KindConfigFile = Join-Path $PSScriptRoot -ChildPath "kind-config.yaml"
            if (-not (Test-Path $KindConfigFile)) {
                throw "kind-config.yaml not found in repository. Add a preconfigured kind-config.yaml to the repo root before running this script."
            }
        
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

		& "$OPENSSL" req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 3650 -out certificate.pem -subj $CertUrl
		& "$OPENSSL" x509 -inform PEM -in certificate.pem -outform DER -out certificate.cer
		& "$OPENSSL" pkcs12 -export -name ssc -in certificate.pem -inkey key.pem -out keystore.p12 -password pass:changeit
		& "$OPENSSL" pkcs12 -export -name lim -in certificate.pem -inkey key.pem -out certificate.pfx -password pass:changeit

		& kubectl create secret tls wildcard-certificate --cert=certificate.pem --key=key.pem

		& keytool -importkeystore -destkeystore ssc-service.jks -srckeystore keystore.p12 -srcstoretype pkcs12 -alias ssc -srcstorepass changeit -deststorepass changeit
		& keytool -import -trustcacerts -file certificate.pem -alias "wildcard-cert" -keystore truststore -storepass changeit -noprompt

		Set-Location $PSScriptRoot
	}

	# run update to prevent spurious errors
	helm repo update

	$PersistentVolumeDir = Join-Path $PSScriptRoot -ChildPath "persistent_volume"
	$ResourceOverrideDir = Join-Path $PSScriptRoot -ChildPath "resource_override"
	$ValuesDir = Join-Path $PSScriptRoot -ChildPath "values"

	#
	# License Infrastructure Manager (LIM)
	#

	if ($InstallLIM)
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
				--from-literal=token="$SIGNING_PASSWORD"
                
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

	if ($InstallSSC)
	{
		# check if SSC is already running
		$SSCStatus = Get-PodStatus -PodName ssc-webapp-0
		if ($SSCStatus -eq "Running")
		{
			Write-Host "SSC is already running ..."
		}
		else
		{
			# check if MySql is already running
			$MySqlStatus = Get-PodStatus -PodName mysql-0
			if ($MysqlStatus -eq "Running")
			{
				Write-Host "MySQL is already running ..."
			}
			else
			{
				Write-Host "Installing MySql ..."
				$MySqlValues = Join-Path $ValuesDir -ChildPath "mysql-values.yaml"
				& helm install mysql bitnami/mysql -f $MySqlValues --version $MYSQL_HELM_VERSION
				Start-Sleep -Seconds 30
				Write-Host
				$MySqlStatus = Wait-UntilPodStatus -PodName mysql-0
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

	if ($InstallSCSAST)
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

	if ($InstallSCDAST)
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
				--from-literal=service-token="$SIGNING_PASSWORD"

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
				--set appsettings.debrickedSettings.accessToken="$( $DEBRICKED_ACCESS_TOKEN )" `
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

	if ($InstallSCDASTScanner)
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
if ($Status) {
	Show-Status
	return
}

if ($Startup) {
	Do-Startup
	return
}

if ($Shutdown) {
	Do-Shutdown
	return
}

if ($Cleanup) {
	Do-Cleanup
	return
}

Write-Host "No action requested. Use -Startup, -Shutdown, or -Status (default)."
