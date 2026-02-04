Write-Host "Fortify KIND shutdown script"

# Import some supporting functions
Import-Module $PSScriptRoot\modules\FortifyFunctions.psm1 -Scope Global -Force
Set-PSPlatform

$KindClusterName = "fortify-demo"

& kind delete cluster --name $KindClusterName

$CertDir = "$($PSScriptRoot)\certificates"
If ((Test-Path -PathType container $CertDir))
{
    Remove-Item -LiteralPath $CertDir -Force -Recurse
}

$SSCSecretDir = "$($PSScriptRoot)\ssc-secret"
If ((Test-Path -PathType container $SSCSecretDir))
{
    Remove-Item -LiteralPath $SSCSecretDir -Force -Recurse
}
