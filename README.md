# Fortify Kubernetes IN Docker (kind) demo

This repository contains some example scripts to setup a working Fortify demo environment using [kind](https://kind.sigs.k8s.io/) and the [Fortify Helm Charts](https://github.com/fortify/helm3-charts). 

kind (Kubernetes IN Docker) is a tool for running local Kubernetes clusters using Docker container "nodes". 
It is useful for developing and testing applications that are designed to run on Kubernetes.

It includes a deployment of:

    [X] Fortify License Infrastructure Manger (LIM)
    [X] Fortify Software Security Center (SSC)
    [X] ScanCentral SAST and Linux Scanner/Sensor
    [X] ScanCentral DAST and Linux Scanner/Sensor

## Documentation

 - https://www.microfocus.com/documentation/fortify-software-security-center/2540/Deploying_SSC_in_Kubernetes_25.4.0.html
 - https://www.microfocus.com/documentation/fortify-ScanCentral-DAST/2540/Deploying_ScanCentral_DAST_in_Kubernetes_25.4.0.html
 - https://www.microfocus.com/documentation/fortify-software-security-center/2540/Deploying_SC_SAST_in_Kubernetes_25.4.0.html

## Prerequisites

### Linux environment with Docker installed
### PowerShell on Linux

Install [PowerShell for Linux](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-linux?view=powershell-7.4).
The scripts are written in PowerShell so that they could be used on both Windows and Linux.

### Kubernetes command line
Install **kubectl** by following: https://kubernetes.io/docs/tasks/tools/

### Helm

Install **helm** by following: https://helm.sh/docs/intro/install/

### kind

Install **kind** by following : https://kind.sigs.k8s.io/docs/user/quick-start/#installation

### OpenSSL

You will need OpenSSL (https://www.openssl.org/) to create a self-signed wildcard certificate. You can install OpenSSL 
using your OS package manager or use the version that is already available with the Git command line tool. If using Linux there is a good chance that OpenSSL is already installed.


### fortify.license file

A working **fortify.license** file will be needed for SSC and ScanCentral SAST.
Place this file in the "root" directory of this project.

### Dockerhub ***fortifydocker*** credentials

You will need Docker Hub credentials to access the Helm charts and private docker images in the [fortifydocker](https://hub.docker.com/u/fortifydocker) organisation.
Enter the username and password into the `.env` file (see below).
### ScanCentral DAST and WebInspect licenses

A working license for ScanCentral DAST and WebInspect will be needed if deploying ScanCentral DAST.

### Fortify Command Line utility

The `fcli` tool can be used to populate data and connect to the Fortify kind Environment.

## Environment preparation

you wish to install. For example to install everything except ScanCentral DAST:

```
# Set the following depending on what components you wish to install
# Just leave blank/empty if you don't want to install the component
INSTALL_LIM=1
INSTALL_SSC=1
INSTALL_SCDAST=
INSTALL_SCDAST_SCANNER=
```
It is recommended to set the components incrementally so you can see what's going on and make sure things are working. For example: set just `INSTALL_LIM=1` first to install LIM and configure licenses then add `INSTALL_SSC=1` and so on.

Note: a ScanCentral DAST activation token needs to be installed in the LIM for the SecureBase database to be installed successfully.

To save time, the startup scripts create and use the same certificates across all of the components.
A single signing password is required and should be configured in the `fortify.config` file:

```
SIGNING_PASSWORD=_YOUR_SIGNING_PASSWOD_
```

To generate your own signing password you can use the command `openssl rand -base64 32`.

`fortify.config` is intended to be checked into the repository and used as the canonical configuration for these scripts.

## Install Fortify environment

Run the following command to start kind and create the Fortify Environment:

```
pwsh 
./demo.ps1 -Start
```

It will take a while for everything to complete. If you want to see the progress and ensure everything
is starting correctly you can monitor the cluster using:

```
kubectl get pods --watch
```

Once the services have started they will be accessible on your local machine through the kind cluster's
ingress controller. By default this repository maps kind host ports to non-privileged host ports to avoid
Windows `http.sys` conflicts: host `8080` -> container `80`, and host `8443` -> container `443`.

Access examples (adjust for your `.env` hostnames):

- HTTP (container port 80) via host port 8080: http://127.0.0.1:8080
- HTTPS (container port 443) via host port 8443: https://127.0.0.1:8443
- Using nip.io hostnames (example): https://ssc.127-0-0-1.nip.io:8443

If you prefer to bind directly to host ports 80/443 you can modify the `kind` config (requires freeing
those ports on Windows and running PowerShell as Administrator), or map different host ports in the
`kind-config.yaml` generated by `startup.ps1`.

Using Microsoft SQL Server for SSC
---------------------------------
This demo can deploy Microsoft SQL Server instead of MySQL for SSC. To use it:

 - Place a values file at `values/mssql-values.yaml` (an example is included).
 - Add the local chart under `charts/mssql-official` (this repo includes a minimal sample).
 - When present, the startup scripts will prefer the local `mssql-official` chart and install it as the
     `mssql` release. 


## Installing Licenses in LIM

Browse to [https://lim.127-0-0-1.nip.io:8443](https://lim.127-0-0-1.nip.io:8443) on your local machine and login using the 
values of `LIM_ADMIN_USER` and `LIM_ADMIN_PASSWORD` set in `.env`.

## Login to SSC

Browse to https://ssc.127-0-0-1.nip.io:8443 on your local machine and login using the values of `SSC_ADMIN_USER` and
`SSC_ADMIN_PASSWORD` set in `.env`.

Note: if you want to keep the SSC "admin" user's default password of `admin` you can run the appropriate commands against the database pod before logging in (example for MSSQL):

```
kubectl exec --stdin --tty mssql-0 -- /bin/bash
# /opt/mssql-tools18/bin/sqlcmd -S localhost -U SA -P "ChangeMe123!" -C -d ssc_db -Q "UPDATE fortifyuser SET requirePasswordChange='N' WHERE Id=1"
# exit
exit
```

## ScanCentral SAST and DAST Configuration in SSC

For ScanCentral SAST, you should use the "internal" URL for the ScanCentral SAST controller, e.g.
`http://scancentral-sast-controller:80/scancentral-ctrl` and the `SHARED_SECRET` value populated
in the `.env` file. You will need to restart SSC for this configuration to take affect using:

```
kubectl delete pod ssc-webapp-0
```

For ScanCentral DAST, you should use the "external" URL for the ScanCentral DAST API, e.g.
`https://scdastapi.127-0-0-1.nip.io:8443`. You will need to refresh your browser for the ScanCentral
DAST view to appear.

## Populate environment

There is a script `populate.ps1` that can be used to create some initial Applications, Versions and Issues.
It uses the `fcli` tool to connect to the Fortify Environment. If you wish to use the `fcli` tool yourself
you can use the "truststore" that has previously been created, for example:

```
fcli config truststore set -f certificates/ssc-service.jks -p changeit -t jks
fcli ssc session login --url https://ssc.127-0-0-1.nip.io -k -u admin -p admin
...
..._your fcli commands_...
...
fcli ssc session logout
```

## Update environment

You can re-run the `demo.ps1` script with different options set in the `fortify.config` file to deploy additional Fortify components.

## Example commands

Here are some additional kubernetes commands to help you:

|                               |      |
|-------------------------------|------|
|Exec into SSC pod              |`kubectl exec --stdin --tty ssc-webapp-0 -- /bin/bash`|
|Restart SSC pod                |`kubectl delete pod ssc-webapp-0`|
|Exec into ScanCentral SAST pod |`kubectl exec --stdin --tty scancentral-sast-controller-0 -- /bin/bash`|
|Restart ScanCentral SAST pod   |`kubectl delete pod scancentral-sast-controller-0`|
|Exec into ScanCentral SAST sensor  | `kubectl exec --stdin --tty scancentral-sast-worker-linux-0 -- /bin/bash`|
|Exec into ScanCentral DAST sensor  | `kubectl exec --stdin --tty scancentral-dast-scanner-0 -- /bin/bash` |
|View all pods                  | `kubectl get pods` |
|View all services              | `kubectl get services` |

## Stopping/Starting kind

You can stop the kind cluster using:

```
./demo.ps1 -Stop
```

Note: this will keep the kubernetes cluster so that even after reboot of your machine you can restart the cluster with:

```
./demo.ps1 -Start
```

You may need to restart the SSC pod once more after restarting the cluster.

## Remove Fortify environment

If you wish to remove the kind environment completely, you can use the following command:

```
./demo.ps1 -Delete
```

## Recent Changes (important)

- **`demo.ps1`**:
    - Fixed a regex/parser issue that could cause `-Cleanup` to fail (CERT parsing).
    - Added certificate auto-detect/sync functions (`Get-CertSha256FromPemFile`, `Get-CertSha256FromSecret`, `Sync-WildcardCertificateAndSscSecretIfNeeded`).
    - Added `-RecreateCertificates` flow to regenerate keystores/truststore and recreate the `ssc` secret.
    - Added an optional `-AutoSyncCerts` toggle to run certificate/secret drift detection on startup.
    - To force a certificate/secret refresh and restart SSC, run:

        ```powershell
        .\demo.ps1 -RecreateCertificates -Start -Services SSC
        ```

- **Certificates / Trust**:
    - This demo uses `mkcert` to create a locally trusted CA and wildcard certs. If you see trust issues in browsers or OpenSSL, run `mkcert -install` on the host and ensure Java truststore is updated (the `demo.ps1` helper will attempt to create the keystore/truststore for SSC).
    - To verify the webapp over HTTPS (use the Host header):

        ```powershell
        curl -k -I -H "Host: ssc.127-0-0-1.nip.io" https://localhost:8443/
        ```

- **`charts/mssql-official`**:
    - When using MSSQL for SSC, the local chart installs with service name `mssql` so SSC autoconfig can reach the database.
    - A Helm post-install Job was added to create the expected `ssc_db` database automatically (see `values/mssql-values.yaml` and `charts/mssql-official/templates/db-init-job.yaml`).

- **Apply changes**:
    - If you've previously created the cluster/releases, run a full cleanup and startup so chart/template changes are applied cleanly:

        ```powershell
        .\demo.ps1 -Cleanup
        .\demo.ps1 -Start
        ```

If you'd like these notes expanded into a migration/upgrade checklist or moved to a dedicated `CHANGES.md`, tell me and I'll add it.
