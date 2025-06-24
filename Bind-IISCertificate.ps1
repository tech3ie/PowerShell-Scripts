#Requires -Version 5.1

<#
.SYNOPSIS
    Binds certificates to IIS websites and applications.

.DESCRIPTION
    This script binds certificates to IIS websites and applications using the certificate's thumbprint.
    It can bind certificates to specific IP addresses, ports, and host headers.

.PARAMETER WebsiteName
    The name of the IIS website to bind the certificate to.

.PARAMETER ApplicationName
    The name of the IIS application (optional, for application-level binding).

.PARAMETER CertificateThumbprint
    The thumbprint of the certificate to bind.

.PARAMETER CertificatePath
    Path to the certificate file (.pfx) to import and bind.

.PARAMETER CertificatePassword
    Password for the certificate file (if importing from .pfx).

.PARAMETER IPAddress
    IP address to bind to (default: All Unassigned).

.PARAMETER Port
    Port number to bind to (default: 443 for HTTPS).

.PARAMETER HostHeader
    Host header for the binding (optional).

.PARAMETER Protocol
    Protocol for the binding (default: https).

.PARAMETER ListWebsites
    Lists all IIS websites.

.PARAMETER ListCertificates
    Lists all certificates in LocalMachine/My store.

.PARAMETER RemoveBinding
    Removes the specified binding instead of adding it.

.PARAMETER Force
    Overwrites existing binding without prompting.

.EXAMPLE
    .\Bind-IISCertificate.ps1 -WebsiteName "Default Web Site" -CertificateThumbprint "1234567890ABCDEF1234567890ABCDEF12345678"

.EXAMPLE
    .\Bind-IISCertificate.ps1 -WebsiteName "MyApp" -CertificatePath "C:\Certificates\MyCert.pfx" -CertificatePassword "MyPassword"

.EXAMPLE
    .\Bind-IISCertificate.ps1 -WebsiteName "MySite" -CertificateThumbprint "1234567890ABCDEF1234567890ABCDEF12345678" -HostHeader "mysite.com"

.EXAMPLE
    .\Bind-IISCertificate.ps1 -ListWebsites

.EXAMPLE
    .\Bind-IISCertificate.ps1 -ListCertificates

.NOTES
    Author: Keval Varia
    Version: 1.0.0
    Date: 2025-06-24
#>

param(
    [Parameter(ParameterSetName = "BindByThumbprint")]
    [Parameter(ParameterSetName = "BindByPath")]
    [string]$WebsiteName,
    
    [Parameter(ParameterSetName = "BindByThumbprint")]
    [Parameter(ParameterSetName = "BindByPath")]
    [string]$ApplicationName,
    
    [Parameter(ParameterSetName = "BindByThumbprint")]
    [string]$CertificateThumbprint,
    
    [Parameter(ParameterSetName = "BindByPath")]
    [string]$CertificatePath,
    
    [Parameter(ParameterSetName = "BindByPath")]
    [string]$CertificatePassword,
    
    [string]$IPAddress = "*",
    
    [int]$Port = 443,
    
    [string]$HostHeader = "",
    
    [string]$Protocol = "https",
    
    [Parameter(ParameterSetName = "ListWebsites")]
    [switch]$ListWebsites,
    
    [Parameter(ParameterSetName = "ListCertificates")]
    [switch]$ListCertificates,
    
    [switch]$RemoveBinding,
    
    [switch]$Force
)

# Function to check if IIS is installed
function Test-IISInstalled {
    try {
        $iisFeature = Get-WindowsFeature -Name "Web-Server" -ErrorAction SilentlyContinue
        return $iisFeature.InstallState -eq "Installed"
    }
    catch {
        return $false
    }
}

# Function to check if WebAdministration module is available
function Test-WebAdministrationModule {
    return (Get-Module -ListAvailable -Name "WebAdministration") -ne $null
}

# Function to list IIS websites
function Get-IISWebsites {
    try {
        Import-Module WebAdministration -ErrorAction Stop
        $websites = Get-Website
        return $websites
    }
    catch {
        Write-Error "Failed to get IIS websites: $($_.Exception.Message)"
        return $null
    }
}

# Function to list certificates in LocalMachine/My store
function Get-CertificatesFromStore {
    try {
        $certStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "LocalMachine")
        $certStore.Open("ReadOnly")
        $certificates = $certStore.Certificates
        $certStore.Close()
        return $certificates
    }
    catch {
        Write-Error "Failed to access LocalMachine/My certificate store: $($_.Exception.Message)"
        return $null
    }
}

# Function to display website information
function Show-WebsiteInfo {
    param(
        [Microsoft.IIs.PowerShell.Framework.ConfigurationElement[]]$Websites
    )
    
    if ($null -eq $Websites -or $Websites.Count -eq 0) {
        Write-Host "No IIS websites found." -ForegroundColor Yellow
        return
    }
    
    Write-Host "`nFound $($Websites.Count) IIS website(s):" -ForegroundColor Cyan
    Write-Host "=" * 80
    
    foreach ($site in $Websites) {
        Write-Host "`nName: $($site.Name)" -ForegroundColor White
        Write-Host "   ID: $($site.Id)" -ForegroundColor Gray
        Write-Host "   State: $($site.State)" -ForegroundColor Gray
        Write-Host "   Physical Path: $($site.PhysicalPath)" -ForegroundColor Gray
        
        # Get bindings for this site
        $bindings = Get-WebBinding -Name $site.Name
        if ($bindings) {
            Write-Host "   Bindings:" -ForegroundColor Gray
            foreach ($binding in $bindings) {
                $bindingInfo = "$($binding.Protocol)://$($binding.BindingInformation)"
                Write-Host "     $bindingInfo" -ForegroundColor Gray
            }
        }
        Write-Host "-" * 40
    }
}

# Function to display certificate information
function Show-CertificateInfo {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certificates
    )
    
    if ($null -eq $Certificates -or $Certificates.Count -eq 0) {
        Write-Host "No certificates found in LocalMachine/My store." -ForegroundColor Yellow
        return
    }
    
    Write-Host "`nFound $($Certificates.Count) certificate(s) in LocalMachine/My store:" -ForegroundColor Cyan
    Write-Host "=" * 80
    
    for ($i = 0; $i -lt $Certificates.Count; $i++) {
        $cert = $Certificates[$i]
        Write-Host "`n$($i + 1). Subject: $($cert.Subject)" -ForegroundColor White
        Write-Host "   Issuer: $($cert.Issuer)" -ForegroundColor Gray
        Write-Host "   Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray
        Write-Host "   Valid From: $($cert.NotBefore)" -ForegroundColor Gray
        Write-Host "   Valid To: $($cert.NotAfter)" -ForegroundColor Gray
        Write-Host "   Has Private Key: $($cert.HasPrivateKey)" -ForegroundColor Gray
        Write-Host "-" * 40
    }
}

# Function to import certificate from file
function Import-CertificateFromFile {
    param(
        [string]$CertificatePath,
        [string]$Password
    )
    
    try {
        if (-not (Test-Path $CertificatePath)) {
            throw "Certificate file not found: $CertificatePath"
        }
        
        $certFile = Get-Item $CertificatePath
        if ($certFile.Extension -ne ".pfx" -and $certFile.Extension -ne ".p12") {
            throw "Certificate file must be in PFX/P12 format"
        }
        
        # Import certificate
        if ($Password) {
            $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
            $cert = Import-PfxCertificate -FilePath $CertificatePath -CertStoreLocation "Cert:\LocalMachine\My" -Password $securePassword
        } else {
            $cert = Import-PfxCertificate -FilePath $CertificatePath -CertStoreLocation "Cert:\LocalMachine\My"
        }
        
        Write-Host "Certificate imported successfully. Thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
        return $cert.Thumbprint
    }
    catch {
        Write-Error "Failed to import certificate: $($_.Exception.Message)"
        return $null
    }
}

# Function to bind certificate to IIS
function Set-IISCertificateBinding {
    param(
        [string]$WebsiteName,
        [string]$ApplicationName,
        [string]$CertificateThumbprint,
        [string]$IPAddress,
        [int]$Port,
        [string]$HostHeader,
        [string]$Protocol,
        [switch]$RemoveBinding,
        [switch]$Force
    )
    
    try {
        Import-Module WebAdministration -ErrorAction Stop
        
        # Verify website exists
        $website = Get-Website -Name $WebsiteName -ErrorAction SilentlyContinue
        if (-not $website) {
            throw "Website '$WebsiteName' not found"
        }
        
        # Verify certificate exists
        $cert = Get-ChildItem "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
        if (-not $cert) {
            throw "Certificate with thumbprint '$CertificateThumbprint' not found in LocalMachine/My store"
        }
        
        # Build binding information
        if ($HostHeader) {
            $bindingInfo = "$IPAddress`:$Port`:$HostHeader"
        } else {
            $bindingInfo = "$IPAddress`:$Port"
        }
        
        # Check if binding already exists
        $existingBinding = Get-WebBinding -Name $WebsiteName | Where-Object { 
            $_.BindingInformation -eq $bindingInfo -and $_.Protocol -eq $Protocol 
        }
        
        if ($RemoveBinding) {
            if ($existingBinding) {
                Remove-WebBinding -Name $WebsiteName -BindingInformation $bindingInfo -Protocol $Protocol
                Write-Host "Removed binding: $Protocol://$bindingInfo" -ForegroundColor Green
            } else {
                Write-Host "Binding not found: $Protocol://$bindingInfo" -ForegroundColor Yellow
            }
            return
        }
        
        if ($existingBinding -and -not $Force) {
            $response = Read-Host "Binding already exists. Overwrite? (Y/N)"
            if ($response -ne "Y" -and $response -ne "y") {
                Write-Host "Binding operation cancelled." -ForegroundColor Yellow
                return
            }
        }
        
        # Remove existing binding if it exists
        if ($existingBinding) {
            Remove-WebBinding -Name $WebsiteName -BindingInformation $bindingInfo -Protocol $Protocol
        }
        
        # Add new binding
        if ($ApplicationName) {
            # Application-level binding
            $appPath = "/$ApplicationName"
            New-WebBinding -Name $WebsiteName -Protocol $Protocol -Port $Port -IPAddress $IPAddress -HostHeader $HostHeader -SslFlags 1
            Set-WebBinding -Name $WebsiteName -Protocol $Protocol -BindingInformation $bindingInfo -PropertyName "certificateHash" -Value $CertificateThumbprint
        } else {
            # Site-level binding
            New-WebBinding -Name $WebsiteName -Protocol $Protocol -Port $Port -IPAddress $IPAddress -HostHeader $HostHeader -SslFlags 1
            Set-WebBinding -Name $WebsiteName -Protocol $Protocol -BindingInformation $bindingInfo -PropertyName "certificateHash" -Value $CertificateThumbprint
        }
        
        Write-Host "Certificate bound successfully to $Protocol://$bindingInfo" -ForegroundColor Green
        Write-Host "Website: $WebsiteName" -ForegroundColor Gray
        Write-Host "Certificate: $($cert.Subject)" -ForegroundColor Gray
        Write-Host "Thumbprint: $CertificateThumbprint" -ForegroundColor Gray
        
    }
    catch {
        Write-Error "Failed to bind certificate: $($_.Exception.Message)"
    }
}

# Main script logic
try {
    # Check if running on Windows
    if ($env:OS -ne "Windows_NT") {
        Write-Error "This script requires Windows operating system."
        exit 1
    }
    
    # Check if IIS is installed
    if (-not (Test-IISInstalled)) {
        Write-Error "IIS is not installed on this system."
        exit 1
    }
    
    # Check if WebAdministration module is available
    if (-not (Test-WebAdministrationModule)) {
        Write-Error "WebAdministration PowerShell module is not available. Please install IIS Management Tools."
        exit 1
    }
    
    # Handle different parameter sets
    if ($ListWebsites) {
        $websites = Get-IISWebsites
        Show-WebsiteInfo -Websites $websites
        return
    }
    
    if ($ListCertificates) {
        $certificates = Get-CertificatesFromStore
        Show-CertificateInfo -Certificates $certificates
        return
    }
    
    # Handle certificate binding
    if ($CertificatePath) {
        # Import certificate from file first
        $importedThumbprint = Import-CertificateFromFile -CertificatePath $CertificatePath -Password $CertificatePassword
        if (-not $importedThumbprint) {
            exit 1
        }
        $CertificateThumbprint = $importedThumbprint
    }
    
    if ($WebsiteName -and $CertificateThumbprint) {
        Set-IISCertificateBinding -WebsiteName $WebsiteName -ApplicationName $ApplicationName -CertificateThumbprint $CertificateThumbprint -IPAddress $IPAddress -Port $Port -HostHeader $HostHeader -Protocol $Protocol -RemoveBinding:$RemoveBinding -Force:$Force
    } else {
        # Default behavior: show help
        Write-Host "IIS Certificate Binding Script" -ForegroundColor Cyan
        Write-Host "=" * 40
        Write-Host "`nUsage examples:" -ForegroundColor White
        Write-Host "  .\Bind-IISCertificate.ps1 -ListWebsites"
        Write-Host "  .\Bind-IISCertificate.ps1 -ListCertificates"
        Write-Host "  .\Bind-IISCertificate.ps1 -WebsiteName 'Default Web Site' -CertificateThumbprint '1234567890ABCDEF1234567890ABCDEF12345678'"
        Write-Host "  .\Bind-IISCertificate.ps1 -WebsiteName 'MyApp' -CertificatePath 'C:\Certificates\MyCert.pfx' -CertificatePassword 'MyPassword'"
        Write-Host "  .\Bind-IISCertificate.ps1 -WebsiteName 'MySite' -CertificateThumbprint '1234567890ABCDEF1234567890ABCDEF12345678' -HostHeader 'mysite.com'"
        Write-Host "  .\Bind-IISCertificate.ps1 -WebsiteName 'MySite' -CertificateThumbprint '1234567890ABCDEF1234567890ABCDEF12345678' -RemoveBinding"
    }
}
catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
} 