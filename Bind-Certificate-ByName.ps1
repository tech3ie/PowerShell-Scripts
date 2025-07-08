#Requires -Version 5.1

<#
.SYNOPSIS
    Binds certificates to IIS websites using CommonName or FriendlyName lookup.

.DESCRIPTION
    This script finds certificates by CommonName or FriendlyName in the LocalMachine/My store
    and binds them directly to IIS websites without exporting. It's a simplified version
    that focuses on direct binding for efficiency.

.PARAMETER CommonName
    The common name (CN) of the certificate to find and bind.

.PARAMETER FriendlyName
    The friendly name of the certificate to find and bind.

.PARAMETER WebsiteName
    The name of the IIS website to bind the certificate to.

.PARAMETER ApplicationName
    The name of the IIS application (optional, for application-level binding).

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
    .\Bind-Certificate-ByName.ps1 -CommonName "MyServer" -WebsiteName "Default Web Site"

.EXAMPLE
    .\Bind-Certificate-ByName.ps1 -FriendlyName "My Web Server Cert" -WebsiteName "MyApp" -HostHeader "mysite.com"

.EXAMPLE
    .\Bind-Certificate-ByName.ps1 -CommonName "MyServer" -WebsiteName "MySite" -RemoveBinding

.EXAMPLE
    .\Bind-Certificate-ByName.ps1 -ListWebsites

.EXAMPLE
    .\Bind-Certificate-ByName.ps1 -ListCertificates

.NOTES
    Author: Keval Varia
    Version: 1.0.0
    Date: 2025-06-27
#>

param(
    [Parameter(ParameterSetName = "BindByCommonName", Mandatory = $true)]
    [Parameter(ParameterSetName = "RemoveBinding")]
    [string]$CommonName,
    
    [Parameter(ParameterSetName = "BindByFriendlyName", Mandatory = $true)]
    [Parameter(ParameterSetName = "RemoveBinding")]
    [string]$FriendlyName,
    
    [Parameter(ParameterSetName = "BindByCommonName", Mandatory = $true)]
    [Parameter(ParameterSetName = "BindByFriendlyName", Mandatory = $true)]
    [Parameter(ParameterSetName = "RemoveBinding", Mandatory = $true)]
    [string]$WebsiteName,
    
    [Parameter(ParameterSetName = "BindByCommonName")]
    [Parameter(ParameterSetName = "BindByFriendlyName")]
    [Parameter(ParameterSetName = "RemoveBinding")]
    [string]$ApplicationName,
    
    [Parameter(ParameterSetName = "BindByCommonName")]
    [Parameter(ParameterSetName = "BindByFriendlyName")]
    [Parameter(ParameterSetName = "RemoveBinding")]
    [string]$IPAddress = "*",
    
    [Parameter(ParameterSetName = "BindByCommonName")]
    [Parameter(ParameterSetName = "BindByFriendlyName")]
    [Parameter(ParameterSetName = "RemoveBinding")]
    [int]$Port = 443,
    
    [Parameter(ParameterSetName = "BindByCommonName")]
    [Parameter(ParameterSetName = "BindByFriendlyName")]
    [Parameter(ParameterSetName = "RemoveBinding")]
    [string]$HostHeader = "",
    
    [Parameter(ParameterSetName = "BindByCommonName")]
    [Parameter(ParameterSetName = "BindByFriendlyName")]
    [Parameter(ParameterSetName = "RemoveBinding")]
    [string]$Protocol = "https",
    
    [Parameter(ParameterSetName = "ListWebsites")]
    [switch]$ListWebsites,
    
    [Parameter(ParameterSetName = "ListCertificates")]
    [switch]$ListCertificates,
    
    [Parameter(ParameterSetName = "RemoveBinding", Mandatory = $true)]
    [switch]$RemoveBinding,
    
    [Parameter(ParameterSetName = "BindByCommonName")]
    [Parameter(ParameterSetName = "BindByFriendlyName")]
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

# Function to get certificates from LocalMachine/My store
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

# Function to find certificate by common name
function Find-CertificateByCommonName {
    param(
        [string]$CommonName
    )
    
    try {
        $certificates = Get-CertificatesFromStore
        if ($null -eq $certificates) {
            return $null
        }
        
        # Search for certificates with matching common name
        $matchingCerts = @()
        foreach ($cert in $certificates) {
            if ($cert.Subject -like "*CN=$CommonName*" -or $cert.Subject -like "*CN=*$CommonName*") {
                $matchingCerts += $cert
            }
        }
        
        if ($matchingCerts.Count -eq 0) {
            Write-Host "No certificates found with common name: $CommonName" -ForegroundColor Red
            Write-Host "Available certificates:" -ForegroundColor Yellow
            Show-CertificateInfo -Certificates $certificates
            return $null
        }
        
        if ($matchingCerts.Count -eq 1) {
            return $matchingCerts[0]
        }
        
        # Multiple matches found
        Write-Host "Multiple certificates found with common name '$CommonName':" -ForegroundColor Yellow
        Show-CertificateInfo -Certificates $matchingCerts
        Write-Host "Please use a more specific common name or use the thumbprint directly." -ForegroundColor Yellow
        return $null
    }
    catch {
        Write-Error "Error searching for certificate: $($_.Exception.Message)"
        return $null
    }
}

# Function to find certificate by friendly name
function Find-CertificateByFriendlyName {
    param(
        [string]$FriendlyName
    )
    
    try {
        $certificates = Get-CertificatesFromStore
        if ($null -eq $certificates) {
            return $null
        }
        
        # Search for certificates with matching friendly name
        $matchingCerts = @()
        foreach ($cert in $certificates) {
            if ($cert.FriendlyName -like "*$FriendlyName*") {
                $matchingCerts += $cert
            }
        }
        
        if ($matchingCerts.Count -eq 0) {
            Write-Host "No certificates found with friendly name: $FriendlyName" -ForegroundColor Red
            Write-Host "Available certificates:" -ForegroundColor Yellow
            Show-CertificateInfo -Certificates $certificates
            return $null
        }
        
        if ($matchingCerts.Count -eq 1) {
            return $matchingCerts[0]
        }
        
        # Multiple matches found
        Write-Host "Multiple certificates found with friendly name '$FriendlyName':" -ForegroundColor Yellow
        Show-CertificateInfo -Certificates $matchingCerts
        Write-Host "Please use a more specific friendly name or use the thumbprint directly." -ForegroundColor Yellow
        return $null
    }
    catch {
        Write-Error "Error searching for certificate: $($_.Exception.Message)"
        return $null
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
    
    Write-Host "`nFound $($Certificates.Count) certificate(s):" -ForegroundColor Cyan
    Write-Host "=" * 80
    
    for ($i = 0; $i -lt $Certificates.Count; $i++) {
        $cert = $Certificates[$i]
        Write-Host "`n$($i + 1). Subject: $($cert.Subject)" -ForegroundColor White
        Write-Host "   Friendly Name: $($cert.FriendlyName)" -ForegroundColor Gray
        Write-Host "   Issuer: $($cert.Issuer)" -ForegroundColor Gray
        Write-Host "   Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray
        Write-Host "   Valid From: $($cert.NotBefore)" -ForegroundColor Gray
        Write-Host "   Valid To: $($cert.NotAfter)" -ForegroundColor Gray
        Write-Host "   Has Private Key: $($cert.HasPrivateKey)" -ForegroundColor Gray
        Write-Host "-" * 40
    }
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
                Write-Host ("Removed binding: {0}://{1}" -f $Protocol, $bindingInfo) -ForegroundColor Green
            } else {
                Write-Host ("Binding not found: {0}://{1}" -f $Protocol, $bindingInfo) -ForegroundColor Yellow
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
            New-WebBinding -Name $WebsiteName -Protocol $Protocol -Port $Port -IPAddress $IPAddress -HostHeader $HostHeader -SslFlags 1
            Set-WebBinding -Name $WebsiteName -Protocol $Protocol -BindingInformation $bindingInfo -PropertyName "certificateHash" -Value $CertificateThumbprint
        } else {
            # Site-level binding
            New-WebBinding -Name $WebsiteName -Protocol $Protocol -Port $Port -IPAddress $IPAddress -HostHeader $HostHeader -SslFlags 1
            Set-WebBinding -Name $WebsiteName -Protocol $Protocol -BindingInformation $bindingInfo -PropertyName "certificateHash" -Value $CertificateThumbprint
        }
        
        Write-Host ("Certificate bound successfully to {0}://{1}" -f $Protocol, $bindingInfo) -ForegroundColor Green
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
    Write-Host "Direct Certificate Binding Script" -ForegroundColor Cyan
    Write-Host "=" * 40
    
    # Check if running on Windows
    if ($env:OS -ne "Windows_NT") {
        Write-Error "This script requires Windows operating system."
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
    
    # Check IIS requirements for binding operations
    if ($WebsiteName -or $RemoveBinding) {
        if (-not (Test-IISInstalled)) {
            Write-Error "IIS is not installed on this system."
            exit 1
        }
        
        if (-not (Test-WebAdministrationModule)) {
            Write-Error "WebAdministration PowerShell module is not available. Please install IIS Management Tools."
            exit 1
        }
    }
    
    # Handle binding operations
    if (($CommonName -or $FriendlyName) -and $WebsiteName) {
        $certificate = $null
        
        if ($CommonName) {
            Write-Host "`nStep 1: Searching for certificate with common name '$CommonName'..." -ForegroundColor Yellow
            $certificate = Find-CertificateByCommonName -CommonName $CommonName
        } elseif ($FriendlyName) {
            Write-Host "`nStep 1: Searching for certificate with friendly name '$FriendlyName'..." -ForegroundColor Yellow
            $certificate = Find-CertificateByFriendlyName -FriendlyName $FriendlyName
        }
        
        if (-not $certificate) {
            exit 1
        }
        
        Write-Host "Found certificate: $($certificate.Subject)" -ForegroundColor Green
        Write-Host "Friendly Name: $($certificate.FriendlyName)" -ForegroundColor Gray
        Write-Host "Thumbprint: $($certificate.Thumbprint)" -ForegroundColor Gray
        
        Write-Host "`nStep 2: Binding certificate to IIS..." -ForegroundColor Yellow
        
        if ($RemoveBinding) {
            Set-IISCertificateBinding -WebsiteName $WebsiteName -ApplicationName $ApplicationName -CertificateThumbprint $certificate.Thumbprint -IPAddress $IPAddress -Port $Port -HostHeader $HostHeader -Protocol $Protocol -RemoveBinding
        } else {
            Set-IISCertificateBinding -WebsiteName $WebsiteName -ApplicationName $ApplicationName -CertificateThumbprint $certificate.Thumbprint -IPAddress $IPAddress -Port $Port -HostHeader $HostHeader -Protocol $Protocol -Force:$Force
        }
        
        Write-Host "`nOperation completed successfully!" -ForegroundColor Green
    } else {
        # Default behavior: show help
        Write-Host "`nUsage examples:" -ForegroundColor White
        Write-Host "  .\Bind-Certificate-ByName.ps1 -CommonName 'MyServer' -WebsiteName 'Default Web Site'"
        Write-Host "  .\Bind-Certificate-ByName.ps1 -FriendlyName 'My Web Server Cert' -WebsiteName 'MyApp' -HostHeader 'mysite.com'"
        Write-Host "  .\Bind-Certificate-ByName.ps1 -CommonName 'MyServer' -WebsiteName 'MySite' -RemoveBinding"
        Write-Host "  .\Bind-Certificate-ByName.ps1 -ListWebsites"
        Write-Host "  .\Bind-Certificate-ByName.ps1 -ListCertificates"
    }
}
catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
} 