#Requires -Version 5.1

<#
.SYNOPSIS
    Exports a certificate by common name and binds it to IIS in one operation.

.DESCRIPTION
    This script performs a complete certificate workflow:
    1. Searches for a certificate by common name in LocalMachine/My store
    2. Exports the certificate to a temporary folder
    3. Binds the certificate to an IIS website
    4. Provides detailed logging of the entire process

.PARAMETER CommonName
    The common name (CN) of the certificate to export and bind.

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

.PARAMETER IncludePrivateKey
    Exports the certificate with its private key (PFX format).

.PARAMETER CertificatePassword
    Password for PFX export when including private key.

.PARAMETER OutputPath
    Custom output path for exported certificate. If not specified, uses a temporary folder.

.PARAMETER Force
    Overwrites existing files and bindings without prompting.

.PARAMETER KeepExportedFile
    Keeps the exported certificate file instead of cleaning it up.

.PARAMETER ListWebsites
    Lists all IIS websites.

.PARAMETER ListCertificates
    Lists all certificates in LocalMachine/My store.

.PARAMETER RemoveBinding
    Removes the binding instead of adding it.

.EXAMPLE
    .\Export-And-Bind-Certificate.ps1 -CommonName "MyServer" -WebsiteName "Default Web Site"

.EXAMPLE
    .\Export-And-Bind-Certificate.ps1 -CommonName "web-server.company.com" -WebsiteName "MyApp" -HostHeader "mysite.com" -IncludePrivateKey -CertificatePassword "MyPassword"

.EXAMPLE
    .\Export-And-Bind-Certificate.ps1 -CommonName "MyServer" -WebsiteName "MySite" -RemoveBinding

.EXAMPLE
    .\Export-And-Bind-Certificate.ps1 -ListWebsites

.EXAMPLE
    .\Export-And-Bind-Certificate.ps1 -ListCertificates

.NOTES
    Author: Keval Varia
    Version: 1.0.0
    Date: 2025-06-24
#>

param(
    [Parameter(ParameterSetName = "ExportAndBind")]
    [Parameter(ParameterSetName = "RemoveBinding")]
    [string]$CommonName,
    
    [Parameter(ParameterSetName = "ExportAndBind")]
    [Parameter(ParameterSetName = "RemoveBinding")]
    [string]$WebsiteName,
    
    [Parameter(ParameterSetName = "ExportAndBind")]
    [Parameter(ParameterSetName = "RemoveBinding")]
    [string]$ApplicationName,
    
    [string]$IPAddress = "*",
    
    [int]$Port = 443,
    
    [string]$HostHeader = "",
    
    [string]$Protocol = "https",
    
    [switch]$IncludePrivateKey,
    
    [string]$CertificatePassword,
    
    [string]$OutputPath,
    
    [switch]$Force,
    
    [switch]$KeepExportedFile,
    
    [Parameter(ParameterSetName = "ListWebsites")]
    [switch]$ListWebsites,
    
    [Parameter(ParameterSetName = "ListCertificates")]
    [switch]$ListCertificates,
    
    [Parameter(ParameterSetName = "RemoveBinding")]
    [switch]$RemoveBinding
)

# Global variables for cleanup
$script:ExportedFilePath = $null
$script:TempFolder = $null

# Function to create temporary folder
function New-TempFolder {
    param(
        [string]$BaseName = "ExportedCertificates"
    )
    
    $tempPath = Join-Path $env:TEMP $BaseName
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $folderPath = Join-Path $tempPath $timestamp
    
    if (-not (Test-Path $tempPath)) {
        New-Item -ItemType Directory -Path $tempPath -Force | Out-Null
        Write-Host "Created base temporary folder: $tempPath" -ForegroundColor Green
    }
    
    if (-not (Test-Path $folderPath)) {
        New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
        Write-Host "Created export folder: $folderPath" -ForegroundColor Green
    }
    
    return $folderPath
}

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
        Write-Host "   Issuer: $($cert.Issuer)" -ForegroundColor Gray
        Write-Host "   Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray
        Write-Host "   Valid From: $($cert.NotBefore)" -ForegroundColor Gray
        Write-Host "   Valid To: $($cert.NotAfter)" -ForegroundColor Gray
        Write-Host "   Has Private Key: $($cert.HasPrivateKey)" -ForegroundColor Gray
        Write-Host "-" * 40
    }
}

# Function to export certificate to file
function Export-CertificateToFile {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$OutputFolder,
        [switch]$IncludePrivateKey,
        [string]$Password,
        [switch]$Force
    )
    
    try {
        # Determine file extension and export format
        if ($IncludePrivateKey) {
            $extension = ".pfx"
            $exportFormat = [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx
        } else {
            $extension = ".cer"
            $exportFormat = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
        }
        
        # Create filename from common name
        $commonName = $Certificate.Subject -replace ".*CN=", "" -replace ",.*", ""
        $commonName = $commonName -replace "[^a-zA-Z0-9_-]", ""
        $filename = "$commonName$extension"
        $filePath = Join-Path $OutputFolder $filename
        
        # Check if file exists
        if ((Test-Path $filePath) -and -not $Force) {
            $response = Read-Host "File '$filePath' already exists. Overwrite? (Y/N)"
            if ($response -ne "Y" -and $response -ne "y") {
                Write-Host "Skipping export of certificate: $($Certificate.Subject)" -ForegroundColor Yellow
                return $null
            }
        }
        
        # Export the certificate
        if ($IncludePrivateKey) {
            if ($Password) {
                $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
                $certBytes = $Certificate.Export($exportFormat, $securePassword)
            } else {
                $certBytes = $Certificate.Export($exportFormat)
            }
        } else {
            $certBytes = $Certificate.Export($exportFormat)
        }
        
        # Write to file
        [System.IO.File]::WriteAllBytes($filePath, $certBytes)
        
        Write-Host "Certificate exported successfully to: $filePath" -ForegroundColor Green
        return $filePath
    }
    catch {
        Write-Error "Failed to export certificate '$($Certificate.Subject)': $($_.Exception.Message)"
        return $null
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

# Function to cleanup temporary files
function Remove-TempFiles {
    if ($script:ExportedFilePath -and (Test-Path $script:ExportedFilePath) -and -not $KeepExportedFile) {
        try {
            Remove-Item $script:ExportedFilePath -Force
            Write-Host "Cleaned up temporary certificate file: $script:ExportedFilePath" -ForegroundColor Gray
        }
        catch {
            Write-Warning "Failed to clean up temporary file: $script:ExportedFilePath"
        }
    }
    
    if ($script:TempFolder -and (Test-Path $script:TempFolder) -and -not $KeepExportedFile) {
        try {
            # Only remove if folder is empty
            $items = Get-ChildItem $script:TempFolder -Force
            if ($items.Count -eq 0) {
                Remove-Item $script:TempFolder -Force
                Write-Host "Cleaned up temporary folder: $script:TempFolder" -ForegroundColor Gray
            }
        }
        catch {
            Write-Warning "Failed to clean up temporary folder: $script:TempFolder"
        }
    }
}

# Main script logic
try {
    Write-Host "Certificate Export and IIS Binding Script" -ForegroundColor Cyan
    Write-Host "=" * 50
    
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
    
    # Handle export and bind operations
    if ($CommonName -and $WebsiteName) {
        Write-Host "`nStep 1: Searching for certificate with common name '$CommonName'..." -ForegroundColor Yellow
        
        # Find certificate by common name
        $certificate = Find-CertificateByCommonName -CommonName $CommonName
        if (-not $certificate) {
            exit 1
        }
        
        Write-Host "Found certificate: $($certificate.Subject)" -ForegroundColor Green
        Write-Host "Thumbprint: $($certificate.Thumbprint)" -ForegroundColor Gray
        
        # Determine output path
        if ($OutputPath) {
            if (-not (Test-Path $OutputPath)) {
                New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
                Write-Host "Created output directory: $OutputPath" -ForegroundColor Green
            }
            $exportFolder = $OutputPath
        } else {
            $exportFolder = New-TempFolder
            $script:TempFolder = $exportFolder
        }
        
        Write-Host "`nStep 2: Exporting certificate to temporary folder..." -ForegroundColor Yellow
        
        # Export certificate
        $exportedFile = Export-CertificateToFile -Certificate $certificate -OutputFolder $exportFolder -IncludePrivateKey:$IncludePrivateKey -Password $CertificatePassword -Force:$Force
        if (-not $exportedFile) {
            exit 1
        }
        
        $script:ExportedFilePath = $exportedFile
        
        if ($RemoveBinding) {
            Write-Host "`nStep 3: Removing certificate binding from IIS..." -ForegroundColor Yellow
            Set-IISCertificateBinding -WebsiteName $WebsiteName -ApplicationName $ApplicationName -CertificateThumbprint $certificate.Thumbprint -IPAddress $IPAddress -Port $Port -HostHeader $HostHeader -Protocol $Protocol -RemoveBinding
        } else {
            Write-Host "`nStep 3: Binding certificate to IIS..." -ForegroundColor Yellow
            Set-IISCertificateBinding -WebsiteName $WebsiteName -ApplicationName $ApplicationName -CertificateThumbprint $certificate.Thumbprint -IPAddress $IPAddress -Port $Port -HostHeader $HostHeader -Protocol $Protocol -Force:$Force
        }
        
        Write-Host "`nOperation completed successfully!" -ForegroundColor Green
        
        if ($KeepExportedFile) {
            Write-Host "Certificate file kept at: $exportedFile" -ForegroundColor Cyan
        }
    } else {
        # Default behavior: show help
        Write-Host "`nUsage examples:" -ForegroundColor White
        Write-Host "  .\Export-And-Bind-Certificate.ps1 -CommonName 'MyServer' -WebsiteName 'Default Web Site'"
        Write-Host "  .\Export-And-Bind-Certificate.ps1 -CommonName 'web-server.company.com' -WebsiteName 'MyApp' -HostHeader 'mysite.com' -IncludePrivateKey -CertificatePassword 'MyPassword'"
        Write-Host "  .\Export-And-Bind-Certificate.ps1 -CommonName 'MyServer' -WebsiteName 'MySite' -RemoveBinding"
        Write-Host "  .\Export-And-Bind-Certificate.ps1 -ListWebsites"
        Write-Host "  .\Export-And-Bind-Certificate.ps1 -ListCertificates"
    }
}
catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}
finally {
    # Cleanup temporary files
    Remove-TempFiles
} 