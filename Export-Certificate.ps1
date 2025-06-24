#Requires -Version 5.1

<#
.SYNOPSIS
    Exports certificates from LocalMachine/My certificate store to a temporary folder.

.DESCRIPTION
    This script exports certificates from the LocalMachine/My certificate store to a temporary folder.
    It can export certificates by thumbprint, subject, or list all available certificates.
    The script creates the temporary folder if it doesn't exist.

.PARAMETER Thumbprint
    The thumbprint of the certificate to export.

.PARAMETER Subject
    The subject name of the certificate to export (partial match supported).

.PARAMETER List
    Lists all certificates in the LocalMachine/My store.

.PARAMETER ExportAll
    Exports all certificates from the store.

.PARAMETER IncludePrivateKey
    Exports the certificate with its private key (PFX format).

.PARAMETER Password
    Password for PFX export when including private key.

.PARAMETER OutputPath
    Custom output path. If not specified, uses a temporary folder.

.PARAMETER Force
    Overwrites existing files without prompting.

.EXAMPLE
    .\Export-Certificate.ps1 -List
    Lists all certificates in the LocalMachine/My store.

.EXAMPLE
    .\Export-Certificate.ps1 -Thumbprint "1234567890ABCDEF1234567890ABCDEF12345678"
    Exports a specific certificate by thumbprint.

.EXAMPLE
    .\Export-Certificate.ps1 -Subject "My Company" -IncludePrivateKey -Password "MyPassword"
    Exports a certificate matching the subject with private key.

.EXAMPLE
    .\Export-Certificate.ps1 -ExportAll
    Exports all certificates from the store.

.NOTES
    Author: PowerShell Scripts
    Version: 1.0
    Date: $(Get-Date -Format "yyyy-MM-dd")
#>

param(
    [Parameter(ParameterSetName = "ByThumbprint")]
    [string]$Thumbprint,
    
    [Parameter(ParameterSetName = "BySubject")]
    [string]$Subject,
    
    [Parameter(ParameterSetName = "List")]
    [switch]$List,
    
    [Parameter(ParameterSetName = "ExportAll")]
    [switch]$ExportAll,
    
    [switch]$IncludePrivateKey,
    
    [string]$Password,
    
    [string]$OutputPath,
    
    [switch]$Force
)

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

# Function to export a single certificate
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
        
        # Create filename from subject
        $subjectName = $Certificate.Subject -replace "CN=", "" -replace ",", "_" -replace " ", "_"
        $subjectName = $subjectName -replace "[^a-zA-Z0-9_-]", ""
        $filename = "$subjectName$extension"
        $filePath = Join-Path $OutputFolder $filename
        
        # Check if file exists
        if ((Test-Path $filePath) -and -not $Force) {
            $response = Read-Host "File '$filePath' already exists. Overwrite? (Y/N)"
            if ($response -ne "Y" -and $response -ne "y") {
                Write-Host "Skipping export of certificate: $($Certificate.Subject)" -ForegroundColor Yellow
                return $false
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
        
        Write-Host "Exported certificate to: $filePath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to export certificate '$($Certificate.Subject)': $($_.Exception.Message)"
        return $false
    }
}

# Main script logic
try {
    # Get certificates from store
    $certificates = Get-CertificatesFromStore
    
    if ($null -eq $certificates) {
        exit 1
    }
    
    # Determine output path
    if ($OutputPath) {
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
            Write-Host "Created output directory: $OutputPath" -ForegroundColor Green
        }
        $exportFolder = $OutputPath
    } else {
        $exportFolder = New-TempFolder
    }
    
    # Handle different parameter sets
    if ($List) {
        Show-CertificateInfo -Certificates $certificates
        return
    }
    
    if ($ExportAll) {
        Write-Host "Exporting all certificates to: $exportFolder" -ForegroundColor Cyan
        $exportedCount = 0
        
        foreach ($cert in $certificates) {
            if (Export-CertificateToFile -Certificate $cert -OutputFolder $exportFolder -IncludePrivateKey:$IncludePrivateKey -Password $Password -Force:$Force) {
                $exportedCount++
            }
        }
        
        Write-Host "`nExport completed. $exportedCount of $($certificates.Count) certificates exported." -ForegroundColor Green
        return
    }
    
    if ($Thumbprint) {
        $cert = $certificates | Where-Object { $_.Thumbprint -eq $Thumbprint }
        if ($cert) {
            Export-CertificateToFile -Certificate $cert -OutputFolder $exportFolder -IncludePrivateKey:$IncludePrivateKey -Password $Password -Force:$Force
        } else {
            Write-Host "Certificate with thumbprint '$Thumbprint' not found in LocalMachine/My store." -ForegroundColor Red
        }
        return
    }
    
    if ($Subject) {
        $matchingCerts = $certificates | Where-Object { $_.Subject -like "*$Subject*" }
        if ($matchingCerts.Count -eq 0) {
            Write-Host "No certificates found matching subject: $Subject" -ForegroundColor Red
        } elseif ($matchingCerts.Count -eq 1) {
            Export-CertificateToFile -Certificate $matchingCerts[0] -OutputFolder $exportFolder -IncludePrivateKey:$IncludePrivateKey -Password $Password -Force:$Force
        } else {
            Write-Host "Multiple certificates found matching '$Subject':" -ForegroundColor Yellow
            Show-CertificateInfo -Certificates $matchingCerts
            Write-Host "Please use -Thumbprint parameter to specify which certificate to export." -ForegroundColor Yellow
        }
        return
    }
    
    # Default behavior: list certificates
    Show-CertificateInfo -Certificates $certificates
    Write-Host "`nUsage examples:" -ForegroundColor Cyan
    Write-Host "  .\Export-Certificate.ps1 -List"
    Write-Host "  .\Export-Certificate.ps1 -Thumbprint '1234567890ABCDEF1234567890ABCDEF12345678'"
    Write-Host "  .\Export-Certificate.ps1 -Subject 'My Company' -IncludePrivateKey -Password 'MyPassword'"
    Write-Host "  .\Export-Certificate.ps1 -ExportAll -IncludePrivateKey"
    Write-Host "  .\Export-Certificate.ps1 -OutputPath 'C:\MyCertificates' -ExportAll"
}
catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
} 