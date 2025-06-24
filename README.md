# PowerShell Scripts

This repository contains useful PowerShell scripts for system administration and automation tasks.

## Scripts

### Export-Certificate.ps1

A PowerShell script to export certificates from the LocalMachine/My certificate store to a temporary folder.

#### Features

- Export certificates by thumbprint, subject name, or export all certificates
- Support for both public key (CER) and private key (PFX) exports
- Automatic temporary folder creation with timestamps
- Password protection for PFX exports
- Comprehensive error handling and logging
- Color-coded output for better readability

#### Requirements

- PowerShell 5.1 or later
- Windows operating system
- Appropriate permissions to access the LocalMachine certificate store

#### Usage Examples

```powershell
# List all certificates in the store
.\Export-Certificate.ps1 -List

# Export a specific certificate by thumbprint
.\Export-Certificate.ps1 -Thumbprint "1234567890ABCDEF1234567890ABCDEF12345678"

# Export a certificate by subject name (partial match)
.\Export-Certificate.ps1 -Subject "My Company"

# Export with private key and password
.\Export-Certificate.ps1 -Subject "My Company" -IncludePrivateKey -Password "MyPassword"

# Export all certificates from the store
.\Export-Certificate.ps1 -ExportAll

# Export to a custom location
.\Export-Certificate.ps1 -ExportAll -OutputPath "C:\MyCertificates"

# Force overwrite existing files
.\Export-Certificate.ps1 -ExportAll -Force
```

#### Parameters

- `-Thumbprint`: Export certificate by its thumbprint
- `-Subject`: Export certificate by subject name (supports partial matching)
- `-List`: List all certificates in the store
- `-ExportAll`: Export all certificates from the store
- `-IncludePrivateKey`: Export with private key (PFX format)
- `-Password`: Password for PFX export when including private key
- `-OutputPath`: Custom output path (defaults to temporary folder)
- `-Force`: Overwrite existing files without prompting

#### Output

The script creates a temporary folder structure like:
```
%TEMP%\ExportedCertificates\20231201_143022\
```

Certificates are exported with filenames based on their subject names, with appropriate extensions:
- `.cer` for public key exports
- `.pfx` for private key exports

#### Security Notes

- When exporting private keys, always use a strong password
- The temporary folder is created in the system's TEMP directory
- Consider cleaning up exported certificates after use
- Ensure appropriate permissions are in place for certificate store access

### Bind-IISCertificate.ps1

A PowerShell script to bind certificates to IIS websites and applications.

#### Features

- Bind certificates by thumbprint or import from PFX files
- Support for site-level and application-level bindings
- Flexible binding options (IP, port, host header)
- Comprehensive validation and error handling
- List IIS websites and certificates for discovery

#### Requirements

- PowerShell 5.1 or later
- Windows operating system with IIS installed
- WebAdministration PowerShell module
- Appropriate permissions for IIS management

#### Usage Examples

```powershell
# List all IIS websites
.\Bind-IISCertificate.ps1 -ListWebsites

# List all certificates in the store
.\Bind-IISCertificate.ps1 -ListCertificates

# Bind using certificate thumbprint
.\Bind-IISCertificate.ps1 -WebsiteName "Default Web Site" -CertificateThumbprint "1234567890ABCDEF1234567890ABCDEF12345678"

# Bind using certificate file
.\Bind-IISCertificate.ps1 -WebsiteName "MyApp" -CertificatePath "C:\Certificates\MyCert.pfx" -CertificatePassword "MyPassword"

# Bind with host header
.\Bind-IISCertificate.ps1 -WebsiteName "MySite" -CertificateThumbprint "1234567890ABCDEF1234567890ABCDEF12345678" -HostHeader "mysite.com"

# Remove a binding
.\Bind-IISCertificate.ps1 -WebsiteName "MySite" -CertificateThumbprint "1234567890ABCDEF1234567890ABCDEF12345678" -RemoveBinding
```

#### Parameters

- `-WebsiteName`: The name of the IIS website to bind the certificate to
- `-CertificateThumbprint`: The thumbprint of the certificate to bind
- `-CertificatePath`: Path to the certificate file (.pfx) to import and bind
- `-CertificatePassword`: Password for the certificate file
- `-IPAddress`: IP address to bind to (default: All Unassigned)
- `-Port`: Port number to bind to (default: 443 for HTTPS)
- `-HostHeader`: Host header for the binding
- `-Protocol`: Protocol for the binding (default: https)
- `-ListWebsites`: Lists all IIS websites
- `-ListCertificates`: Lists all certificates in LocalMachine/My store
- `-RemoveBinding`: Removes the specified binding instead of adding it
- `-Force`: Overwrites existing binding without prompting

### Export-And-Bind-Certificate.ps1

A comprehensive PowerShell script that combines certificate export and IIS binding in one operation.

#### Features

- **Complete Workflow**: Export certificate by common name and bind to IIS in one command
- **Smart Certificate Discovery**: Searches for certificates by common name with intelligent matching
- **Automatic Cleanup**: Removes temporary files after binding (optional)
- **Flexible Export Options**: Support for both public and private key exports
- **Comprehensive Logging**: Step-by-step progress reporting with color-coded output
- **Error Handling**: Robust error handling with cleanup on failure

#### Requirements

- PowerShell 5.1 or later
- Windows operating system with IIS installed
- WebAdministration PowerShell module
- Appropriate permissions for certificate store and IIS management

#### Usage Examples

```powershell
# Basic export and bind operation
.\Export-And-Bind-Certificate.ps1 -CommonName "MyServer" -WebsiteName "Default Web Site"

# Export with private key and bind with host header
.\Export-And-Bind-Certificate.ps1 -CommonName "web-server.company.com" -WebsiteName "MyApp" -HostHeader "mysite.com" -IncludePrivateKey -CertificatePassword "MyPassword"

# Export to custom location and keep the file
.\Export-And-Bind-Certificate.ps1 -CommonName "MyServer" -WebsiteName "MySite" -OutputPath "C:\Certificates" -KeepExportedFile

# Remove certificate binding
.\Export-And-Bind-Certificate.ps1 -CommonName "MyServer" -WebsiteName "MySite" -RemoveBinding

# Discovery commands
.\Export-And-Bind-Certificate.ps1 -ListWebsites
.\Export-And-Bind-Certificate.ps1 -ListCertificates
```

#### Parameters

- `-CommonName`: The common name (CN) of the certificate to export and bind
- `-WebsiteName`: The name of the IIS website to bind the certificate to
- `-ApplicationName`: The name of the IIS application (optional, for application-level binding)
- `-IPAddress`: IP address to bind to (default: All Unassigned)
- `-Port`: Port number to bind to (default: 443 for HTTPS)
- `-HostHeader`: Host header for the binding (optional)
- `-Protocol`: Protocol for the binding (default: https)
- `-IncludePrivateKey`: Exports the certificate with its private key (PFX format)
- `-CertificatePassword`: Password for PFX export when including private key
- `-OutputPath`: Custom output path for exported certificate
- `-Force`: Overwrites existing files and bindings without prompting
- `-KeepExportedFile`: Keeps the exported certificate file instead of cleaning it up
- `-ListWebsites`: Lists all IIS websites
- `-ListCertificates`: Lists all certificates in LocalMachine/My store
- `-RemoveBinding`: Removes the binding instead of adding it

#### Workflow

The script performs the following steps:

1. **Certificate Discovery**: Searches for certificates by common name in LocalMachine/My store
2. **Certificate Export**: Exports the certificate to a temporary folder (or custom location)
3. **IIS Binding**: Binds the certificate to the specified IIS website
4. **Cleanup**: Removes temporary files (unless `-KeepExportedFile` is specified)

#### Output

The script provides detailed, color-coded output showing:
- Certificate discovery results
- Export file location
- Binding configuration details
- Success/failure status for each step

#### Security Notes

- When exporting private keys, always use a strong password
- The script automatically cleans up temporary files for security
- Use `-KeepExportedFile` only when you need to retain the exported certificate
- Ensure appropriate permissions are in place for both certificate store and IIS access

## Output

The scripts create organized folder structures and files:

### Certificate Export Output
```
%TEMP%\ExportedCertificates\20231201_143022\
├── MyServer.cer (public key only)
└── MyServer.pfx (with private key)
```

### File Types
| Export Type | Extension | Format | Content | Use Case |
|-------------|-----------|--------|---------|----------|
| Public Key | `.cer` | X.509 DER | Certificate only | Sharing public key, verification |
| Private Key | `.pfx` | PKCS#12 | Certificate + Private Key | Installation, backup, transfer |

## Security Notes

- When exporting private keys, always use a strong password
- Temporary folders are created in the system's TEMP directory
- Consider cleaning up exported certificates after use
- Ensure appropriate permissions are in place for certificate store access
- The Export-And-Bind-Certificate script automatically handles cleanup for security

## License

This project is licensed under the terms specified in the LICENSE file.
