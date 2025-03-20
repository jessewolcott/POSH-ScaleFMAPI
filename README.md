# ScaleFMAPI PowerShell Module
## Overview
The ScaleFMAPI PowerShell module provides a secure interface for interacting with Scale Computing's REST API. This module enables administrators to query and manage Scale Computing clusters without embedding API keys directly into scripts.
## Features
* Secure API Key Management: Store API keys in encrypted files rather than hardcoding them
* Cluster Information Retrieval: Get detailed information about your Scale Computing clusters
* Modular Design: Well-structured functions for maintainability and extensibility
* Logging Capabilities: Optional logging to track API interactions and troubleshoot issues
## Prerequisites
* PowerShell 5.1 or higher
* Network access to Scale Computing API endpoints
* Valid API key with appropriate permissions
## Installation
* Download the module files to your preferred location
* Import the module:
```powershell
Import-Module -Path "C:\Path\To\ScaleFMAPI.psm1"
```
# Quick Start
```powershell
# Import the module
Import-Module .\ScaleComputingAPI.psm1

# Register your API key
Register-ScaleApiKey -Role "MyAdmin" -ApiKey "your-api-key-here"

# Get information about your clusters
$clusters = Get-ScaleComputingClusters -ApiKeyName "MyAdmin" -EnableLogging $true

# View the results
$clusters | Format-Table -AutoSize
```

## Functions
### Register-ScaleApiKey
Securely stores an API key for later use.
```powershell
Register-ScaleApiKey -Role "MyRole" -ApiKey "your-api-key" -EnableLogging $true
```
#### Parameters:
* -Role: Name to associate with this API key (optional, will prompt if not provided)
* -ApiKey: The API key to store (optional, will prompt if not provided)
* -EnableLogging: Enable or disable logging ($true or $false)

### Get-ScaleAvailableApiKeys
Lists all registered API keys.
```powershell
Get-ScaleAvailableApiKeys -Role "MyRole"
```
#### Parameters:
* -Role: Optional filter to show only a specific role
### Remove-ScaleApiKey
Removes a registered API key and its credential file.
``` powershell
Remove-ScaleApiKey -Role "MyRole" -Force -EnableLogging $true
```
#### Parameters:
-Name or -Role: Name of the API key role to remove
-Force: Skip confirmation prompts
-EnableLogging: Enable or disable logging ($true or $false)

### Set-ScaleApiEndpoint
Configures the API endpoint URL. This is not needed if using `https://api.scalecomputing.com/api/v2`
```powershell
Set-ScaleApiEndpoint -Url "https://api.scalecomputing.com/api/v2" -EnableLogging $true
```

#### Parameters:
* -Url: API endpoint URL (default: "https://api.scalecomputing.com/api/v2")
* -EnableLogging: Enable or disable logging ($true or $false)
### Get-ScaleApiEndpoint
Returns the API endpoint URL.
```powershell
# Get the current API endpoint
Get-ScaleApiEndpoint -EnableLogging $true
```

#### Parameters:
* -EnableLogging: Enable or disable logging ($true or $false)

### Get-ScaleComputingClusters
Retrieves information about Scale Computing clusters.
```powershell
Get-ScaleComputingClusters -ApiKeyName "MyRole" -Limit 100 -EnableLogging $true
```
#### Parameters:
* -ApiKeyName: Name of a previously registered API key (required)
* -Limit: Maximum number of clusters to retrieve (default: 500)
* -Offset: Offset for pagination (default: 0)
* -EnableLogging: Enable or disable logging ($true or $false)

# Security
This module implements several security best practices:
* No hardcoded API keys: All API keys must be registered by the user
* Encrypted storage: API keys are encrypted with PowerShell's secure string encryption
* Memory protection: Decrypted keys are securely handled in memory
* Least privilege: Functions only access the API endpoints they need
# Logging
When logging is enabled, the module writes to log files in a "Logs" directory created in the same location as the module. Log files are named by date (e.g., "ScaleComputing_2025-03-20.log").
# Examples
Register an API key and get cluster information
```powershell
# Import module
Import-Module .\ScaleComputingAPI.psm1

# Register API key
Register-ScaleApiKey -Role "ClusterAdmin" -ApiKey "your-api-key-here" -EnableLogging $true

# Get and display clusters
$clusters = Get-ScaleComputingClusters -ApiKeyName "ClusterAdmin" -EnableLogging $true
$clusters | Where-Object { $_.UpdatesAvailable -eq "Yes" } | Format-Table
```
View available API keys and remove one
```powershell
# See all registered keys
Get-ScaleAvailableApiKeys

# Remove a specific key
Remove-ScaleApiKey -Role "OldAdmin" -Force
```
# Troubleshooting
* API key not found: Make sure you've registered the key with Register-ScaleApiKey
* Connection errors: Verify network connectivity to the Scale Computing API endpoint
* Permission denied: Ensure your API key has the required permissions

# Contributing
Contributions to this module are welcome. Please ensure any modifications maintain the security features and follow PowerShell best practices.

# To-do 
1. Document more use cases to expand into functions
1. Add more error handling
1. `Get-ScaleComputingClusters` has an update checker, but its not working because I need to figure out how to poll the API for latest available build. 
1. Set-ScaleApiEndpoint needs to store the parameter in a permanent way