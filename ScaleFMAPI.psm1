# ScaleComputingAPI.psm1

# Module-level variables
$script:HCOSGA = '9.4.27.217089'
$script:ApiEndpoint = 'https://api.scalecomputing.com/api/v2'
$script:CredentialFolder = Join-Path -Path $PSScriptRoot -ChildPath "Credentials"
$script:EnableLogging = $false

function Initialize-ScaleEnvironment {
    [CmdletBinding()]
    param()
    
    # Create credentials folder if it doesn't exist
    if (-not (Test-Path -Path $script:CredentialFolder)) {
        New-Item -Path $script:CredentialFolder -ItemType Directory | Out-Null
        Write-ScaleLog -Message "Created credentials directory: $($script:CredentialFolder)" -Level 'Info'
    }
    
    # Create logs folder if it doesn't exist
    $logDirectory = Join-Path -Path $PSScriptRoot -ChildPath "Logs"
    if (-not (Test-Path -Path $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory | Out-Null
    }
    
    # Load any existing credential files into memory
    $credFiles = Get-ChildItem -Path $script:CredentialFolder -Filter "*.cred" -ErrorAction SilentlyContinue
    foreach ($file in $credFiles) {
        $roleName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        $script:ApiKeys[$roleName] = $file.FullName
    }
}

function Write-ScaleLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    if (-not $script:EnableLogging) {
        return
    }
    
    $logDirectory = Join-Path -Path $PSScriptRoot -ChildPath "Logs"
    
    if (-not (Test-Path -Path $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory | Out-Null
    }
    
    $logFile = Join-Path -Path $logDirectory -ChildPath "ScaleComputing_$(Get-Date -Format 'yyyy-MM-dd').log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $logFile -Value $logEntry
}

function Register-ScaleApiKey {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$ApiKey,
        
        [Parameter(Mandatory = $false)]
        [string]$Role,
        
        [Parameter(Mandatory = $false)]
        [bool]$EnableLogging = $false
    )
    
    # Set logging state
    $script:EnableLogging = $EnableLogging
    
    # Initialize environment
    Initialize-ScaleEnvironment
    
    # Make sure ApiKeys dictionary is initialized
    if ($null -eq $script:ApiKeys) {
        $script:ApiKeys = @{}
        Write-ScaleLog -Message "Initialized ApiKeys dictionary" -Level 'Info'
    }
    
    # Either use provided Role or prompt for it
    if ([string]::IsNullOrWhiteSpace($Role)) {
        $roleName = Read-Host -Prompt "Enter a name for this API key role (e.g., OrgAdmin, ReadOnly)"
    } else {
        $roleName = $Role
        Write-ScaleLog -Message "Using provided role name: $roleName" -Level 'Info'
    }
    
    # Either use provided ApiKey or prompt for it
    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        $apiKeySecure = Read-Host -Prompt "Enter the API key" -AsSecureString
    } else {
        # Convert plain text API key to SecureString
        $apiKeySecure = ConvertTo-SecureString -String $ApiKey -AsPlainText -Force
        Write-ScaleLog -Message "Using provided API key" -Level 'Info'
    }
    
    try {
        # Convert secure string to encrypted standard string
        $encryptedKey = ConvertFrom-SecureString -SecureString $apiKeySecure
        
        # Create credentials folder if it doesn't exist
        if (-not (Test-Path -Path $script:CredentialFolder)) {
            New-Item -Path $script:CredentialFolder -ItemType Directory -Force | Out-Null
            Write-ScaleLog -Message "Created credentials directory: $($script:CredentialFolder)" -Level 'Info'
        }
        
        # Save encrypted key to file
        $credentialFile = Join-Path -Path $script:CredentialFolder -ChildPath "$roleName.cred"
        $encryptedKey | Set-Content -Path $credentialFile -Force
        
        Write-ScaleLog -Message "API key stored successfully for role: $roleName" -Level 'Info'
        Write-Host "API key stored successfully for role: $roleName" -ForegroundColor Green
        
        # Add to the in-memory keys dictionary
        $script:ApiKeys[$roleName] = $credentialFile
        
        # Return success information
        return [PSCustomObject]@{
            Role = $roleName
            CredentialFile = $credentialFile
            Status = "Success"
        }
    }
    catch {
        $errorMessage = "Failed to store API key: $_"
        Write-ScaleLog -Message $errorMessage -Level 'Error'
        Write-Error $errorMessage
    }
}

function Get-ScaleApiKey {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    
    $keyFile = $script:ApiKeys[$Name]
    if (-not $keyFile) {
        $errorMessage = "API key '$Name' not found. Please register it first using Register-ScaleApiKey."
        Write-ScaleLog -Message $errorMessage -Level 'Error'
        throw $errorMessage
    }
    
    # Check if this is a valid file path
    if (-not (Test-Path -Path $keyFile)) {
        $errorMessage = "Credential file for role '$Name' not found at: $keyFile"
        Write-ScaleLog -Message $errorMessage -Level 'Error'
        throw $errorMessage
    }
    
    try {
        # Read the encrypted key from file
        $encryptedKey = Get-Content -Path $keyFile
        
        # Convert encrypted key to secure string
        $secureKey = ConvertTo-SecureString -String $encryptedKey
        
        # Convert secure string to plain text for API use
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
        $apiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        
        return $apiKey
    }
    catch {
        $errorMessage = "Failed to decrypt API key: $_"
        Write-ScaleLog -Message $errorMessage -Level 'Error'
        throw $errorMessage
    }
}

function Set-ScaleApiEndpoint {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Url = "https://api.scalecomputing.com/api/v2",
        
        [Parameter(Mandatory = $false)]
        [bool]$EnableLogging = $false
    )
    
    $script:EnableLogging = $EnableLogging
    $script:ApiEndpoint = $Url
    Write-ScaleLog -Message "API endpoint set to: $Url" -Level 'Info'
    
    # Return the current endpoint for confirmation
    return [PSCustomObject]@{
        ApiEndpoint = $script:ApiEndpoint
        SetTime = Get-Date
    }
}
function Get-ScaleApiEndpoint {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [bool]$EnableLogging = $false
    )
    
    # Set logging state
    $script:EnableLogging = $EnableLogging
    
    # Ensure the ApiEndpoint variable exists
    if ([string]::IsNullOrWhiteSpace($script:ApiEndpoint)) {
        # Set to default if not configured
        $script:ApiEndpoint = "https://api.scalecomputing.com/api/v2"
        Write-ScaleLog -Message "API endpoint was not configured, set to default: $($script:ApiEndpoint)" -Level 'Info'
    }
    
    # Log the retrieval
    Write-ScaleLog -Message "Retrieved current API endpoint: $($script:ApiEndpoint)" -Level 'Info'
    
    # Return a custom object with the endpoint information
    return [PSCustomObject]@{
        ApiEndpoint = $script:ApiEndpoint
        LastModified = if ($script:EndpointLastModified) { $script:EndpointLastModified } else { Get-Date }
        Default = $script:ApiEndpoint -eq "https://api.scalecomputing.com/api/v2"
    }
}
function Get-ScaleAvailableApiKeys {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Role
    )
    
    # Initialize environment to ensure all keys are loaded
    Initialize-ScaleEnvironment
    
    # Return list of available API keys
    $keyInfo = @()
    
    # If Role parameter is specified, filter for just that role
    if (-not [string]::IsNullOrWhiteSpace($Role)) {
        if ($script:ApiKeys.ContainsKey($Role)) {
            $value = $script:ApiKeys[$Role]
            
            $keyInfo += [PSCustomObject]@{
                Name = $Role
                CredentialFile = $value
                Exists = Test-Path -Path $value
            }
        }
        else {
            Write-Warning "No API key found with role name: $Role"
        }
    }
    else {
        # Return all keys
        foreach ($key in $script:ApiKeys.Keys) {
            $value = $script:ApiKeys[$key]
            
            $keyInfo += [PSCustomObject]@{
                Name = $key
                CredentialFile = $value
                Exists = Test-Path -Path $value
            }
        }
    }
    
    return $keyInfo
}

function Remove-ScaleApiKey {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Role,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [bool]$EnableLogging = $false
    )
    
    $script:EnableLogging = $EnableLogging
    
    # Use Role parameter if provided, otherwise use Name
    $keyName = if (-not [string]::IsNullOrWhiteSpace($Role)) { $Role } else { $Name }
    
    # Check if a key name was provided
    if ([string]::IsNullOrWhiteSpace($keyName)) {
        $errorMessage = "Either -Name or -Role parameter must be specified."
        Write-ScaleLog -Message $errorMessage -Level 'Error'
        Write-Error $errorMessage
        return
    }
    
    $keyFile = $script:ApiKeys[$keyName]
    if (-not $keyFile) {
        $warningMessage = "API key '$keyName' not found."
        Write-ScaleLog -Message $warningMessage -Level 'Warning'
        Write-Warning $warningMessage
        return
    }
    
    # Check if the credential file exists
    if (Test-Path -Path $keyFile) {
        # Remove the file
        if ($Force -or $PSCmdlet.ShouldProcess($keyFile, "Delete credential file")) {
            Remove-Item -Path $keyFile -Force
            Write-ScaleLog -Message "Credential file for '$keyName' has been deleted." -Level 'Info'
        }
    }
    
    # Remove from the in-memory dictionary
    $script:ApiKeys.Remove($keyName)
    Write-ScaleLog -Message "API key '$keyName' has been removed from memory." -Level 'Info'
    Write-Host "API key '$keyName' has been removed successfully." -ForegroundColor Green
}

function Get-ScaleComputingClusters {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ApiKeyName,
        
        [Parameter(Mandatory = $false)]
        [int]$Limit = 500,
        
        [Parameter(Mandatory = $false)]
        [int]$Offset = 0,
        
        [Parameter(Mandatory = $false)]
        [bool]$EnableLogging = $false
    )
    
    # Set logging state
    $script:EnableLogging = $EnableLogging
    
    # Build API URL for clusters endpoint
    $clustersUrl = "$script:ApiEndpoint/clusters?offset=$Offset&limit=$Limit"
    
    try {
        # Get API key from stored credentials
        $apiKey = Get-ScaleApiKey -Name $ApiKeyName
        
        $headers = @{
            "accept" = "application/json"
            "api-key" = $apiKey
        }
        
        Write-ScaleLog -Message "Requesting clusters data from: $clustersUrl" -Level 'Info'
        $response = Invoke-RestMethod -Uri $clustersUrl -Headers $headers -Method Get
        Write-ScaleLog -Message "Retrieved $(($response.items).Count) clusters successfully" -Level 'Info'
        
        # Process the response to extract the needed information
        $results = foreach ($item in $response.items) {
            $updatesAvailable = "No"
            $versionAvailable = $null
            
            if ($item.version -ne $script:HCOSGA) {
                $updatesAvailable = "Yes"
                $versionAvailable = ($item.updatesAvailableOptions).uuid
            }
            
            [PSCustomObject]@{
                "ClusterName" = $item.name
                "HealthState" = $item.healthState
                "HealthScore" = $item.healthScore
                "Version" = $item.version
                "UpdatesAvailable" = $updatesAvailable
                "VersionAvailable" = $versionAvailable
                "BackplaneNode" = $item.leaderNodeLanIp
                "LastCheckin" = if ($item.LastCheckin) { 
                    (Get-Date $item.LastCheckin).ToString("MM/dd/yyyy hh:mm:ss tt") 
                } else { 
                    $null 
                }
            }
        }
        
        return $results
    }
    catch {
        $errorMessage = "Failed to retrieve Scale Computing clusters: $_"
        Write-ScaleLog -Message $errorMessage -Level 'Error'
        Write-Error $errorMessage
        return $null
    }
}
function Get-ScaleVMs {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ApiKeyName,
        
        [Parameter(Mandatory = $false)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Running", "Powered Off", "Unknown", "")]
        [string]$PowerState,
        
        [Parameter(Mandatory = $false)]
        [string]$Tag,
        
        [Parameter(Mandatory = $false)]
        [decimal]$MinDriveCapacityGB,
        
        [Parameter(Mandatory = $false)]
        [decimal]$MaxDriveCapacityGB,
        
        [Parameter(Mandatory = $false)]
        [decimal]$MinDriveFreeSpaceGB,
        
        [Parameter(Mandatory = $false)]
        [decimal]$MinDrivePercentage,
        
        [Parameter(Mandatory = $false)]
        [decimal]$MaxDrivePercentage,
        
        [Parameter(Mandatory = $false)]
        [decimal]$MinRAMGB,
        
        [Parameter(Mandatory = $false)]
        [decimal]$MaxRAMGB,
        
        [Parameter(Mandatory = $false)]
        [string]$VMOS_IP,
        
        [Parameter(Mandatory = $false)]
        [string]$HostNodeIP,
        
        [Parameter(Mandatory = $false)]
        [string]$ClusterName,
        
        [Parameter(Mandatory = $false)]
        [DateTime]$CreatedAfter,
        
        [Parameter(Mandatory = $false)]
        [DateTime]$CreatedBefore,
        
        [Parameter(Mandatory = $false)]
        [DateTime]$UpdatedAfter,
        
        [Parameter(Mandatory = $false)]
        [DateTime]$UpdatedBefore,
        
        [Parameter(Mandatory = $false)]
        [int]$Limit = 500,
        
        [Parameter(Mandatory = $false)]
        [int]$Offset = 0,
        
        [Parameter(Mandatory = $false)]
        [bool]$EnableLogging = $false
    )
    
    # Set logging state
    $script:EnableLogging = $EnableLogging
    
    # Build API URL for VMs endpoint
    $vmsUrl = "$script:ApiEndpoint/vms?offset=$Offset&limit=$Limit"
    
    try {
        # Get API key from stored credentials
        $apiKey = Get-ScaleApiKey -Name $ApiKeyName
        
        $headers = @{
            "accept" = "application/json"
            "api-key" = $apiKey
        }
        
        Write-ScaleLog -Message "Requesting VMs data from: $vmsUrl" -Level 'Info'
        $response = Invoke-RestMethod -Uri $vmsUrl -Headers $headers -Method Get
        Write-ScaleLog -Message "Retrieved $(($response.items).Count) VMs successfully" -Level 'Info'
        
        # Process the response to extract the needed information
        $results = foreach ($item in $response.items) {
            $powerState = switch ($item.state) {
                "1" { "Running" }
                "0" { "Powered Off" }
                default { "Unknown" }
            }
            
            $driveCapacityGB = [Math]::Round(($item.driveCapacity / 1024 / 1024 / 1024), 2)
            $driveAllocationGB = [Math]::Round(($item.driveAllocation / 1024 / 1024 / 1024), 2)
            $driveFreeSpaceGB = $driveCapacityGB - $driveAllocationGB
            $drivePercentage = if ($driveCapacityGB -gt 0) { 
                ($driveAllocationGB / $driveCapacityGB) * 100
            } else { 
                0 
            }
            $ramGB = [Math]::Round(($item.memory / 1024 / 1024 / 1024), 2)
            
            # Create VM object
            $vmObj = [PSCustomObject]@{
                "VM Name"                  = $item.name
                "Description"              = $item.description
                "Power State"              = $powerState
                "Tags"                     = $item.tags
                "Drive Total Capacity (GB)" = $driveCapacityGB
                "Drive Free Space (GB)"    = $driveFreeSpaceGB
                "Drive Percentage (%)"     = $drivePercentage
                "RAM (GB)"                 = $ramGB
                "VM OS IPs"                = $item.ips
                "Host Node IP"             = $item.nodeIp
                "Cluster Name"             = ($item.cluster).name
                "VM Created"               = $item.createdAt
                "VM Updated"               = $item.updatedAt
            }
            
            $vmObj
        }
        
        # Apply filters
        if (-not [string]::IsNullOrEmpty($VMName)) {
            $results = $results | Where-Object { $_."VM Name" -like "*$VMName*" }
        }
        if (-not [string]::IsNullOrEmpty($Description)) {
            $results = $results | Where-Object { $_."Description" -like "*$Description*" }
        }
        if (-not [string]::IsNullOrEmpty($PowerState)) {
            $results = $results | Where-Object { $_."Power State" -eq $PowerState }
        }
        if (-not [string]::IsNullOrEmpty($Tag)) {
            $results = $results | Where-Object { $null -ne $_.Tags -and $_.Tags -contains $Tag }
        }
        if ($MinDriveCapacityGB -gt 0) {
            $results = $results | Where-Object { $_."Drive Total Capacity (GB)" -ge $MinDriveCapacityGB }
        }
        if ($MaxDriveCapacityGB -gt 0) {
            $results = $results | Where-Object { $_."Drive Total Capacity (GB)" -le $MaxDriveCapacityGB }
        }
        if ($MinDriveFreeSpaceGB -gt 0) {
            $results = $results | Where-Object { $_."Drive Free Space (GB)" -ge $MinDriveFreeSpaceGB }
        }
        if ($MinDrivePercentage -gt 0) {
            $results = $results | Where-Object { $_."Drive Percentage (%)" -ge $MinDrivePercentage }
        }
        if ($MaxDrivePercentage -gt 0) {
            $results = $results | Where-Object { $_."Drive Percentage (%)" -le $MaxDrivePercentage }
        }
        if ($MinRAMGB -gt 0) {
            $results = $results | Where-Object { $_."RAM (GB)" -ge $MinRAMGB }
        }
        if ($MaxRAMGB -gt 0) {
            $results = $results | Where-Object { $_."RAM (GB)" -le $MaxRAMGB }
        }
        if (-not [string]::IsNullOrEmpty($VMOS_IP)) {
            $results = $results | Where-Object { $null -ne $_."VM OS IPs" -and $_."VM OS IPs" -contains $VMOS_IP }
        }
        if (-not [string]::IsNullOrEmpty($HostNodeIP)) {
            $results = $results | Where-Object { $_."Host Node IP" -eq $HostNodeIP }
        }
        if (-not [string]::IsNullOrEmpty($ClusterName)) {
            $results = $results | Where-Object { $_."Cluster Name" -like "*$ClusterName*" }
        }
        if ($CreatedAfter) {
            $results = $results | Where-Object { $_."VM Created" -gt $CreatedAfter }
        }
        if ($CreatedBefore) {
            $results = $results | Where-Object { $_."VM Created" -lt $CreatedBefore }
        }
        if ($UpdatedAfter) {
            $results = $results | Where-Object { $_."VM Updated" -gt $UpdatedAfter }
        }
        if ($UpdatedBefore) {
            $results = $results | Where-Object { $_."VM Updated" -lt $UpdatedBefore }
        }
        
        Write-ScaleLog -Message "Returned $($results.Count) VMs after filtering" -Level 'Info'
        return $results
    }
    catch {
        $errorMessage = "Failed to retrieve Scale Computing VMs: $_"
        Write-ScaleLog -Message $errorMessage -Level 'Error'
        Write-Error $errorMessage
        return $null
    }
}
# Initialize module on import
Initialize-ScaleEnvironment

# Export module members
Export-ModuleMember -Function Get-ScaleComputingClusters, Set-ScaleApiEndpoint, Register-ScaleApiKey, Get-ScaleAvailableApiKeys, Remove-ScaleApiKey