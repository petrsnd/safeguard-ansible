[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$Component,
    [Parameter(Mandatory=$true)]
    [string]$BuildId,
    [Parameter(Mandatory=$true)]
    [string]$TagName,
    [Parameter(Mandatory=$true)]
    [string]$IsTagBuild
)

$local:IsTagBuildBool = $IsTagBuild -eq "True" -or $IsTagBuild -eq "true" -or $IsTagBuild -eq "1"

Write-Host "Component = $Component"
Write-Host "BuildId = $BuildId"
Write-Host "TagName = $TagName"
Write-Host "IsTagBuild = $($local:IsTagBuildBool)"

# Read the semantic version from the component's metadata file
if ($Component -eq "collection") {
    $local:GalaxyFile = "collection/oneidentity/safeguard/galaxy.yml"
    $local:Content = Get-Content $local:GalaxyFile -Raw
    if ($local:Content -match 'version:\s*(\S+)') {
        $local:SemanticVersion = $Matches[1]
    } else {
        throw "Could not read version from $($local:GalaxyFile)"
    }
} elseif ($Component -eq "credplugin") {
    $local:TomlFile = "credential_type_plugin/pyproject.toml"
    $local:Content = Get-Content $local:TomlFile -Raw
    if ($local:Content -match 'version\s*=\s*"([^"]+)"') {
        $local:SemanticVersion = $Matches[1]
    } else {
        throw "Could not read version from $($local:TomlFile)"
    }
} else {
    throw "Unknown component: $Component. Must be 'collection' or 'credplugin'."
}

Write-Host "SemanticVersion = $($local:SemanticVersion)"

if ($local:IsTagBuildBool) {
    # Tag builds: strip the component prefix to get the version
    # e.g. "collection-v2.0.0" -> "2.0.0", "credplugin-v2.0.0" -> "2.0.0"
    if ($TagName -match '^(collection|credplugin)-v(.+)$') {
        $local:PackageVersion = $Matches[2]
    } else {
        $local:PackageVersion = $TagName
    }
    Write-Host "Tag build detected, using tag version"
} else {
    # Dev builds get a prerelease suffix for unique artifact versioning.
    # Collection uses SemVer format (required by Ansible Galaxy).
    # Credential plugin uses PEP 440 format (required by PyPI).
    $local:BuildNumber = [int]$BuildId % 65534
    if ($Component -eq "collection") {
        $local:PackageVersion = "${local:SemanticVersion}-dev.${local:BuildNumber}"
    } else {
        $local:PackageVersion = "${local:SemanticVersion}.dev${local:BuildNumber}"
    }
    Write-Host "Dev build, BuildNumber = $($local:BuildNumber)"
}

Write-Host "PackageVersion = $($local:PackageVersion)"

# Compute the GitHub release tag — dev builds use a non-triggering prefix
# to avoid re-triggering the pipeline's tag-based triggers.
if ($local:IsTagBuildBool) {
    $local:ReleaseTag = $TagName
} else {
    if ($Component -eq "collection") {
        $local:ReleaseTag = "dev/collection-v${local:PackageVersion}"
    } else {
        $local:ReleaseTag = "dev/credplugin-v${local:PackageVersion}"
    }
}

Write-Host "ReleaseTag = $($local:ReleaseTag)"

# Write the version back into the metadata file
if ($Component -eq "collection") {
    (Get-Content $local:GalaxyFile).replace($local:SemanticVersion, $local:PackageVersion) | Set-Content $local:GalaxyFile
    Write-Host "Updated $($local:GalaxyFile) with version $($local:PackageVersion)"
} elseif ($Component -eq "credplugin") {
    (Get-Content $local:TomlFile).replace("`"$($local:SemanticVersion)`"", "`"$($local:PackageVersion)`"") | Set-Content $local:TomlFile
    Write-Host "Updated $($local:TomlFile) with version $($local:PackageVersion)"
}

Write-Output "##vso[task.setvariable variable=PackageVersion;]$($local:PackageVersion)"
Write-Output "##vso[task.setvariable variable=ReleaseTag;]$($local:ReleaseTag)"
