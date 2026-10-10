<#
.SYNOPSIS
    Read-only inventory of tool availability and unassigned driver source.
.DESCRIPTION
    Tool presence is not a working driver, valid signature, assigned altitude or VM approval.
    Does not change certificates, boot options, services, Defender or driver registration.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"
$sourceDirectory = Join-Path $PSScriptRoot "AegisFilter"
$inventory = [ordered]@{
    OperatingSystemArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    DriverSourcePresent = (Test-Path -LiteralPath (Join-Path $sourceDirectory "AegisFilter.c"))
    DriverProjectPresent = (Test-Path -LiteralPath (Join-Path $sourceDirectory "AegisFilter.vcxproj"))
    InfTemplatePresent = (Test-Path -LiteralPath (Join-Path $sourceDirectory "AegisFilter.inf"))
    MSBuildOnPath = [bool](Get-Command msbuild.exe -CommandType Application -ErrorAction SilentlyContinue)
    Inf2CatOnPath = [bool](Get-Command inf2cat.exe -CommandType Application -ErrorAction SilentlyContinue)
    SignToolOnPath = [bool](Get-Command signtool.exe -CommandType Application -ErrorAction SilentlyContinue)
    NativeEnforcementValidated = $false
    AltitudeAssignmentValidated = $false
    IsolatedVmValidated = $false
}
[pscustomobject]$inventory
Write-Warning "This is only an inventory. Missing native, assignment, signing and VM validation gates prevent release approval."
