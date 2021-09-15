#
# Module manifest for module 'EC2Access'
#
#
# Copyright 2021 Cloudsoft Corporation Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

@{

# Script module or binary module file associated with this manifest.
RootModule = 'EC2Access.psm1'

# Version number of this module.
ModuleVersion = '1.0.0'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = '676c68f1-dc0c-4c88-8435-0d06041a39eb'

# Author of this module
Author = 'Richard Downer'

# Company or vendor of this module
CompanyName = 'Cloudsoft'

# Copyright statement for this module
Copyright = '© 2021 Cloudsoft Corporation Ltd.'

# Description of the functionality provided by this module
Description = 'Provides easy Remote Desktop access to EC2 instances'

# Minimum version of the PowerShell engine required by this module
PowerShellVersion = '5.1'
# Probably earlier is compatible but this is untested

# Name of the PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
DotNetFrameworkVersion = '4.0.0'

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
ClrVersion = '4.0.0'

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
RequiredModules = @( 'AWS.Tools.EC2', 'AWS.Tools.SimpleSystemsManagement' )

# Assemblies that must be loaded prior to importing this module
RequiredAssemblies = @( 'BouncyCastle.Crypto.dll' )

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @( 'Get-EC2Password', 'Start-DirectEC2RemoteDesktop', 'Start-EC2RemoteDesktopViaSessionManager' )

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = @()

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
FileList = @( 'EC2Access.psd1', 'EC2Access.psm1', 'BouncyCastle.Crypto.dll', 'LICENSE', 'README.md', 'LICENSE.BouncyCastle', 'en-US/about_EC2Access.help.txt' )

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        LicenseUri = 'https://opensource.org/licenses/Apache-2.0'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/richardcloudsoft/EC2Access'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        # ReleaseNotes = ''

        # Prerelease string of this module
        # Prerelease = ''

        # Flag to indicate whether the module requires explicit user acceptance for install/update/save
        # RequireLicenseAcceptance = $false

        # External dependent modules of this module
        # ExternalModuleDependencies = @()

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

