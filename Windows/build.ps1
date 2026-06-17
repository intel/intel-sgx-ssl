#
# Copyright (C) 2011-2023 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#


#=========================================#
# Do not edit this script below this line #
#=========================================#

Param(
	[Parameter(mandatory=$false)][string]$OPENSSL_VERSION = "openssl-3.0.0",
    [Parameter(mandatory=$false)][bool] $PSW_available=1
)
function ExecuteCommand() {
    param
    (
        [Parameter(Mandatory=$true)][string] $Command,
        [Parameter(Mandatory=$true)][string] $Cmdarg
    )
    try {
        & $command $cmdarg
        if ($LASTEXITCODE -ne 0) {
            throw 'Execution failed'
            Exit 1
        }
    } catch {
        Write-Error "cannot find $command"
        Exit 1
    }
}

try {
    #Write-out "Validating Prerequisites (perl, nasm)"
    ExecuteCommand "nasm" "-v"
    ExecuteCommand "perl" "-v"
} catch {
    Write-Error "cannot find nasm or perl, exiting"
    Exit 1
}

try {
    $SGXSSL_ROOT = Get-Location
    if (-not (Test-Path "../openssl_source/$OpenSSL_version.tar.gz" -PathType Leaf))
    {
        Write-Output "$OpenSSL_version source code package not available, exiting"
        Exit 1 
    }
    Write-Output "Building SGXSSL with: $OpenSSL_version"
    ForEach ($Config in ("debug", "release", "cve-2020-0551-load-release", "cve-2020-0551-cf-release")) {
        Write-Output "  Building libraries in x64, $Config..."
        $BUILD_LEVEL = "ALL"
        if ( $PSW_available -ne 1)
        {
            $BUILD_LEVEL = "SKIP_TEST"
        }
        $Build_proc = Start-Process powershell -ArgumentList ".\build_pkg.ps1 -my_Configuration $Config -OPENSSL_version $OpenSSL_version -BUILD_LEVEL $BUILD_LEVEL -Clean 0" -PassThru
        $Build_proc.WaitForExit()
        if ($Build_proc.HasExited) {
            # Write-Host "The build process has exited."
        }
        if ($Build_proc.ExitCode  -ne 0) {
            Write-Output "  Failed building config $Config, exiting..."
            Exit 1
        } else {
            Write-Output "  Successfully built config $Config"
        }
    }

    $currentTime = Get-Date -format "dd-MMM-yyyy HH:mm:ss"
    Write-Output "Build completed: Zipping package $currentTime"
    $SGXSSL_version_numbers = ($OpenSSL_version -split '-')[1]
    if ( $PSW_available -eq 1) 
    {
        $SGXSSL_version_numbers = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Intel\SGX_PSW" -Name "Version")."Version" + "_" + $SGXSSL_version_numbers
    }
    Set-Location package
    Compress-Archive -Path docs, include, lib  -DestinationPath ..\sgxssl.$SGXSSL_version_numbers.zip -Update
    
} catch {
    Write-Output $_.ToString()
    Write-Output $_.ScriptStackTrace
    Exit 1
} finally  {
    set-location $SGXSSL_ROOT
}
Exit 0