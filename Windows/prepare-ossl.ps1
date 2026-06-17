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
    [string]$OSSL_URL_PATH = "https://www.openssl.org/source"
    ,[Parameter(mandatory=$false)][string]$OPENSSL_VERSION = "openssl-3.0.10"
)

try {
    $SGXSSL_ROOT = Get-Location
    $full_openssl_url = "$OSSL_URL_PATH/$OPENSSL_VERSION.tar.gz"
    $full_openssl_hash_url = "$full_openssl_url.sha256"
    $downloaded_ossl_file = "$SGXSSL_ROOT/../openssl_source/$OPENSSL_VERSION.tar.gz"
    $downloaded_osslhash_file = "$downloaded_ossl_file.sha256"
   

    if (-not (Test-Path -path $downloaded_ossl_file))
    {
        Write-Output "Downloading $OPENSSL_VERSION code from remote server..."
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
        (New-Object Net.WebClient).DownloadFile($full_openssl_url, $downloaded_ossl_file)
        (New-Object Net.WebClient).DownloadFile($full_openssl_hash_url, $downloaded_osslhash_file)

        $opensslfilehash = (Get-FileHash $downloaded_ossl_file).Hash.ToLower()
        $expected_hash = (Get-Content $downloaded_osslhash_file  | Select-String -Pattern $opensslfilehash).ToString().Trim()
        if ($opensslfilehash -ne $expected_hash) 
        {
            Write-Output "Error:  expected $expected_hash, while got file hash:", $opensslfilehash
            Exit 1
        } else {
            Write-Output "$downloaded_ossl_file code was downloaded and verified."
        }
    }
} catch {
    Write-Output $_.ToString()
    Write-Output $_.ScriptStackTrace
    Exit 1
} finally  {
    set-location $SGXSSL_ROOT
}
Exit 0