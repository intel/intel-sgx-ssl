@echo off
Rem 
Rem Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
Rem 
Rem Redistribution and use in source and binary forms, with or without
Rem modification, are permitted provided that the following conditions
Rem are met:
Rem 
Rem   * Redistributions of source code must retain the above copyright
Rem     notice, this list of conditions and the following disclaimer.
Rem   * Redistributions in binary form must reproduce the above copyright
Rem     notice, this list of conditions and the following disclaimer in
Rem     the documentation and/or other materials provided with the
Rem     distribution.
Rem   * Neither the name of Intel Corporation nor the names of its
Rem     contributors may be used to endorse or promote products derived
Rem     from this software without specific prior written permission.
Rem 
Rem THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
Rem "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
Rem LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
Rem A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
Rem OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
Rem SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
Rem LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
Rem DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
Rem THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
Rem (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
Rem OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
Rem 
Rem 

@echo off


set SGXSSL_VERSION=1.9.100.%errorlevel%

REM Check if Prerequisites apps available
echo "Validating Prerequisites (7z, perl, nasm)"
7z > nul 2>&1
if %errorlevel% neq 0 (
	echo "Build failed, can't find 7z."
)
perl -v > nul 2>&1
if %errorlevel% neq 0 (
	echo "Build failed, can't find perl."
)
nasm -v > nul 2>&1
if %errorlevel% neq 0 (
	echo "Build failed, can't find nasm."
)


REM This variable must be set to the openssl file name (version) located in the openssl_source folder
if "%1"=="" (
	set OPENSSL_VERSION=openssl-1.1.1
) else (
	set OPENSSL_VERSION=%1
)

for /f "tokens=2*" %%A in ('REG QUERY "HKLM\SOFTWARE\Intel\SGX_PSW" /v Version') DO (
  for %%F in (%%B) do (
    set PSW_VER=%%F
	goto :break
  )
)
:break
set SGXSSL_VERSION=%PSW_VER%_%OPENSSL_VERSION:openssl-=%
echo "Building SGXSSL with: %OPENSSL_VERSION%  %date% %time% to %SGXSSL_VERSION%"

REM *********************************************************
REM **                     win32_debug                     **
REM *********************************************************

set pltfrm_conf=win32_debug
echo "Building %pltfrm_conf%  %date% %time%"
start /WAIT cmd /C call build_package.cmd %pltfrm_conf% %OPENSSL_VERSION% no-clean
if %errorlevel% neq 0 (
	echo "Failed building %pltfrm_conf%  %date% %time%"
) else (
	echo "Successfully built %pltfrm_conf%  %date% %time%"
)

REM *********************************************************
REM **                    win32_release                    **
REM *********************************************************
set pltfrm_conf=win32_release
echo "Building %pltfrm_conf%  %date% %time%"
start /WAIT cmd /C call build_package.cmd %pltfrm_conf% %OPENSSL_VERSION% no-clean
if %errorlevel% neq 0 (
	echo "Failed building %pltfrm_conf%  %date% %time%"
) else (
	echo "Successfully built %pltfrm_conf%  %date% %time%"
)

REM *********************************************************
REM **                      x64_debug                      **
REM *********************************************************
set pltfrm_conf=x64_debug
echo "Building %pltfrm_conf%  %date% %time%"
start /WAIT cmd /C call build_package.cmd %pltfrm_conf% %OPENSSL_VERSION% no-clean
if %errorlevel% neq 0 (
	echo "Failed building %pltfrm_conf%  %date% %time%"
) else (
	echo "Successfully built %pltfrm_conf%  %date% %time%"
)

REM *********************************************************
REM **                     x64_release                     **
REM *********************************************************
set pltfrm_conf=x64_release
echo "Building %pltfrm_conf%  %date% %time%"
start /WAIT cmd /C call build_package.cmd %pltfrm_conf% %OPENSSL_VERSION% no-clean
if %errorlevel% neq 0 (
	echo "Failed building %pltfrm_conf%  %date% %time%"
) else (
	echo "Successfully built %pltfrm_conf%  %date% %time%"
)



REM # generate list of tools used for creating this release
set BUILD_TOOLS_FILENAME=sgxssl.%SGXSSL_VERSION%.build-tools.txt
echo "OpenSSL package version:" >> %BUILD_TOOLS_FILENAME%
echo "%OPENSSL_VERSION%" >> %BUILD_TOOLS_FILENAME%
echo "SVN revision:" >> %BUILD_TOOLS_FILENAME%
echo "%SVN_REVISION%" >> %BUILD_TOOLS_FILENAME%
echo "perl --version:" >> %BUILD_TOOLS_FILENAME%
perl --version >> %BUILD_TOOLS_FILENAME%


echo "Build completed\nZipping package  %date% %time%"

cd package

7z.exe a ..\sgxssl.%SGXSSL_VERSION%.zip .

if %errorlevel% neq 0 (
	echo "Failed command: [7z.exe a ..\sgxssl.%SGXSSL_VERSION%.zip package] %errorlevel%"
	cd ..
	exit /b 1
)
echo "**********************************************************"
echo "*           SGXSSL package built successfully           **"
echo                  %date% %time%                   
echo "**********************************************************"

cd ..
exit /b 0