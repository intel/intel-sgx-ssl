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


REM #=========================================#
REM # Do not edit this script below this line #
REM #=========================================#

rem @echo on

set OPENSSL_INSTALL_DIR=%cd%
set OPENSSL_INSTALL_DIR=%OPENSSL_INSTALL_DIR%\OpenSSL_install_dir_tmp\Windows
set PROCESSOR_ARCHITECTURE=AMD64

if "%1"=="" goto usage

set build_mode=%1
goto %build_mode%

:win32_debug
set my_Configuration=Debug
set my_Platform=Win32
set VS_CMD_PLFM=x86
set OPENSSL_CFG_PLFM=sgx-VC-WIN32 --debug
goto build_start


:win32_release
set my_Configuration=Release
set my_Platform=Win32
set VS_CMD_PLFM=x86
set OPENSSL_CFG_PLFM=sgx-VC-WIN32
goto build_start


:x64_debug
set my_Configuration=Debug
set my_Platform=x64
set VS_CMD_PLFM=amd64
set OPENSSL_CFG_PLFM=sgx-VC-WIN64A --debug
goto build_start


:x64_release
set my_Configuration=Release
set my_Platform=x64
set VS_CMD_PLFM=amd64
set OPENSSL_CFG_PLFM=sgx-VC-WIN64A
goto build_start

:build_start

if "%VS_CMD_PLFM%"=="x86" (
	set PROCESSOR_ARCHITECTURE=x86
	)
@echo "PROCESSOR_ARCHITECTURE: %PROCESSOR_ARCHITECTURE%"

perl Configure --config=sgx_config.conf %OPENSSL_CFG_PLFM%  ^
no-dtls no-ssl2 no-idea no-mdc2 no-rc5 no-rc4 no-bf no-ec2m no-camellia no-cast no-srp no-hw no-dso no-shared no-ui no-ssl3 no-md2 no-md4 no-stdio ^
-FI".\bypass_to_sgxssl.h" -D_NO_CRT_STDIO_INLINE -DOPENSSL_NO_SOCK -DOPENSSL_NO_DGRAM ^
-DOPENSSL_NO_ASYNC -arch:IA32  --prefix=%OPENSSL_INSTALL_DIR%

nmake build_generated libcrypto.lib
if %errorlevel% neq 0 (
	@echo Failed command: [nmake build_generated libcrypto.lib]   %date% %time%
	goto error
)

@echo Script ended successfully!   %date% %time%
goto end

:usage
@echo Usage: build_package ^<win32_debug^|win32_release^|x64_debug^|x64_release^>
@echo Run from within OpenSSL root directory.

:end
exit /b 0

:error
@echo Script ended with error!   %date% %time%
exit /b 1
