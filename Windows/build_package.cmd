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

set SGXSSL_ROOT=%cd%
set SGXSSL_SOLUTION=%SGXSSL_ROOT%\sgx\
set OPENSSL_VERSION=%2
set TEST_MODE=%4
set OPENSSL_INSTALL_DIR=%SGXSSL_ROOT%\..\openssl_source\OpenSSL_install_dir_tmp
set PROCESSOR_ARCHITECTURE=AMD64
perl svn_revision.pl > sgx\libsgx_tsgxssl\tsgxssl_version.h

set build_mode=%1
goto %build_mode%

:win32_debug
set Configuration=Debug
set Platform=Win32
set VS_CMD_PLFM=x86
set OPENSSL_CFG_PLFM=VC-WIN32
goto build_start


:win32_release
set Configuration=Release
set Platform=Win32
set VS_CMD_PLFM=x86
set OPENSSL_CFG_PLFM=VC-WIN32
goto build_start


:x64_debug
set Configuration=Debug
set Platform=x64
set VS_CMD_PLFM=amd64
set OPENSSL_CFG_PLFM=VC-WIN64A
goto build_start


:x64_release
set Configuration=Release
set Platform=x64
set VS_CMD_PLFM=amd64
set OPENSSL_CFG_PLFM=VC-WIN64A
goto build_start





:build_start

cd %SGXSSL_ROOT%\..\openssl_source
rmdir /s /q %OPENSSL_VERSION%

7z.exe x -y %OPENSSL_VERSION%.tar.gz
7z.exe x -y %OPENSSL_VERSION%.tar

REM Intel® Software Guard Extensions SSL uses rd_rand, so there is no need to get a random based on time
REM sed -i "s|time_t tim;||g" %OPENSSL_VERSION%\crypto\bn\bn_rand.c
call powershell -Command "(get-content %OPENSSL_VERSION%\crypto\bn\bn_rand.c) -replace ('time_t tim;','') | out-file %OPENSSL_VERSION%\crypto\bn\bn_rand.c"
REM sed -i "s|time(&tim);||g" %OPENSSL_VERSION%\crypto\bn\bn_rand.c
call powershell -Command "(get-content %OPENSSL_VERSION%\crypto\bn\bn_rand.c) -replace ('time\(&tim\);','') | out-file %OPENSSL_VERSION%\crypto\bn\bn_rand.c"
REM sed -i "s|RAND_add(&tim, sizeof(tim), 0.0);||g" %OPENSSL_VERSION%\crypto\bn\bn_rand.c
call powershell -Command "(get-content %OPENSSL_VERSION%\crypto\bn\bn_rand.c) -replace ('RAND_add\(&tim, sizeof\(tim\), 0.0\);','') | out-file %OPENSSL_VERSION%\crypto\bn\bn_rand.c"

REM Remove AESBS to support only AESNI and VPAES
REM sed -i '/BSAES_ASM/d' $OPENSSL_VERSION/Configure
call powershell -Command "(get-content %OPENSSL_VERSION%\Configure) -replace ('BSAES_ASM','') | out-file %OPENSSL_VERSION%\Configure"

copy /y  rand_win.c %OPENSSL_VERSION%\crypto\rand\
copy /y  rand_lib.c %OPENSSL_VERSION%\crypto\rand\
copy /y  md_rand.c %OPENSSL_VERSION%\crypto\rand\

cd %SGXSSL_ROOT%\..\openssl_source\%OPENSSL_VERSION%
call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" %VS_CMD_PLFM%

if "%VS_CMD_PLFM%"=="x86" (
	set PROCESSOR_ARCHITECTURE=x86
	)
echo "PROCESSOR_ARCHITECTURE: %PROCESSOR_ARCHITECTURE%"
perl Configure %OPENSSL_CFG_PLFM%  no-dtls no-ssl2 no-idea no-mdc2 no-rc5 no-rc4 no-bf no-ec2m no-camellia no-cast no-srp no-hw no-dso no-shared no-ui no-ssl3 no-md2 no-md4 no-stdio -FI"%SGXSSL_ROOT%\..\openssl_source\bypass_to_sgxssl.h" -D_NO_CRT_STDIO_INLINE -DOPENSSL_NO_SOCK -DOPENSSL_NO_DGRAM -DOPENSSL_NO_ASYNC -arch:IA32  --prefix=%OPENSSL_INSTALL_DIR%

nmake build_generated libcrypto.lib
if %errorlevel% neq 0 (
	echo Failed command: [nmake build_generated libcrypto.lib]   %date% %time%
	goto error
)



xcopy /y  libcrypto.lib %SGXSSL_ROOT%\package\lib\%Platform%\%Configuration%\libsgx_tsgxssl_crypto.lib*
xcopy /y  ossl_static.pdb %SGXSSL_ROOT%\package\lib\%Platform%\%Configuration%\
xcopy /y include\openssl\* %SGXSSL_ROOT%\package\include\openssl\

echo "Done building OpenSSL for %Platform% | %Configuration%. Building Intel® Software Guard Extensions SSL libraries  %date% %time%"
cd %SGXSSL_SOLUTION%\

set MSBUILD="C:\Program Files (x86)\MSBuild\14.0\Bin\MSBuild.exe"
 
call %MSBUILD% SGXOpenSSLLibrary.sln /p:Configuration=%Configuration% /p:Platform=%Platform% /t:Rebuild
if %errorlevel% neq 0 (
	echo "Failed command: [MSBuild.exe SGXOpenSSLLibrary.sln /p:Configuration=%Configuration% /p:Platform=%Platform%  /t:Rebuild]   %date% %time%"
	goto error
)
xcopy /y %Platform%\%Configuration%\libsgx_tsgxssl.lib %SGXSSL_ROOT%\package\lib\%Platform%\%Configuration%\
xcopy /y %Platform%\%Configuration%\libsgx_usgxssl.lib %SGXSSL_ROOT%\package\lib\%Platform%\%Configuration%\
if "%Configuration%"=="Debug" (
	xcopy /y %Platform%\%Configuration%\libsgx_tsgxssl.pdb %SGXSSL_ROOT%\package\lib\%Platform%\%Configuration%\
	xcopy /y %Platform%\%Configuration%\libsgx_usgxssl.pdb %SGXSSL_ROOT%\package\lib\%Platform%\%Configuration%\
)

if "%Configuration%" neq "Release" (
	if "%TEST_MODE%" neq "SIM" (
		cd %Platform%\%Configuration%\
		call TestApp.exe
		if %errorlevel% neq 0 (
			echo "Failed command: app, %errorlevel%   %date% %time%"
			goto error
		)
	)
)

if "%3"=="no-clean" goto end
pause
:cleanup

del /f /q %SGXSSL_ROOT%\package\include\openssl\*

del /f /q %SGXSSL_ROOT%\package\lib\x64\Debug\*
del /f /q %SGXSSL_ROOT%\package\lib\x64\Release\*
del /f /q %SGXSSL_ROOT%\package\lib\Win32\Debug\*
del /f /q %SGXSSL_ROOT%\package\lib\Win32\Release\*


del /f /q %SGXSSL_SOLUTION%\libsgx_tsgxssl\tsgxssl_version.h

rmdir /s /q %SGXSSL_SOLUTION%\Win32
rmdir /s /q %SGXSSL_SOLUTION%\x64

rmdir /s /q %SGXSSL_SOLUTION%\libsgx_tsgxssl\Win32
rmdir /s /q %SGXSSL_SOLUTION%\libsgx_tsgxssl\x64

rmdir /s /q %SGXSSL_SOLUTION%\libsgx_usgxssl\Win32
rmdir /s /q %SGXSSL_SOLUTION%\libsgx_usgxssl\x64

rmdir /s /q %SGXSSL_SOLUTION%\app\Win32
rmdir /s /q %SGXSSL_SOLUTION%\app\x64

rmdir /s /q %SGXSSL_SOLUTION%\enclave\Win32
rmdir /s /q %SGXSSL_SOLUTION%\enclave\x64

:end

echo Script ended successfully!   %date% %time%

exit /b 0

:error
cd %SGXSSL_ROOT%
echo Script ended with error!   %date% %time%
pause
exit /b 1
