[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/intel/intel-sgx-ssl/badge)](https://securityscorecards.dev/viewer/?uri=github.com/intel/intel-sgx-ssl)

Intel® Software Guard Extensions SSL
================================================

Introduction
------------
The Intel® Software Guard Extensions SSL (Intel® SGX SSL) cryptographic library is intended to provide cryptographic services for Intel® Software Guard Extensions (SGX) enclave applications.
The Intel® SGX SSL cryptographic library is based on the underlying OpenSSL* Open Source project, providing a full-strength general purpose cryptography library.

This branch supports OpenSSL version 3.0.*, but works in 1.1.1 compatible mode.

License
-------
See [License.txt](License.txt) for details.

Documentation
-------
- For details on library architecture: [Architecture overview](Intel(R)%20Software%20Guard%20Extensions%20SSL%20Library%20Architecture.pdf)
- For details on using the libraries, please refer to the:
  * [Linux developer guide](Linux/package/docs/Intel(R)%20Software%20Guard%20Extensions%20SSL%20Library%20Linux%20Developer%20Guide.pdf)
  * [Windows developer guide](Windows/package/docs/Intel(R)%20Software%20Guard%20Extensions%20SSL%20Library%20Windows%20Developer%20Guide.pdf)


Build Intel® SGX SSL package
----------------------------
Windows
----------------------------
### Prerequisites
- Microsoft Visual Studio 2019
- Perl
- NASM (Netwide Assembler)
- Intel(R) SGX Windows latest release, including SDK, PSW, and driver

 (Note: Perl, NASM need to be included in machine's PATH variable)

To build Intel® SGX SSL package in Windows OS:
1. Download OpenSSL package into openssl_source/ directory. (tar.gz package, e.g. openssl-3.0.*.tar.gz)
2. Download and install latest SGX SDK from [Intel Developer Zone](https://software.intel.com/en-us/sgx-sdk/download). You can find installation guide from the same website.
3. Change the directory to the SGXSSL path and enter the following command:
```
build_all.cmd <OPENSSL_VERSION> [default == openssl-3.2.0]
```
This will build the Intel® SGX SSL libraries (libsgx_tsgxssl.lib, libsgx_usgxssl.lib, libsgx_tsgxssl_crypto.lib), which can be found in package/lib/{Win32|X64}/{debug|release}/. And the version with CVE-2020-0551 Mitigation enabled can be found in package/lib/X64/{CVE-2020-0551-CF-Release|CVE-2020-0551-Load-Release}/.

Linux
----------------------------
### Prerequisites
- Perl
- Toolchain with mitigation (refer to [SGX Linux README](https://github.com/intel/linux-sgx/blob/master/README.md))
- Intel(R) SGX Linux latest release, including SDK, PSW, and driver

To build Intel® SGX SSL package in Linux OS:
1. Download OpenSSL 3.2.* package into openssl_source/ directory. (tar.gz package, e.g. openssl-3.2.*.tar.gz)
2. Download and install latest SGX SDK from [01.org](https://download.01.org/intel-sgx/latest/). You can find installation guide in the same website.
3. Source SGX SDK's environment variables.
4. Cd to Linux/ directory and run:
```
make all test
```
This will build and test the Intel® SGX SSL libraries (libsgx_tsgxssl.a, libsgx_usgxssl.a, libsgx_tsgxssl_crypto.a), which can be found in package/lib64/. And the Intel® SGX SSL trusted libraries (libsgx_tsgxssl.lib,  libsgx_tsgxssl_crypto.lib) with CVE-2020-0551 Mitigation enabled can be found in package/lib64/{cve_2020_0551_cf|cve_2020_0551_load}/.

### Available `make` flags:
- DEBUG={1,0}: Libraries build mode, with debug symbols or without. Default ``0``.
- NO_THREADS={1,0}: Enable ``no-threads`` in the OpenSSL's build configuration options. Default ``0``.
- SGX_MODE={HW,SIM}: User can take ``SIM`` to run the unit test on non-SGX platform if necessary. Default ``HW``. 
- DESTDIR=\<PATH\>: Directory realpath to install Intel® SGX SSL libraries in. Default ``/opt/intel/sgxssl/``. 
- VERBOSE={1,0}: Makefile verbose mode. Print compilation commands before executing it. Default ``0``.
- OSSL3ONLY={1,0}: USE only OpenSSL 3.x APIs, and legacy functions will not be valid. Default ``0``.

To install Intel® SGX SSL libraries in Linux OS, run:
```
make all test
sudo make install
```

Note for Version 3.*
--------------------
To use the trusted cryptography library with SGX SSL/OpenSSL 3.*, it possibly needs to increase the value in the enclave signing configuration XML file:
```
...
<HeapMaxSize>...</HeapMaxSize>
...
```
, especially for the enclave with multithreads. 
