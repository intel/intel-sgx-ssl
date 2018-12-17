Intel® Software Guard Extensions SSL
================================================

Introduction
------------
The Intel® Software Guard Extensions SSL (Intel® SGX SSL) cryptographic library is intended to provide cryptographic services for Intel® Software Guard Extensions (SGX) enclave applications.
The Intel® SGX SSL cryptographic library is based on the underlying OpenSSL* Open Source project, providing a full-strength general purpose cryptography library.
Supported OpenSSL version is 1.1.1*. To work with 1.1.0 version please use "openssl_1.1.0" branch.

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
- Microsoft Visual Studio 2015.
- 7-Zip
- Perl
- NASM (Netwide Assembler)
- Intel(R) SGX SDK.
- Intel(R) SGX PSW.
- Intel(R) SGX driver.
(Note: 7-Zip, Perl, NASM need to be included in machine's PATH variable)

To build Intel® SGX SSL package in Windows OS:
1. Download OpenSSL package into openssl_source/ directory. (tar.gz package, e.g. openssl-1.1.1.tar.gz)
2. Download and install latest SGX SDK from [Intel Developer Zone](https://software.intel.com/en-us/sgx-sdk/download). You can find installation guide from the same website.
3. Change the directory to the SGXSSL path and enter the following command:
```
build_all.cmd <OPENSSL_VERSION> [default == openssl-1.1.1]
```
This will build the Intel® SGX SSL libraries (libsgx_tsgxssl.lib, libsgx_usgxssl.lib, libsgx_tsgxssl_crypto.lib), which can be found in package/lib/{Win32|X64}/{debug|release}/.

Linux
----------------------------
### Prerequisites
- Perl
- Intel(R) SGX SDK.
- Intel(R) SGX PSW.
- Intel(R) SGX driver.

To build Intel® SGX SSL package in Linux OS:
1. Download OpenSSL 1.1.1* package into openssl_source/ directory. (tar.gz package, e.g. openssl-1.1.1a.tar.gz)
2. Download and install latest SGX SDK from [01.org](https://01.org/intel-software-guard-extensions/downloads). You can find installation guide in the same website.
3. Source SGX SDK's environment variables.
4. Cd to Linux/ directory and run:
```
make all test
```
This will build and test the Intel® SGX SSL libraries (libsgx_tsgxssl.a, libsgx_usgxssl.a, libsgx_tsgxssl_crypto.a), which can be found in package/lib64/.

### Available `make` flags:
- DEBUG={1,0}: Libraries build mode, with debug symbols or without.
- SGX_MODE={HW,SIM}: SGX feature mode. Hardware/Simulation
- DESTDIR=\<PATH\>: Directory realpath to install Intel® SGX SSL libraries in. Default /opt/intel/sgxssl/
- VERBOSE={1,0}: Makefile verbose mode. Print compilation commands before executing it.

To install Intel® SGX SSL libraries in Linux OS, run:
```
make all test
sudo make install
```

