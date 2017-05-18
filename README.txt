The Intel® SgxSSL cryptographic library is intended to provide cryptographic services for Intel® Software Guard Extensions (SGX) enclave applications.
The Intel® SgxSSL cryptographic library is based on the underlying OpenSSL* Open Source project, providing a full-strength 
general purpose cryptography library.
The API exposed by the Intel® SgxSSL library is fully compliant with unmodified OpenSSL APIs.

In order to build an SGXSSL package, follow the below steps:
	1. Download OpenSSL package into openssl_source/ directory. (tar.gz package, e.g. openssl-1.1.0e.tar.gz)
	2. Update version number in build script build_sgxssl.sh. (OPENSSL_VERSION=)
	3. Run buildsgxssl.sh.

This will create the SGXSSL libraries (libsgx_tsgxssl_crypto.a, libsgx_tsgxssl.a, libsgx_usgxssl.a), which can be found in package/lib64/{debug|release}/.
