The Intel® Software Guard Extensions SSL (Intel® SGX SSL) cryptographic library is intended to provide cryptographic services for Intel® Software Guard Extensions (SGX) enclave applications.
The Intel® SGX SSL cryptographic library is based on the underlying OpenSSL* Open Source project, providing a full-strength general purpose cryptography library.

The API exposed by the Intel® SGX SSL library is fully compliant with unmodified OpenSSL APIs.

In order to build an Intel® SGX SSL package, follow the below steps:
	1. Download OpenSSL package into openssl_source/ directory. (tar.gz package, e.g. openssl-1.1.0e.tar.gz)
	2. Update the OPENSSL_VERSION veriable in build_sgxssl.sh to the version number of the downloaded OpenSSL.
        3. Download and install latest SGX SDK from [01.org](https://01.org/intel-software-guard-extensions/downloads). You can find installation guide from the same website.
        4. Update the SGX_SDK_PATH variable to the path where SGX SDK is installed in build_sgxssl.sh.
	5. Run build_sgxssl.sh.

This will create the Intel® SGX SSL libraries (libsgx_tsgxssl_crypto.a, libsgx_tsgxssl.a, libsgx_usgxssl.a), which can be found in package/lib64/{debug|release}/.

For more details on using the libraries, please refer to the developer guide under [package/docs](https://github.com/01org/intel-sgx-ssl/blob/master/package/docs)
