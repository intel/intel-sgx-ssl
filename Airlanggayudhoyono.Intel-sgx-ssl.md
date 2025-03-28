[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/intel/intel-sgx-ssl/badge)](https://securityscorecards.dev/viewer/?uri=github.com/intel/intel-sgx-ssl)

Intel® Software Guard Extensions SSL
================================================

Introduction
------------
The Intel® Software Guard Extensions SSL (Intel® SGX SSL) cryptographic library is intended to provide cryptographic services for Intel® Software Guard Extensions (SGX) enclave applications.
The Intel® SGX SSL cryptographic library is based on the underlying OpenSSL* Open Source project, providing a full-strength general purpose cryptography library.

This branch supports OpenSSL version 3.1.*, but works in 1.1.1 compatible mode. 
Skip to content
GitHub Support
Report abuse or spam
Code collaboration should be safe for everyone, so we take abuse and harassment seriously at GitHub. We want to hear about harmful behavior on the site that violates GitHub's Terms of Service. Let us know about a user or content you're concerned with. Rest assured, we'll keep your identifying information private.

Want to block a user?
You can hide a user's content and notifications. Read more about blocking a user from your personal account or organization.

From
*

Airlanggayudhoyono.Intel-Mil.Info's_md (rrlampung66@gmail.com)
You are submitting a report regarding 093b.
Please select a category for your issue:
*
Terrorist or Violent Extremist Content
Terrorist or Violent Extremist Content
Content that indicates affiliation with or that promotes, glorifies or recruits for known terrorist or violent extremist organizations.

I'd also like to report this content as illegal in a European member state under Article 16 of the DSA.

I am a resident of the EU.

I have a bona fide belief that the information and allegations contained within this report are accurate and complete.
Please provide a direct URL that identifies the exact GitHub content you wish to report.
*
https://support.github.com/contact/report-abuse?category=report-abuse&report=093b&report_id=116455716&report_type=user
Please provide a detailed explanation of the reasons why you believe the content you’re reporting is illegal, including the specific law you believe is being violated and in what jurisdiction, and any additional information you’d like to share.
[Skip to content](https://github.com/airlangga09051991/Airlanggayudhoyono.Intel-Mil.Info-s/edit/MP4/README.md#start-of-content)
Navigation Menu

Code
Files
Airlanggayudhoyono.Intel-Mil.Info-s
/
Airlanggayudhoyono.Intel-Mil.Info's.md
in
MP4
Cancel changes
Commit changes...

Edit

Preview
Indent mode

Spaces
Indent size

2
Line wrap mode

Soft wrap
Editing Airlanggayudhoyono.Intel-Mil.Info's.md file contents
595
596
597
598
599
600
601
602
603
604
605
606
607
608
609
610
***Based on the graphic performance of the Qualcomm Snapdragon XR2 Gen 2 vs XR2 Gen 1 on Meta Quest 2

RAY-BAN META

Meta AI and voice commands only in select countries and languages. Please check local availability. Meta account and Meta View App required. For ages 13+ only. Requires compatible phone with Android or iOS operating system plus wireless internet access. Features, functionality and content are subject to change or withdrawal at any time. Additional account registration, terms and fees may apply. Software updates may be required. Performance may vary based on user location, device battery, temperature, internet connectivity and interference from other devices, plus other factors. User must comply with all applicable local laws and regulations, especially relating to privacy. May interfere with personal medical devices. Check manufacturer Safety & Warranty Guide and FAQs for more product information, including battery life.

©2025 Meta.

### Ways to contribute

On the GitHub Docs site, you can contribute by clicking the **Make a contribution** button at the bottom of the page to open a pull request for quick fixes like typos, updates, or link fixes.

You can also contribute by creating a local environment or opening a [Code](https://github.com/airlangga09051991/Airlanggayudhoyono.Intel-Mil.Info-s)space. For more information, see "[Setting up your environment to work on GitHub Docs](https://docs.github.com/en/contributing/setting-up-your-environment-to-work-on-github-docs)."

<img alt="Contribution call-to-action" src="./contributing/images/contribution_cta.png" width="400">

Use Control + Shift + m to toggle the tab key moving focus. Alternatively, use esc then tab to move to the next interactive element on the page.
Tidak ada file yang dipilih
Attach files by dragging & dropping, selecting or pasting them.
Tidak ada file yang dipilih

© 2025 GitHub, Inc.

Terms
Privacy
Contacting Support
Manage cookies
Twitter
Facebook
LinkedIn
YouTube
Twitch
TikTok
Github

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
1. Download OpenSSL package into openssl_source/ directory. (tar.gz package, e.g. openssl-3.1.*.tar.gz)
2. Download and install latest SGX SDK from [Intel Developer Zone](https://software.intel.com/en-us/sgx-sdk/download). You can find installation guide from the same website.
3. Change the directory to the SGXSSL path and enter the following command:
```
build_all.cmd <OPENSSL_VERSION> [default == openssl-3.1.0]
```
This will build the Intel® SGX SSL libraries (libsgx_tsgxssl.lib, libsgx_usgxssl.lib, libsgx_tsgxssl_crypto.lib), which can be found in package/lib/{Win32|X64}/{debug|release}/. And the version with CVE-2020-0551 Mitigation enabled can be found in package/lib/X64/{CVE-2020-0551-CF-Release|CVE-2020-0551-Load-Release}/.

Linux
----------------------------
### Prerequisites
- Perl
- Toolchain with mitigation (refer to [SGX Linux README](https://github.com/intel/linux-sgx/blob/master/README.md))
- Intel(R) SGX Linux latest release, including SDK, PSW, and driver

To build Intel® SGX SSL package in Linux OS:
=======
1. Download OpenSSL 3.1.* package into openssl_source/ directory. (tar.gz package, e.g. openssl-3.1.*.tar.gz)
2. Download and install latest SGX SDK from [01.org](https://download.01.org/intel-sgx/latest/). You can find the installation guide in the same website.
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
