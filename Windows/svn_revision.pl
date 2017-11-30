#!/usr/intel/bin/perl

## 
## Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
## 
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions
## are met:
## 
##   * Redistributions of source code must retain the above copyright
##     notice, this list of conditions and the following disclaimer.
##   * Redistributions in binary form must reproduce the above copyright
##     notice, this list of conditions and the following disclaimer in
##     the documentation and/or other materials provided with the
##     distribution.
##   * Neither the name of Intel Corporation nor the names of its
##     contributors may be used to endorse or promote products derived
##     from this software without specific prior written permission.
## 
## THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
## "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
## LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
## A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
## OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
## SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
## LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
## DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
## THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
## (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
## OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
## 
## 
 
# svn_revision.pl
# generates tsgxssl_version.h file with the current SVN revision number
# uses SubWCRev.exe from Tortoise SVN bin directory to get the SVN revision number

my $result = `"c:/Program Files/TortoiseSVN/bin/SubWCRev.exe" .`;

# Split revision tool output to lines and take second line
my @result = split('\n',$result);
my $line = $result[1];

# Split second line to words and take revision value from last word
my @line = split(' ',$line);
my $version = $line[4];

# Generate header file like output
print "// auto generated file. do not add to SVN repository\n\n";

print "#ifndef __SGXSSL_VERSION_H__\n";
print "#define __SGXSSL_VERSION_H__\n\n";
print "#include <sys/cdefs.h>\n\n";

print "// revision ID field taken from SVN repository\n";
print "#define STRFILEVER \"1.8.100.";
print "$version\"\n\n";

print "#define SGX_SSL_VERSION_STR  __CONCAT(\"SGX_SSL_VERSION_\", \"1.8.100.\")\n\n";

print "#endif // __SGXSSL_VERSION_H__\n";

exit ($version)
