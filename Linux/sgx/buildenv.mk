#
# Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
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


# -----------------------------------------------------------------------------
# Function : parent-dir
# Arguments: 1: path
# Returns  : Parent dir or path of $1, with final separator removed.
# -----------------------------------------------------------------------------
parent-dir = $(patsubst %/,%,$(dir $(1:%/=%)))


# -----------------------------------------------------------------------------
# Macro    : my-dir
# Returns  : the directory of the current Makefile
# Usage    : $(my-dir)
# -----------------------------------------------------------------------------
my-dir = $(realpath $(call parent-dir,$(lastword $(MAKEFILE_LIST))))

ROOT_DIR	:= $(call my-dir)
export PACKAGE_LIB := $(ROOT_DIR)/../package/lib64/
export PACKAGE_INC := $(ROOT_DIR)/../package/include/
export TRUSTED_LIB_DIR := $(ROOT_DIR)/libsgx_tsgxssl/
export UNTRUSTED_LIB_DIR := $(ROOT_DIR)/libsgx_usgxssl/
export TEST_DIR := $(ROOT_DIR)/test_app/
export OS_ID=0
export LINUX_SGX_BUILD ?= 0
export TRUSTED_LIB := libsgx_tsgxssl.a
export UNTRUSTED_LIB := libsgx_usgxssl.a
export VCC := @$(CC)
export VCXX := @$(CXX)
export OBJDIR := release
DESTDIR ?= /opt/intel/sgxssl/
DEBUG ?= 0
$(shell mkdir -p $(PACKAGE_LIB))
UBUNTU_CONFNAME:=/usr/include/x86_64-linux-gnu/bits/confname.h
ifneq ("$(wildcard $(UBUNTU_CONFNAME))","")
	OS_ID=1
else
	OS_ID=2
endif
ifeq ($(DEBUG), 1)
	OBJDIR := debug
	OPENSSL_LIB := libsgx_tsgxssl_cryptod.a
	TRUSTED_LIB := libsgx_tsgxssld.a
	UNTRUSTED_LIB := libsgx_usgxssld.a
else
	OBJDIR := release
	OPENSSL_LIB := libsgx_tsgxssl_crypto.a
	TRUSTED_LIB := libsgx_tsgxssl.a
	UNTRUSTED_LIB := libsgx_usgxssl.a
endif

ifeq ($(VERBOSE),1)
      VCC=$(CC)
      VCXX=$(CXX)
else
      VCC=@$(CC)
      VCXX=@$(CXX)
endif
