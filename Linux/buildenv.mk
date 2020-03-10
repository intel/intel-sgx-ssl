
# Mitigation options
MITIGATION-CVE-2020-0551 ?= NONE
MITIGATION_INDIRECT ?= 0
MITIGATION_RET ?= 0
MITIGATION_AFTERLOAD ?= 0
MITIGATION_LIB_PATH :=

ifeq ($(MITIGATION-CVE-2020-0551), LOAD)
    MITIGATION_INDIRECT := 1
    MITIGATION_RET := 1
    MITIGATION_AFTERLOAD := 1
    MITIGATION_LIB_PATH := cve_2020_0551_load
else ifeq ($(MITIGATION-CVE-2020-0551), CF)
    MITIGATION_INDIRECT := 1
    MITIGATION_RET := 1
    MITIGATION_AFTERLOAD := 0
    MITIGATION_LIB_PATH := cve_2020_0551_cf
else
    MITIGATION-CVE-2020-0551 :=
    MITIGATION_LIB_PATH :=
endif

MITIGATION_CFLAGS :=
MITIGATION_ASFLAGS :=

ifeq ($(MITIGATION_INDIRECT), 1)
    MITIGATION_CFLAGS += -mindirect-branch=thunk-extern -Wa,-mlfence-before-indirect-branch=register
    MITIGATION_ASFLAGS += -mlfence-before-indirect-branch=register
endif

ifeq ($(MITIGATION_RET), 1)
    MITIGATION_CFLAGS += -mfunction-return=thunk-extern -Wa,-mlfence-before-ret=not
    MITIGATION_ASFLAGS += -mlfence-before-ret=not
endif

ifeq ($(MITIGATION_AFTERLOAD), 1)
    MITIGATION_CFLAGS += -Wa,-mlfence-after-load=yes
    MITIGATION_ASFLAGS += -mlfence-after-load=yes
endif

