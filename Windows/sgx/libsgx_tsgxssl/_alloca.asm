;
; Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions
; are met:
;
;   * Redistributions of source code must retain the above copyright
;     notice, this list of conditions and the following disclaimer.
;   * Redistributions in binary form must reproduce the above copyright
;     notice, this list of conditions and the following disclaimer in
;     the documentation and/or other materials provided with the
;     distribution.
;   * Neither the name of Intel Corporation nor the names of its
;     contributors may be used to endorse or promote products derived
;     from this software without specific prior written permission.
;
; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
; "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
; LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
; A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
; OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
; SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
; LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
; DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
; THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
; (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
; OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;
;

;
; File: alloca.asm
; Description:
;     The file provides __alloca_probe, __alloca_probe_16 functions
;     Entry: eax = size of space need to alloca
;     Exit: eax = ponit to the space on stack
;

ifdef _WIN32

    .686P
    .XMM
    .model flat

EXTERN __chkstk : PROC

_TEXT SEGMENT

PUBLIC __alloca_probe_16

sgxssl___alloca_probe PROC
__alloca16:					;16 bit align alloca 
__alloca_probe_16 = __alloca16
    push 	eax				;store the eax into stack
    						;eax = eax - 4
    lea 	eax, [esp + 8]			;the TOP before enter into this function
    						;[esp + 0 * SE_WORDSIZE] = eax, the memory size need to allocate
    						;[esp + 1 * SE_WORDSIZE] = the return address of this function
    sub		eax, [esp]			;eax = top of stack after memory allocated
    and 	eax, 0FH			;16 bytes align
    add 	eax, [esp]			;increase allocation size, 
    						;eax = the final size need to allocate

    ;check if CF is set
    jnc		_out				;if CF=0 do nothing
    or 		eax, 0FFFFFFFFH			;set eax = 0xFFFFFFF if size wrapped around
    
_out:
    add 	esp, 4				;pop eax
    jmp 	__chkstk
    
sgxssl___alloca_probe ENDP

_TEXT ENDS

endif

END

