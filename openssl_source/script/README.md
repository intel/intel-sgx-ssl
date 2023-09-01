SGX Mitigating LVI in OpenSSL
=============================


* [Introduction](#introduction)
* [Goal](#goal)
* [Prepare Process](#prepare-process)
    * [Use of .byte 0xf3,0xc3 Instead of RET](#use-of-byte-0xf30xc3-instead-of-ret)
* [Approach 1: Distinguish Constant Directives](#approach-1-distinguish-constant-directives)
* [Approach 2: Do Not Distinguish Constant Directives](#approach-2-do-not-distinguish-constant-directives)
* [Appendix: Assembly Files](#appendix-assembly-files)

Introduction
------------

With either approach below, disassembly of the unmitigated assembly
(object) code should be consulted at the end, to vet the manual addition
of any LFENCEs. [Both approaches below ultimately depend on the number
of LFENCEs that need to be manually added being manageable.]

Goal
----

Goal: Knowledge of where to *manually* add LFENCEs in assembly source
code that sometimes encodes instructions using constant directives.

For example, knowing that:
```
 .long 0x90A548F3
```
In the original assembly code should change to (for "load level" LVI
mitigation)
```
 .long 0x90A548F3

 lfence
```
Prepare Process
---------------

### Use of .byte 0xf3,0xc3 Instead of RET

Most assembly source files that OpenSSL uses are generated from perl
files/scripts. One such perl file is crypto\\perlasm\\x86_64-xlate.pl.
This file stands out because it generates .byte 0xf3,0xc3 instead of
RET[^1]. The process of mitigating LVI in OpenSSL includes manual steps.
Changing crypto\\perlasm\\x86_64-xlate.pl to generate
```
 nop
 rep ret
```
instead of
```
 .byte 0xf3,0xc3
```
makes the manual steps much easier. The rest of this document explains
why this is the case, including why the addition of a NOP.

### Starting from Scratch

It's clear that mitigating a given OpenSSL release should consider what,
if anything, of relevance is different in the release compared to the
last release that was mitigated. However, describing how to do this
can't be done without describing how to mitigate from scratch, which is
the purpose of this section. Furthermore, this document currently only
describes starting from scratch.

What's needed?

The following items are needed from the new/target OpenSSL release:

1.  crypto\\perlasm\\x86_64-xlate.pl, modified to generate NOP RET
    instead of .byte 0xf3,0xc3. Of course, this assumes that this perl
    file exists and generates .byte 0xf3,0xc3 in the first place.

2.  Original assembly source files. As noted above, these are, in
    general, generated from perl files. The easiest way to generate them
    is to simply build the SGX-related project that includes OpenSSL
    (eg, SGX SSL) without LVI mitigations but with the modified
    x86_64-xlate.pl described above.

3.  Output of Disassemble-2 step below.

4.  Disassembly of original assembly (object) code assembled w/o any
    modifications for LVI.

At a high level, the idea is to manually add the LFENCEs in item 3 to
item 2. Having item 4 lets you sanity check before adding. You could
also imagine a situation where the LVI changes break the build or cause
tests to fail. Having item 4 can also help in situations like this.

Approach 1: Distinguish Constant Directives
-------------------------------------------

|Manual Analysis|Construction|Assemble-1| Disassemble-1 |Assemble-2 | Disassemble-2 | Manual addition Test Build |
| ------------ | ------------ | ------------ | ------------ |------------ |------------ |------------ |
| Analyze assembly filles to distinguish constant directives that are encoding code/instructions from those that are specifying data. Basically, mark the constant directives specifying data. | Use the scripts to construct temp assembly files consisting of the constant-encoded instructions from the original assembly files. This step is done when all constant-encoded instructions are in their own assembly files. | Use the scripts basically to generate something that can be disassembled. It’s best NOT to have the build tools add LVI mitigations in this step. | Use the scripts. This helps effect a conversion from the original constant-encoded instructions to mnemonics. | Use the scripts. See Appendix: Do You Need Both load Level and CF Level LVI Mitigations? below. | These steps are for manual addition of LFENCEs to the original (generated) assembly files Use the scripts for Disassemble-2 step. Mitigations in the result of Disassemble-2 need to be manually added to the original (generated) assembly files.One approach for manually adding: the mnemonics of the instructions that need LFENCEs are in the Disassemble-2 output. You can search for these in the disassembly of the object files built without LVI mitigations. The disassembly will have the same instruction bytes for the constant-encoded instructions as the original assembly so you can search for them in the original assembly files. (This may require hex to dec conversion.) Then, you can know where to add the mitigations to the original assembly files. The instruction bytes in the Disassemble-2 output may be (and often are) different than those specified in the original assembly file, due to Intel mnemonic ambiguity (same mnemonic can be encoded in multiple ways). | Build and pay attention to the following assembler warnings: constant directive` skips -mlfence-before-indirect-branch on `jmp` `constant directive` skips -mlfence-before-indirect-branch on `call` `constant directive` skips -mlfence-before-ret on `ret` They may be indicating that NOPs need to added and where to add them. See Appendix: Do You Need Both load Level and CF Level LVI Mitigations? below. |


###### Problems with this approach

Manually distinguishing the constant directives, that is, the Manual
Analysis step is painful.

What happens if mistakes are made during Manual Analysis?

------------------------------------------------------------------------------------
### **Case 1**: Mistakenly conclude data is being specified when it's really code 

The idea is to delete the data and keep the code, so with this type of
mistake, we might "process" less than we should and miss some LFENCEs.

###### Possibility of feedback/detection

There's no inherent "feedback" with this type of mistake.

-------------------------------------------------------------------------------------
### **Case 2**: Mistakenly conclude code is being specified when it's really data 

This is bad because, in general, it will cause the rest of the assembly
file (in Assemble-1 step) to be out of sync.

###### Possibility of feedback/detection

There's a good chance of feedback, either the assembly files in
Assemble-1 step may fail to assemble or the results of the Disassemble-2
step (which have to analyzed anyway) may be obviously wrong upon (human)
inspection. The likelihood of the latter would seem to increase the
earlier in a file the first mistake of this type is made.

-------------------------------------------------------------------------
### Case 3: Wrong treatment of constant-encoded prefixes (and similar) 

The following is from an OpenSSL assembly file
(crypto\\bn\\asm\\x86_64-mont5.s):
```
 movdqa %xmm1,%xmm4
 .byte 0x67
 movdqa %xmm1,%xmm2
 .byte 0x67
 paddd %xmm0,%xmm1
```
With such code and with this approach, we would end with the following
in the temp assembly file:
```
 <nops and constant directives specifying code earlier in the original
 (generated) assembly file (not shown above)\>
 .byte 0x67
 .byte 0x67
 <nops and constant directives specifying code later in the original
 (generated) assembly file (not shown above)\>
```
Would this cause a problem? I don't know. It's tempting to say that if
it does cause a problem, then the situation is hopeless since it would
suggest that constants and mnemonics are somehow being combined in
OpenSSL assembly files to encode instructions, beyond prefixing. A more
specific question: could what are clearly intended to be treated as
prefixes (0x67) be treated incorrectly if they get separated from their
instructions (as above)?

###### Possibility of feedback/detection

No if we delete such "prefixes" (or comment them out) before the
Assemble-1 step, that is, during Manual Analysis.

Yes if we keep them.

This is one case where I let the Assemble-1 step feedback into the
Manual Analysis step, along the lines of not doing anything for
constant-encoded instruction prefixes unless not doing anything causes
Assemble-1 step to fail. In this case, go back and comment out the
offending prefix.

--------------------------------------------------------------
### Case 4: Using RET or NOP RET Instead of .byte 0xf3,0xc3 


As stated above,

1.  building OpenSSL normally includes perl scripts generating assembly
    source files.

2.  these assembly files containing some amount of constant-encoded
    instructions.

3.  the constant-encoded instructions including 0xf3,0xc3 for REP RET

The Prepare Process has several options here:

|Option|Pros|Pros|
| ------------ | ------------ | ------------ |
|don’t affect the generation of the assembly | files, that is, don’t change the perl scripts | Don’t have to worry about any perl files changing. Have to manually add the corresponding mitigations to the assembly files|
|change the perl scripts to generate REP RET|Don’t have to manually add the corresponding mitigations to the assembly files except in cases where OpenSSL would normally generate a constant directive immediately followed by .byte 0xf3,0xc3. This case is relatively common.|Have to manually add some of the corresponding mitigations to the assembly files.|
|change the perl scripts to generate RET|Same as directly above|Same as directly above Removing the REP will break things if an exceedingly rare constant directive pattern is present – see directly below.|
|change the perl scripts to generate NOP REP RET|Don’t have to manually add the corresponding mitigations to the assembly files, that is, allows assembler to mitigate the case where OpenSSL would normally generate a constant directive immediately followed by .byte 0xf3,0xc3. The assembler won’t mitigate .byte 0xf3,0xc3 Since the assembler needs mnemonics. The assembler won’t mitigate <constant directive> REP RET Since the assembler doesn’t know if the constant directive applies to the RET. The assembler will mitigate <constant directive> NOP REP RET But, if the constant directive really is associated with the REP RET, then the assembler-added mitigation as well as the NOP may break the code.|Could break code in cases where OpenSSL would normally generate a constant directive immediately followed by .byte 0xf3,0xc3 AND the constant directive is somehow associated with the .byte 0xf3,0xc3, that is: <constant directive> .byte 0xf3,0xc3 And what if the two directives together were intended to encode a different instruction or different instructions? In this case, you can’t change either directive or insert anything between the two directives, which is exactly what this option does. This pattern is not known to exist. If in doubt, the disassembly of the object code corresponding to untouched perl/assembly files will show whether this exceedingly rare pattern existed.|
|change the perl scripts to generate NOP RET|Analogous to directly above|Same as directly above|

### Manual Addition of LFENCEs
---------------------------------
How do you know where to add the LFENCEs in the output of the
Disassemble-2 step to the original (generated) assembly files?

The output of the Disassemble-2 step consists of mnemonics and, in cases
where the instructions are vulnerable to LVI, LFENCEs.

So how do you know where to put the LFENCEs? One way is to convey the
line number of the line with the constant directive so that it
survives/is preserved across assembly and subsequent disassembly.

###### Original

```
340: .byte 243,15,30,250
341: movq %rsp,%rax
```
###### Option 1

convey the line number in an immediate operand
(after something identifiable)
```
n: .byte 243,15,30,250
n+1: mov \$511233000**340**, %r9
```
The scripts don't currently process any files line by line so [this
option is on hold]

###### Option 2:

add nops to keep the line number of the line
with the mnemonic corresponding to the directive close to the line
number of the line with the directive in the original assembly file.
```
~1: nop
~2: nop
...
~339: nop
~340: \<mnemonic for some constant-encoded instruction\>
```
As of this writing, [this is what we do]. The line numbers of the
mnemonics won't exactly match the line numbers of the original constant
directives but they should be close.

The scripts also currently cause labels of functions to be preserved,
which also provides valuable context. For example, you can see something
like the following in the Disassemble-2 output:
```
 95: nop
 96: nop
 97: nop
 98: shlq \$0x0,(%rsp)
 9d: lfence
 a0: repz ret
 a2: nop
 a3: nop
 00000000000000a4 \<prepare\_x86_64_AES_encrypt_compact\>:
 a4: nop
 a5: nop
 a6: nop
```
This tells you that there was a constant-encoded instruction close to
and before a function named \_x86_64_AES_encrypt_compact (the scripts
add "prepare\_"). This is in addition to the line numbers being close as
described above.

Approach 2: Do Not Distinguish Constant Directives
--------------------------------------------------

Approach 2 becomes an exercise in figuring out how to assemble
disassembly output -- Assemble-2 step below. This is challenging beyond
the ambiguity of Intel instruction mnemonics. As of this writing (August
23, 2023), this approach is not being pursued.


|Manual analysis |Construction|Assemble-1| Disassemble-1 |Assemble-2 | Disassemble-2 Manual addition of LFENCEs to the original (generated) assembly files |
| ------------ | ------------ | ------------ | ------------ |------------ |------------ |
| ~~Analyze assembly filles to distinguish constant directives that are encoding code/instructions from those that are specifying data. Basically, mark the directives specifying data.~~ | ~~Use script to construct temp assembly files consisting of the constant-encoded instructions from the original assembly files.This step is done when all constant-encoded instructions are in their own assembly files, that is, all the constant-encoded instructions in foo.s go into foo_const_enc_instrs.s.~~ | Basically to generate something that can be disassembled. It’s best NOT to have the build tools add LVI mitigations in this step. | This helps effect a conversion from the original constant-encoded instructions to mnemonics, which the LVI mitigation-aware tools need. | For reasons that I won’t go into here, you effectively want two sub-steps here, one where you apply CF level mitigations and one where you apply full mitigations. Then, add both sets of LFENCEs to the original (generated) assembly files. | Some of the LFENCEs in the result of Disassemble-2 need to be manually added to the original (generated) assembly files. Suggestion: put original assembly file and the output of disassemble-2 step side-by-side. If should be fairly easy to determine which LFENCEs need to be added and where.|

### Manual Addition of LFENCEs


Suggestion: put original assembly file and the output of disassemble-2
step side-by-side. If should be fairly easy to determine which LFENCEs
need to be added and where.

The output of the Disassemble-2 step consists of mnemonics and, in cases
where the instructions are vulnerable to LVI, LFENCEs. Disassembler
output also typically includes assembler output.

How exactly do you know which LFENCEs to add and where? Remember, with
this approach, the Assemble-2 step adds LFENCEs due to all vulnerable
instructions in the original assembly, not just the constant-encoded
instructions. In the side by side comparison, line numbers and mnemonics
should correlate pretty well giving an indication both of which LFENCEs
to add and where. Note that the difference in line numbers will increase
proportionally with the number of LFENCEs added.

### First Steps for a New OpenSSL Release

It should come as no surprise that diffs are involved when changing to a
new OpenSSL release. Specifically, we care about changes to
crypto\\perlasm\\x86_64-xlate.pl and we care about changes to the
assembly files. Diffing the assembly files is a bit of a pain since
they're generated. An alternative is to compare the generating perl
files. I think it's a judgment call. For example, an approach like this
could work: if there are changes to the perl files (other than
crypto\\perlasm\\x86_64-xlate.pl, which we treat separately), then
proceed to diff the assembly files. Regardless, once the diff is done,
it's also a judgment call whether to resort to Starting from Scratch.

Appendix: Assembly Files
------------------------

This the assembly files list that SGX SSL uses from OpenSSL release
3.0.10 ([openssl/openssl at openssl-3.0.10
(github.com)](https://github.com/openssl/openssl/tree/openssl-3.0.10))
along with some information that was helpful during the Prepare Process
for 3.0.10-based SGX SSL.

|    | Common, OE and SGX SSL | Unexplained diffs in OE files?|
| ------------ | ------------ | ------------ |
|crypto\aes\aesni-mb-x86_64.s | y | n |
|crypto\aes\aesni-sha1-x86_64.s | y | n |
|crypto\aes\aesni-sha256-x86_64.s | y | n |
|crypto\aes\aes-x86_64.s | y | n |
|crypto\aes\bsaes-x86_64.s | y | n |
|crypto\aes\aesni-x86_64.s | y | y |
|crypto\aes\vpaes-x86_64.s | y | y |
|crypto\bn\rsaz-avx2.s | y | n |
|crypto\bn\rsaz-x86_64.s | y | n |
|crypto\bn\x86_64-gf2m.s | y | n |
|crypto\bn\x86_64-mont.s | y | n |
|crypto\bn\x86_64-mont5.s | y | n |
|crypto\ec\ecp_nistz256-x86_64.s | y | n |
|crypto\ec\x25519-x86_64.s | y | n |
|crypto\md5\md5-x86_64.s | y | n |
|crypto\modes\aesni-gcm-x86_64.s | y | n |
|crypto\modes\ghash-x86_64.s | y | n |
|crypto\sha\keccak1600-x86_64.s | y | n |
|crypto\sha\sha1-mb-x86_64.s | y | n |
|crypto\sha\sha1-x86_64.s | y | n |
|crypto\sha\sha256-mb-x86_64.s | y | n |
|crypto\sha\sha256-x86_64.s | y | n |
|crypto\sha\sha512-x86_64.s | y | n |
|crypto\x86_64cpuid.s | y | y |
|crypto\bn\rsaz-avx512.s | N | n.a. |
|crypto\chacha\chacha-x86_64.s | N | n.a. |
|crypto\poly1305\poly1305-x86_64.s | N | n.a. |
|crypto\whrlpool\wp-x86_64.s | N | n.a. |
