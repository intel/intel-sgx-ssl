Mitigating LVI in OpenSSL

Revision 0.51

August 28, 2023

# Table of Contents {#table-of-contents .TOC-Heading}

[Revision History
[3](#_Toc143512966)](file:///C:\Users\qiangfu1\Downloads\lvi-openssl3.0.docx#_Toc143512966)

[1 Introduction
[4](#introduction)](file:///C:\Users\qiangfu1\Downloads\lvi-openssl3.0.docx#_Toc143512967)

[2 Goal
[4](#goal)](file:///C:\Users\qiangfu1\Downloads\lvi-openssl3.0.docx#_Toc143512968)

[2.1 Prepare Process
[4](#prepare-process)](file:///C:\Users\qiangfu1\Downloads\lvi-openssl3.0.docx#_Toc143512969)

[2.1.1 Use of .byte 0xf3,0xc3 Instead of RET
[4](#use-of-.byte-0xf30xc3-instead-of-ret)](file:///C:\Users\qiangfu1\Downloads\lvi-openssl3.0.docx#_Toc143512970)

[2.1.2 Starting from Scratch
[5](#starting-from-scratch)](file:///C:\Users\qiangfu1\Downloads\lvi-openssl3.0.docx#_Toc143512971)

[2.1.3 First Steps for a New OpenSSL Release
[12](#first-steps-for-a-new-openssl-release)](file:///C:\Users\qiangfu1\Downloads\lvi-openssl3.0.docx#_Toc143512972)

[3 Appendix: Assembly Files
[13](#appendix-assembly-files)](file:///C:\Users\qiangfu1\Downloads\lvi-openssl3.0.docx#_Toc143512973)

[4 Appendix: Status August 20, 2023
[16](#appendix-status-august-20-2023)](file:///C:\Users\qiangfu1\Downloads\lvi-openssl3.0.docx#_Toc143512974)

[]{#_Toc143512966 .anchor}Revision History

+-----------+-------+-------------------------------------------------+
| Date      | Rev   | Description                                     |
|           | ision |                                                 |
+===========+=======+=================================================+
| 8/15/2023 | 0.3   |                                                 |
+-----------+-------+-------------------------------------------------+
| 8/21/2023 | 0.4   | Add info on NOP RET vs RET.                     |
|           |       |                                                 |
|           |       | Misc.                                           |
+-----------+-------+-------------------------------------------------+
| 8/23/2023 | 0.5   | Clean up                                        |
|           |       |                                                 |
|           |       | Correct details about original assembly's use   |
|           |       | of .byte 0xf3,0xc3.                             |
+-----------+-------+-------------------------------------------------+
| 8/28/2023 | 0.51  | Embed more files.                               |
+-----------+-------+-------------------------------------------------+

# Introduction

With either approach below, disassembly of the unmitigated assembly
(object) code should be consulted at the end, to vet the manual addition
of any LFENCEs. [Both approaches below ultimately depend on the number
of LFENCEs that need to be manually added being manageable.]{.mark}

# Goal

Goal: Knowledge of where to *manually* add LFENCEs in assembly source
code that sometimes encodes instructions using constant directives.

For example, knowing that:

> .long 0x90A548F3

In the original assembly code should change to (for "load level" LVI
mitigation)

> .long 0x90A548F3
>
> lfence

## Prepare Process

### Use of .byte 0xf3,0xc3 Instead of RET

Most assembly source files that OpenSSL uses are generated from perl
files/scripts. One such perl file is crypto\\perlasm\\x86_64-xlate.pl.
This file stands out because it generates .byte 0xf3,0xc3 instead of
RET[^1]. The process of mitigating LVI in OpenSSL includes manual steps.
Changing crypto\\perlasm\\x86_64-xlate.pl to generate

> nop
>
> rep ret

instead of

> .byte 0xf3,0xc3

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

#### Approach 1: Distinguish Constant Directives

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Time
  \-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--à\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--à\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--à\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--à
  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

+------------+------+------+------+------+------+------+-------------+
| Manual     | Cons | As   | D    | As   | D    | Ma   | Test Build  |
| Analysis   | truc | semb | isas | semb | isas | nual |             |
|            | tion | le-1 | semb | le-2 | semb | addi |             |
|            |      |      | le-1 |      | le-2 | tion |             |
+============+======+======+======+======+======+======+=============+
| Analyze    | Use  | Use  | Use  | Use  | T    |      | Build and   |
| assembly   | the  | the  | the  | the  | hese |      | pay         |
| filles to  | scr  | scr  | scri | scri | s    |      | attention   |
| d          | ipts | ipts | pts. | pts. | teps |      | to the      |
| istinguish | to   | b    | This | See  | are  |      | following   |
| constant   | c    | asic | h    | A    | for  |      | assembler   |
| directives | onst | ally | elps | ppen | ma   |      | warnings:   |
| that are   | ruct | to   | ef   | dix: | nual |      |             |
| encoding   | temp | gene | fect | Do   | addi |      | \`constant  |
| code/in    | asse | rate | a    | You  | tion |      | directive\` |
| structions | mbly | s    | co   | Need | of   |      | skips       |
| from those | f    | omet | nver | Both | LFE  |      | -mlfence-   |
| that are   | iles | hing | sion | load | NCEs |      | before-indi |
| specifying | co   | that | from | L    | to   |      | rect-branch |
| data.      | nsis | can  | the  | evel | the  |      | on \`jmp\`  |
| Basically, | ting | be   | orig | and  | orig |      |             |
| mark the   | of   | d    | inal | CF   | inal |      | \`constant  |
| constant   | the  | isas | cons | L    | (ge  |      | directive\` |
| directives | cons | semb | tant | evel | nera |      | skips       |
| specifying | tant | led. | -enc | LVI  | ted) |      | -mlfence-   |
| data.      | -enc | It's | oded | Miti | asse |      | before-indi |
|            | oded | best | inst | gati | mbly |      | rect-branch |
|            | inst | NOT  | ruct | ons? | f    |      | on \`call\` |
|            | ruct | to   | ions | be   | iles |      |             |
|            | ions | have | to   | low. | Use  |      | \`constant  |
|            | from | the  | mn   |      | the  |      | directive\` |
|            | the  | b    | emon |      | scr  |      | skips       |
|            | orig | uild | ics. |      | ipts |      | -mlfence    |
|            | inal | t    |      |      | for  |      | -before-ret |
|            | asse | ools |      |      | D    |      | on \`ret\`  |
|            | mbly | add  |      |      | isas |      |             |
|            | fi   | LVI  |      |      | semb |      | They may be |
|            | les. | mit  |      |      | le-2 |      | indicating  |
|            |      | igat |      |      | s    |      | that NOPs   |
|            | This | ions |      |      | tep. |      | need to     |
|            | step | in   |      |      | Mit  |      | added and   |
|            | is   | this |      |      | igat |      | where to    |
|            | done | s    |      |      | ions |      | add them.   |
|            | when | tep. |      |      | in   |      | See         |
|            | all  |      |      |      | the  |      | Appendix:   |
|            | cons |      |      |      | re   |      | Do You Need |
|            | tant |      |      |      | sult |      | Both load   |
|            | -enc |      |      |      | of   |      | Level and   |
|            | oded |      |      |      | D    |      | CF Level    |
|            | inst |      |      |      | isas |      | LVI         |
|            | ruct |      |      |      | semb |      | M           |
|            | ions |      |      |      | le-2 |      | itigations? |
|            | are  |      |      |      | need |      | below.      |
|            | in   |      |      |      | to   |      |             |
|            | t    |      |      |      | be   |      |             |
|            | heir |      |      |      | manu |      |             |
|            | own  |      |      |      | ally |      |             |
|            | asse |      |      |      | a    |      |             |
|            | mbly |      |      |      | dded |      |             |
|            | fi   |      |      |      | to   |      |             |
|            | les. |      |      |      | the  |      |             |
|            |      |      |      |      | orig |      |             |
|            |      |      |      |      | inal |      |             |
|            |      |      |      |      | (ge  |      |             |
|            |      |      |      |      | nera |      |             |
|            |      |      |      |      | ted) |      |             |
|            |      |      |      |      | asse |      |             |
|            |      |      |      |      | mbly |      |             |
|            |      |      |      |      | fi   |      |             |
|            |      |      |      |      | les. |      |             |
|            |      |      |      |      |      |      |             |
|            |      |      |      |      | One  |      |             |
|            |      |      |      |      | appr |      |             |
|            |      |      |      |      | oach |      |             |
|            |      |      |      |      | for  |      |             |
|            |      |      |      |      | manu |      |             |
|            |      |      |      |      | ally |      |             |
|            |      |      |      |      | add  |      |             |
|            |      |      |      |      | ing: |      |             |
|            |      |      |      |      | the  |      |             |
|            |      |      |      |      | m    |      |             |
|            |      |      |      |      | nemo |      |             |
|            |      |      |      |      | nics |      |             |
|            |      |      |      |      | of   |      |             |
|            |      |      |      |      | the  |      |             |
|            |      |      |      |      | inst |      |             |
|            |      |      |      |      | ruct |      |             |
|            |      |      |      |      | ions |      |             |
|            |      |      |      |      | that |      |             |
|            |      |      |      |      | need |      |             |
|            |      |      |      |      | LFE  |      |             |
|            |      |      |      |      | NCEs |      |             |
|            |      |      |      |      | are  |      |             |
|            |      |      |      |      | in   |      |             |
|            |      |      |      |      | the  |      |             |
|            |      |      |      |      | D    |      |             |
|            |      |      |      |      | isas |      |             |
|            |      |      |      |      | semb |      |             |
|            |      |      |      |      | le-2 |      |             |
|            |      |      |      |      | out  |      |             |
|            |      |      |      |      | put. |      |             |
|            |      |      |      |      | You  |      |             |
|            |      |      |      |      | can  |      |             |
|            |      |      |      |      | se   |      |             |
|            |      |      |      |      | arch |      |             |
|            |      |      |      |      | for  |      |             |
|            |      |      |      |      | t    |      |             |
|            |      |      |      |      | hese |      |             |
|            |      |      |      |      | in   |      |             |
|            |      |      |      |      | the  |      |             |
|            |      |      |      |      | dis  |      |             |
|            |      |      |      |      | asse |      |             |
|            |      |      |      |      | mbly |      |             |
|            |      |      |      |      | of   |      |             |
|            |      |      |      |      | the  |      |             |
|            |      |      |      |      | ob   |      |             |
|            |      |      |      |      | ject |      |             |
|            |      |      |      |      | f    |      |             |
|            |      |      |      |      | iles |      |             |
|            |      |      |      |      | b    |      |             |
|            |      |      |      |      | uilt |      |             |
|            |      |      |      |      | wit  |      |             |
|            |      |      |      |      | hout |      |             |
|            |      |      |      |      | LVI  |      |             |
|            |      |      |      |      | miti |      |             |
|            |      |      |      |      | gati |      |             |
|            |      |      |      |      | ons. |      |             |
|            |      |      |      |      | The  |      |             |
|            |      |      |      |      | dis  |      |             |
|            |      |      |      |      | asse |      |             |
|            |      |      |      |      | mbly |      |             |
|            |      |      |      |      | will |      |             |
|            |      |      |      |      | have |      |             |
|            |      |      |      |      | the  |      |             |
|            |      |      |      |      | same |      |             |
|            |      |      |      |      | ins  |      |             |
|            |      |      |      |      | truc |      |             |
|            |      |      |      |      | tion |      |             |
|            |      |      |      |      | b    |      |             |
|            |      |      |      |      | ytes |      |             |
|            |      |      |      |      | for  |      |             |
|            |      |      |      |      | the  |      |             |
|            |      |      |      |      | cons |      |             |
|            |      |      |      |      | tant |      |             |
|            |      |      |      |      | -enc |      |             |
|            |      |      |      |      | oded |      |             |
|            |      |      |      |      | inst |      |             |
|            |      |      |      |      | ruct |      |             |
|            |      |      |      |      | ions |      |             |
|            |      |      |      |      | as   |      |             |
|            |      |      |      |      | the  |      |             |
|            |      |      |      |      | orig |      |             |
|            |      |      |      |      | inal |      |             |
|            |      |      |      |      | asse |      |             |
|            |      |      |      |      | mbly |      |             |
|            |      |      |      |      | so   |      |             |
|            |      |      |      |      | you  |      |             |
|            |      |      |      |      | can  |      |             |
|            |      |      |      |      | se   |      |             |
|            |      |      |      |      | arch |      |             |
|            |      |      |      |      | for  |      |             |
|            |      |      |      |      | them |      |             |
|            |      |      |      |      | in   |      |             |
|            |      |      |      |      | the  |      |             |
|            |      |      |      |      | orig |      |             |
|            |      |      |      |      | inal |      |             |
|            |      |      |      |      | asse |      |             |
|            |      |      |      |      | mbly |      |             |
|            |      |      |      |      | fi   |      |             |
|            |      |      |      |      | les. |      |             |
|            |      |      |      |      | (    |      |             |
|            |      |      |      |      | This |      |             |
|            |      |      |      |      | may  |      |             |
|            |      |      |      |      | req  |      |             |
|            |      |      |      |      | uire |      |             |
|            |      |      |      |      | hex  |      |             |
|            |      |      |      |      | to   |      |             |
|            |      |      |      |      | dec  |      |             |
|            |      |      |      |      | conv |      |             |
|            |      |      |      |      | ersi |      |             |
|            |      |      |      |      | on.) |      |             |
|            |      |      |      |      | T    |      |             |
|            |      |      |      |      | hen, |      |             |
|            |      |      |      |      | you  |      |             |
|            |      |      |      |      | can  |      |             |
|            |      |      |      |      | know |      |             |
|            |      |      |      |      | w    |      |             |
|            |      |      |      |      | here |      |             |
|            |      |      |      |      | to   |      |             |
|            |      |      |      |      | add  |      |             |
|            |      |      |      |      | the  |      |             |
|            |      |      |      |      | mit  |      |             |
|            |      |      |      |      | igat |      |             |
|            |      |      |      |      | ions |      |             |
|            |      |      |      |      | to   |      |             |
|            |      |      |      |      | the  |      |             |
|            |      |      |      |      | orig |      |             |
|            |      |      |      |      | inal |      |             |
|            |      |      |      |      | asse |      |             |
|            |      |      |      |      | mbly |      |             |
|            |      |      |      |      | fi   |      |             |
|            |      |      |      |      | les. |      |             |
|            |      |      |      |      | The  |      |             |
|            |      |      |      |      | ins  |      |             |
|            |      |      |      |      | truc |      |             |
|            |      |      |      |      | tion |      |             |
|            |      |      |      |      | b    |      |             |
|            |      |      |      |      | ytes |      |             |
|            |      |      |      |      | in   |      |             |
|            |      |      |      |      | the  |      |             |
|            |      |      |      |      | D    |      |             |
|            |      |      |      |      | isas |      |             |
|            |      |      |      |      | semb |      |             |
|            |      |      |      |      | le-2 |      |             |
|            |      |      |      |      | ou   |      |             |
|            |      |      |      |      | tput |      |             |
|            |      |      |      |      | may  |      |             |
|            |      |      |      |      | be   |      |             |
|            |      |      |      |      | (and |      |             |
|            |      |      |      |      | o    |      |             |
|            |      |      |      |      | ften |      |             |
|            |      |      |      |      | are) |      |             |
|            |      |      |      |      | d    |      |             |
|            |      |      |      |      | iffe |      |             |
|            |      |      |      |      | rent |      |             |
|            |      |      |      |      | than |      |             |
|            |      |      |      |      | t    |      |             |
|            |      |      |      |      | hose |      |             |
|            |      |      |      |      | s    |      |             |
|            |      |      |      |      | peci |      |             |
|            |      |      |      |      | fied |      |             |
|            |      |      |      |      | in   |      |             |
|            |      |      |      |      | the  |      |             |
|            |      |      |      |      | orig |      |             |
|            |      |      |      |      | inal |      |             |
|            |      |      |      |      | asse |      |             |
|            |      |      |      |      | mbly |      |             |
|            |      |      |      |      | f    |      |             |
|            |      |      |      |      | ile, |      |             |
|            |      |      |      |      | due  |      |             |
|            |      |      |      |      | to   |      |             |
|            |      |      |      |      | I    |      |             |
|            |      |      |      |      | ntel |      |             |
|            |      |      |      |      | mnem |      |             |
|            |      |      |      |      | onic |      |             |
|            |      |      |      |      | a    |      |             |
|            |      |      |      |      | mbig |      |             |
|            |      |      |      |      | uity |      |             |
|            |      |      |      |      | (    |      |             |
|            |      |      |      |      | same |      |             |
|            |      |      |      |      | mnem |      |             |
|            |      |      |      |      | onic |      |             |
|            |      |      |      |      | can  |      |             |
|            |      |      |      |      | be   |      |             |
|            |      |      |      |      | enc  |      |             |
|            |      |      |      |      | oded |      |             |
|            |      |      |      |      | in   |      |             |
|            |      |      |      |      | mult |      |             |
|            |      |      |      |      | iple |      |             |
|            |      |      |      |      | wa   |      |             |
|            |      |      |      |      | ys). |      |             |
+------------+------+------+------+------+------+------+-------------+

##### Problems with this approach

Manually distinguishing the constant directives, that is, the Manual
Analysis step is painful.

What happens if mistakes are made during Manual Analysis?

###### **Case 1**: Mistakenly conclude data is being specified when it's really code  {#case-1-mistakenly-conclude-data-is-being-specified-when-its-really-code .unnumbered}

The idea is to delete the data and keep the code, so with this type of
mistake, we might "process" less than we should and miss some LFENCEs.

[Possibility of feedback/detection]{.underline}

There's no inherent "feedback" with this type of mistake.

###### **Case 2**: Mistakenly conclude code is being specified when it's really data {#case-2-mistakenly-conclude-code-is-being-specified-when-its-really-data .unnumbered}

This is bad because, in general, it will cause the rest of the assembly
file (in Assemble-1 step) to be out of sync.

[Possibility of feedback/detection]{.underline}

There's a good chance of feedback, either the assembly files in
Assemble-1 step may fail to assemble or the results of the Disassemble-2
step (which have to analyzed anyway) may be obviously wrong upon (human)
inspection. The likelihood of the latter would seem to increase the
earlier in a file the first mistake of this type is made.

###### Case 3: Wrong treatment of constant-encoded prefixes (and similar) {#case-3-wrong-treatment-of-constant-encoded-prefixes-and-similar .unnumbered}

The following is from an OpenSSL assembly file
(crypto\\bn\\asm\\x86_64-mont5.s):

> movdqa %xmm1,%xmm4
>
> .byte 0x67
>
> movdqa %xmm1,%xmm2
>
> .byte 0x67
>
> paddd %xmm0,%xmm1

With such code and with this approach, we would end with the following
in the temp assembly file:

> \<nops and constant directives specifying code earlier in the original
> (generated) assembly file (not shown above)\>
>
> .byte 0x67
>
> .byte 0x67
>
> \<nops and constant directives specifying code later in the original
> (generated) assembly file (not shown above)\>

Would this cause a problem? I don't know. It's tempting to say that if
it does cause a problem, then the situation is hopeless since it would
suggest that constants and mnemonics are somehow being combined in
OpenSSL assembly files to encode instructions, beyond prefixing. A more
specific question: could what are clearly intended to be treated as
prefixes (0x67) be treated incorrectly if they get separated from their
instructions (as above)?

[Possibility of feedback/detection]{.underline}

No if we delete such "prefixes" (or comment them out) before the
Assemble-1 step, that is, during Manual Analysis.

Yes if we keep them.

This is one case where I let the Assemble-1 step feedback into the
Manual Analysis step, along the lines of not doing anything for
constant-encoded instruction prefixes unless not doing anything causes
Assemble-1 step to fail. In this case, go back and comment out the
offending prefix.

###### Case 4: Using RET or NOP RET Instead of .byte 0xf3,0xc3 {#case-4-using-ret-or-nop-ret-instead-of-.byte-0xf30xc3 .unnumbered}

As stated above,

1.  building OpenSSL normally includes perl scripts generating assembly
    source files.

2.  these assembly files containing some amount of constant-encoded
    instructions.

3.  the constant-encoded instructions including 0xf3,0xc3 for REP RET

The Prepare Process has several options here:

+----------------------+-----------------------+-----------------------+
| Option               | Pros                  | Cons                  |
+======================+=======================+=======================+
| don't affect the     | Don't have to worry   | Have to manually add  |
| generation of the    | about any perl files  | the corresponding     |
| assembly files, that | changing.             | mitigations to the    |
| is, don't change the |                       | assembly files        |
| perl scripts         |                       |                       |
+----------------------+-----------------------+-----------------------+
| change the perl      | Don't have to         | Have to manually add  |
| scripts to generate  | manually add the      | *some of* the         |
| REP RET              | corresponding         | corresponding         |
|                      | mitigations to the    | mitigations to the    |
|                      | assembly files except | assembly files.       |
|                      | in cases where        |                       |
|                      | OpenSSL would         |                       |
|                      | normally generate a   |                       |
|                      | constant directive    |                       |
|                      | immediately followed  |                       |
|                      | by .byte 0xf3,0xc3.   |                       |
|                      | This case is          |                       |
|                      | relatively common.    |                       |
+----------------------+-----------------------+-----------------------+
| change the perl      | Same as directly      | Same as directly      |
| scripts to generate  | above                 | above                 |
| RET                  |                       |                       |
|                      |                       | Removing the REP will |
|                      |                       | break things if an    |
|                      |                       | exceedingly rare      |
|                      |                       | constant directive    |
|                      |                       | pattern is present -- |
|                      |                       | see directly below.   |
+----------------------+-----------------------+-----------------------+
| change the perl      | Don't have to         | Could break code in   |
| scripts to generate  | manually add the      | cases where OpenSSL   |
| NOP REP RET          | corresponding         | would normally        |
|                      | mitigations to the    | generate a constant   |
|                      | assembly files, that  | directive immediately |
|                      | is, allows assembler  | followed by .byte     |
|                      | to mitigate the case  | 0xf3,0xc3 AND the     |
|                      | where OpenSSL would   | constant directive is |
|                      | normally generate a   | somehow associated    |
|                      | constant directive    | with the .byte        |
|                      | immediately followed  | 0xf3,0xc3, that is:   |
|                      | by .byte 0xf3,0xc3.   |                       |
|                      | The assembler won't   | \<constant            |
|                      | mitigate              | directive\>           |
|                      |                       |                       |
|                      | .byte 0xf3,0xc3       | .byte 0xf3,0xc3       |
|                      |                       |                       |
|                      | Since the assembler   | And what if the two   |
|                      | needs mnemonics. The  | directives together   |
|                      | assembler won't       | were intended to      |
|                      | mitigate              | encode a different    |
|                      |                       | instruction or        |
|                      | \<constant            | different             |
|                      | directive\>           | instructions? In this |
|                      |                       | case, you can't       |
|                      | REP RET               | change either         |
|                      |                       | directive or insert   |
|                      | Since the assembler   | anything between the  |
|                      | doesn't know if the   | two directives, which |
|                      | constant directive    | is exactly what this  |
|                      | applies to the RET.   | option does.          |
|                      | The assembler will    |                       |
|                      | mitigate              | This pattern is not   |
|                      |                       | known to exist. If in |
|                      | \<constant            | doubt, the            |
|                      | directive\>           | disassembly of the    |
|                      |                       | object code           |
|                      | NOP                   | corresponding to      |
|                      |                       | untouched             |
|                      | REP RET               | perl/assembly files   |
|                      |                       | will show whether     |
|                      | But, if the constant  | this exceedingly rare |
|                      | directive really is   | pattern existed.      |
|                      | associated with the   |                       |
|                      | REP RET, then the     |                       |
|                      | assembler-added       |                       |
|                      | mitigation as well as |                       |
|                      | the NOP may break the |                       |
|                      | code.                 |                       |
+----------------------+-----------------------+-----------------------+
| change the perl      | Analogous to directly | Same as directly      |
| scripts to generate  | above                 | above                 |
| NOP RET              |                       |                       |
+----------------------+-----------------------+-----------------------+

##### Manual Addition of LFENCEs

How do you know where to add the LFENCEs in the output of the
Disassemble-2 step to the original (generated) assembly files?

The output of the Disassemble-2 step consists of mnemonics and, in cases
where the instructions are vulnerable to LVI, LFENCEs.

So how do you know where to put the LFENCEs? One way is to convey the
line number of the line with the constant directive so that it
survives/is preserved across assembly and subsequent disassembly.

[Original]{.underline}

340: .byte 243,15,30,250

341: movq %rsp,%rax

[Option 1:]{.underline} convey the line number in an immediate operand
(after something identifiable)

n: .byte 243,15,30,250

n+1: mov \$511233000**340**, %r9

The scripts don't currently process any files line by line so [this
option is on hold]{.mark}.

[Option 2:]{.underline} add nops to keep the line number of the line
with the mnemonic corresponding to the directive close to the line
number of the line with the directive in the original assembly file.

\~1: nop

\~2: nop

...

\~339: nop

\~340: \<mnemonic for some constant-encoded instruction\>

As of this writing, [this is what we do]{.mark}. The line numbers of the
mnemonics won't exactly match the line numbers of the original constant
directives but they should be close.

The scripts also currently cause labels of functions to be preserved,
which also provides valuable context. For example, you can see something
like the following in the Disassemble-2 output:

> 95: nop
>
> 96: nop
>
> 97: nop
>
> 98: shlq \$0x0,(%rsp)
>
> 9d: lfence
>
> a0: repz ret
>
> a2: nop
>
> a3: nop
>
> 00000000000000a4 \<prepare\_x86_64_AES_encrypt_compact\>:
>
> a4: nop
>
> a5: nop
>
> a6: nop

This tells you that there was a constant-encoded instruction close to
and before a function named \_x86_64_AES_encrypt_compact (the scripts
add "prepare\_"). This is in addition to the line numbers being close as
described above.

#### Approach 2: Do Not Distinguish Constant Directives

Approach 2 becomes an exercise in figuring out how to assemble
disassembly output -- Assemble-2 step below. This is challenging beyond
the ambiguity of Intel instruction mnemonics. As of this writing (August
23, 2023), this approach is not being pursued.

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Time
  \-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--à\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--à\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--à\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\--à
  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

+---------------+--------+--------+--------+--------+--------+--------+
| ~~Manual      | ~~co   | Asse   | D      | Asse   | D      | Manual |
| analysis~~    | nstruc | mble-1 | isasse | mble-2 | isasse | ad     |
|               | tion~~ |        | mble-1 |        | mble-2 | dition |
|               |        |        |        |        |        | of     |
|               |        |        |        |        |        | L      |
|               |        |        |        |        |        | FENCEs |
|               |        |        |        |        |        | to the |
|               |        |        |        |        |        | or     |
|               |        |        |        |        |        | iginal |
|               |        |        |        |        |        | (gene  |
|               |        |        |        |        |        | rated) |
|               |        |        |        |        |        | as     |
|               |        |        |        |        |        | sembly |
|               |        |        |        |        |        | files  |
+===============+========+========+========+========+========+========+
| ~~Analyze     | ~~Use  | Bas    | This   | For    | Some   |        |
| assembly      | script | ically | helps  | r      | of the |        |
| filles to     | to     | to     | effect | easons | L      |        |
| distinguish   | con    | ge     | a      | that I | FENCEs |        |
| constant      | struct | nerate | conv   | won't  | in the |        |
| directives    | temp   | som    | ersion | go     | result |        |
| that are      | as     | ething | from   | into   | of     |        |
| encoding      | sembly | that   | the    | here,  | D      |        |
| code          | files  | can be | or     | you    | isasse |        |
| /instructions | cons   | d      | iginal | effec  | mble-2 |        |
| from those    | isting | isasse | cons   | tively | need   |        |
| that are      | of the | mbled. | tant-e | want   | to be  |        |
| specifying    | cons   | It's   | ncoded | two    | ma     |        |
| data.         | tant-e | best   | instru | sub    | nually |        |
| Basically,    | ncoded | NOT to | ctions | -steps | added  |        |
| mark the      | instru | have   | to     | here,  | to the |        |
| directives    | ctions | the    | mnem   | one    | or     |        |
| specifying    | from   | build  | onics, | where  | iginal |        |
| data.~~       | the    | tools  | which  | you    | (gene  |        |
|               | or     | add    | the    | apply  | rated) |        |
|               | iginal | LVI    | LVI    | CF     | as     |        |
|               | as     | mitig  | miti   | level  | sembly |        |
|               | sembly | ations | gation | mitig  | files. |        |
|               | fi     | in     | -aware | ations |        |        |
|               | les.~~ | this   | tools  | and    | Sugge  |        |
|               |        | step.  | need.  | one    | stion: |        |
|               | ~~This |        |        | where  | put    |        |
|               | step   |        |        | you    | or     |        |
|               | is     |        |        | apply  | iginal |        |
|               | done   |        |        | full   | as     |        |
|               | when   |        |        | mitiga | sembly |        |
|               | all    |        |        | tions. | file   |        |
|               | cons   |        |        | Then,  | and    |        |
|               | tant-e |        |        | add    | the    |        |
|               | ncoded |        |        | both   | output |        |
|               | instru |        |        | sets   | of     |        |
|               | ctions |        |        | of     | d      |        |
|               | are in |        |        | L      | isasse |        |
|               | their  |        |        | FENCEs | mble-2 |        |
|               | own    |        |        | to the | step   |        |
|               | as     |        |        | or     | s      |        |
|               | sembly |        |        | iginal | ide-by |        |
|               | files, |        |        | (gene  | -side. |        |
|               | that   |        |        | rated) | If     |        |
|               | is,    |        |        | as     | should |        |
|               | all    |        |        | sembly | be     |        |
|               | the    |        |        | files. | fairly |        |
|               | cons   |        |        |        | easy   |        |
|               | tant-e |        |        |        | to     |        |
|               | ncoded |        |        |        | det    |        |
|               | instru |        |        |        | ermine |        |
|               | ctions |        |        |        | which  |        |
|               | in     |        |        |        | L      |        |
|               | foo.s  |        |        |        | FENCEs |        |
|               | go     |        |        |        | need   |        |
|               | into   |        |        |        | to be  |        |
|               | f      |        |        |        | added  |        |
|               | oo_con |        |        |        | and    |        |
|               | st_enc |        |        |        | where. |        |
|               | _instr |        |        |        |        |        |
|               | s.s.~~ |        |        |        |        |        |
+---------------+--------+--------+--------+--------+--------+--------+

##### Manual Addition of LFENCEs

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

# Appendix: Assembly Files

These are the assembly files that SGX SSL uses from OpenSSL release
3.0.10 ([openssl/openssl at openssl-3.0.10
(github.com)](https://github.com/openssl/openssl/tree/openssl-3.0.10))
along with some information that was helpful during the Prepare Process
for 3.0.10-based SGX SSL.

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                                                                                                                                                 Common, OE  Unexplained
                                                                                                                                                                                 and SGX SSL diffs in OE
                                                                                                                                                                                             files?
  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------- -------------
  \\crypto\\aes\\aesni-mb-x86_64.s                                                                                                                                               y           N

  [crypto\\aes\\aesni-sha1-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\aes\aesni-sha1-x86_64.s)         y           n

  [crypto\\aes\\aesni-sha256-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\aes\aesni-sha256-x86_64.s)     y           n

  [crypto\\aes\\aes-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\aes\aes-x86_64.s)                       y           n

  [crypto\\aes\\bsaes-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\aes\bsaes-x86_64.s)                   y           n

  [crypto\\aes\\aesni-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\aes\aesni-x86_64.s)                   y           y

  [crypto\\aes\\vpaes-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\aes\vpaes-x86_64.s)                   y           y

  [crypto\\bn\\rsaz-avx2.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\bn\rsaz-avx2.s)                           y           n

  [crypto\\bn\\rsaz-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\bn\rsaz-x86_64.s)                       y           n

  [crypto\\bn\\x86_64-gf2m.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\bn\x86_64-gf2m.s)                       y           n

  [crypto\\bn\\x86_64-mont.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\bn\x86_64-mont.s)                       y           n

  [crypto\\bn\\x86_64-mont5.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\bn\x86_64-mont5.s)                     y           n

  [crypto\\ec\\ecp_nistz256-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\ec\ecp_nistz256-x86_64.s)       y           n

  [crypto\\ec\\x25519-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\ec\x25519-x86_64.s)                   y           n

  [crypto\\md5\\md5-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\md5\md5-x86_64.s)                       y           n

  [crypto\\modes\\aesni-gcm-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\modes\aesni-gcm-x86_64.s)       y           n

  [crypto\\modes\\ghash-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\modes\ghash-x86_64.s)               y           n

  [crypto\\sha\\keccak1600-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\sha\keccak1600-x86_64.s)         y           n

  [crypto\\sha\\sha1-mb-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\sha\sha1-mb-x86_64.s)               y           n

  [crypto\\sha\\sha1-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\sha\sha1-x86_64.s)                     y           n

  [crypto\\sha\\sha256-mb-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\sha\sha256-mb-x86_64.s)           y           n

  [crypto\\sha\\sha256-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\sha\sha256-x86_64.s)                 y           n

  [crypto\\sha\\sha512-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\sha\sha512-x86_64.s)                 y           n

  [crypto\\x86_64cpuid.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\x86_64cpuid.s)                              y           y

  [crypto\\bn\\rsaz-avx512.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\bn\rsaz-avx512.s)                       N            n.a.

  [crypto\\chacha\\chacha-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\chacha\chacha-x86_64.s)           N            n.a.

  [crypto\\poly1305\\poly1305-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\poly1305\poly1305-x86_64.s)   N            n.a.

  [crypto\\whrlpool\\wp-x86_64.s](file:///\\WSL.LOCALHOST\Ubuntu-22.04\home\markg\dev\git\intel-sgx-ssl\openssl_source\openssl-3.0.10\crypto\whrlpool\wp-x86_64.s)               N            n.a.
  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Appendix: Status August 20, 2023

I had just gone through all the OE files and wanted to avoid doing it
again. This mostly goes to the OpenSSL commit that OE used vs the one we
want to use for SGX SSL. SGX SSL is using the 3.0.10 tag. I did my best
to determine the common assembly files and diffed them. I think I
compared 3.0.10 untouched to OE with LVI mitigations and made sure all
the changes were LVI mitigations. Doing it this way means that the set
of files that I've prepared for SGX SSL have LVI mitigations added in
two different ways:

1.  The OE assembly files were generated by untouched perl scripts so
    the assembly files have instances of .byte 0xf3,0xc3 and mitigations
    had to be added manually to them.

2.  The SGX SSL assembly files that aren't also OE files were generated
    by modified perl scripts so the assembly files have instances of NOP
    RET instead of .byte 0xf3,0xc3 and LVI mitigations don't have to be
    added manually.

Here are the resulting assembly files:

Of the 28 SGX SSL assembly files, 22 have manually added mitigations.

For reference, here are the files after the manual analysis step.

  -----------------------------------------------------------------------
  SGX SSL                            
  ---------------------------------- ------------------------------------
  OE used for SGX SSL                

  -----------------------------------------------------------------------

There are cases where the same assembly file is in both zip files. These
are common files but I treated them like they weren't common. We use the
ones in the SGX SSL zip file.

# Appendix: Do You Need Both load Level and CF Level LVI Mitigations?

load level for the GNU assembler is -mlfence-after-load=yes
-mlfence-before-ret=shl.

CF level is -mlfence-before-indirect-branch=all -mlfence-before-ret=shl

From this you can see that RETs get treated the same for both levels.
Also, other than assembler warnings, -mlfence-after-load=yes
-mlfence-before-indirect-branch=all is the same as
-mlfence-after-load=yes.

## Case 1

> \<constant directive\>
>
> mnemonic for indirect jump/call through register

Apply load level: an LFENCE would be added for the load, wherever it is.

Apply CF level: nothing. The Manual Analysis step wouldn't care about
the indirect jump/call since it's a mnemonic. Then, the assembler
wouldn't add an LFENCE when assembling the original file since the
indirect jump/call is preceded by a constant directive.

For best security, need to apply load level or pay attention to
assembler constant directive warnings and manually add LFENCEs. With
binutils 2.38, the relevant warnings are \`constant directive\` skips
-mlfence-before-indirect-branch on \`jmp\` and \`constant directive\`
skips -mlfence-before-indirect-branch on \`call\`. Note that the need to
pay attention to these warnings is independent of constant-encoded
instructions, they should always be paid attention to.

## Case 2

> mnemonic
>
> \<constant directive for indirect jump/call through register\>

Apply load level: an LFENCE would be added for the load, wherever it is.

Apply CF level: an LFENCE would be added before the indirect.

## Case 3

> \<constant directive\>
>
> ret

Either level: nothing. Manual Analysis would ignore the RET mnemonic and
then the constant directive would prevent the assembler from mitigating
the original assembly file.

Need to pay attention to assembler constant directive warnings and
manually add LFENCEs. With binutils 2.38, the relevant warning is
\`constant directive\` skips -mlfence-before-ret on \`ret\`. Note that
the need to pay attention to this warning is independent of
constant-encoded instructions, it should always be paid attention to.

## Case 4

> mnemonic
>
> .byte 0xc3 ; ret

Either level: would be mitigated.

## Conclusion

Either pay attention to assembler \`constant directive\` skips
-mlfence-before-indirect-branch on \`jmp\` and \`constant directive\`
skips -mlfence-before-indirect-branch on \`call\` warnings and only use
CF level mitigations or ignore the warnings and use load level. You
don't need to use both load level and CF level mitigations. Always pay
attention to \`constant directive\` skips -mlfence-before-ret on \`ret\`
warnings. Paying attention basically means adding a NOP between the
constant directive referenced in the warning and the JMP or RET
instruction.

# Appendix: Possible Content for Release Notes

What we've been doing for CF from the start (since 2020) could have been
better from perf-standpoint but what Jing is ready to merge is worse.
Note that Jing basically submitted the PR on my behalf. Jing isn't
advocating huring CF performance. 😊 We do have to make changes -- we
can't use the same assembly files to overwrite that we've been using --
but there are different approaches with different tradeoffs. To some
extent and given Q3 release schedule, I'm suggesting that we trade some
CF performance for lower risk. I'm also thinking that we can address the
CF performance in a future release, ideally when we have to change the
base OpenSSL 3.x release.

The approach that corresponds to the PR is a little weird since I wanted
to leverage the manual effort what I invested for OE, which I did before
SGX SSL. OE doesn't change any perl files so leveraging my OE effort
ultimately means that the PR corresponds to a mix of approaches for
mitigating the .byte 0xf3,0xc3 (f3 c3 is REP RET) instances. For the
OE - SGX SSL common files, the mitigation has been added manually and
you'll see

> Shl \$0,(%rsp)
>
> Lfence
>
> .byte 0xf3,0xc3

In the "final" assembly files.

For the SGX SSL only files, we change the one "xlate" perl script to not
generate .byte 0xf3,0xc3 and you'll see

> Nop
>
> Rep ret

In the final assembly files. Note that we've always had SGX SSL change
the one "xlate" perl script to not generate .byte 0xf3,0xc3 but before,
I think we changed it to simply generate RET. If the perl script doesn't
add the NOP, then it has to be added manually in several cases. (In
fact, I think this is the only reason that we've been overwriting any
assembly files for CF.) Changing the xlate perl script to also generate
the REP now is just to closer to "normal OpenSSL".

Note that the modified xlate perl script must be used during the Build
Process. While it's the case that most of the files will be overwritten,
the ones that aren't need to not have .byte 0xf3,0xc3.

[^1]: Note that 0xf3,0xc3 is REP RET. 0xc3 alone is RET. The two are
    architecturally equivalent. My understanding is that REP RET
    corresponds to a workaround needed on some AMD processors. The
    assembler treats REP RET the same as RET wrt LVI mitigations.
