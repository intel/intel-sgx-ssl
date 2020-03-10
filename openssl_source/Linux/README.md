Hand-modified Assembly Files
----------------------------

Assembly files have some instructions encoded with constant directives, such as .byte 0xf3,0xc3.
The assembly files in this directory require manual modifications:
* Insert an LFENCE instruction after constant directive instructions that include a load uop.
* Insert a NOP instruction between a constant directive and a RET instruction.

