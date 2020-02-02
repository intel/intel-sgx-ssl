import sys
import os
import re 
import shutil
import random

LOCK = "lock"
REP = "rep[a-z]*"
REX = "rex(?:\.[a-zA-Z]+)?"
REX = "rex(?:\.[a-zA-Z]+)?"
SCALAR = "(?:(?:[+-]\s*)?(?:[0-9][0-9a-fA-F]*|0x[0-9a-fA-F]+))"
IMMEDIATE = "(?:%s[hb]?)" %(SCALAR)
REG = "(?:[a-zA-Z][a-zA-Z0-9]*)"
SYM = "(?:[_a-zA-Z][_a-zA-Z0-9]*(?:@[0-9a-zA-Z]+)?)"
LABEL = "(?:[._a-zA-Z0-9]+)"
SEP = "(?:(?:^|:)\s*)"
PFX = "(?:%s\s+)?" %(REX)
CONST = "(?:(?:%s|%s|%s)(?:\s*[/*+-]\s*(?:%s|%s|%s))*)" %(SYM, SCALAR, LABEL, SYM, SCALAR, LABEL)
OFFSET = "(?:%s|%s|%s\s*:\s*(?:%s|%s|))" %(CONST, SYM, REG, CONST, SYM)
MEMORYOP = "(?:\[*(?:[a-zA-Z]+\s+)*(?:%s\s*:\s*%s?|(?:%s\s*)?\[[^]]+\]\]*))" %(REG, CONST, OFFSET)
ANYOP = "(?:%s|%s|%s|%s|%s)" %(MEMORYOP, IMMEDIATE, REG, SYM, LABEL)
MEMORYSRC = "(?:%s\s*,\s*)+%s(?:\s*,\s*%s)*" %(ANYOP, MEMORYOP, ANYOP)
MEMORYANY = "(?:%s\s*,\s*)*%s(?:\s*,\s*%s)*" %(ANYOP, MEMORYOP, ANYOP)
ATTSTAR = ""

LFENCE = [
    "(?:%s%smov(?:[a-rt-z][a-z0-9]*)?\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%s(?:vpmask|mask|c|v|p|vp)mov[a-z0-9]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%spop[bswlqt]?\s+(?:%s|%s))" %(SEP, PFX, MEMORYOP, REG),
    "(?:%s%spopad?\s+%s\s*)" %(SEP, PFX, REG),
    "(?:%s%s(?:%s\s+)?xchg[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?(?:x|p|vp|ph|h|pm|)add[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?(?:p|vp|ph|h|)sub[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?ad[co]x?[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?sbb[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?(?:p|)cmp(?:[a-rt-z][a-z0-9]*)?\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?inc[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?dec[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?not[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?neg[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:i|v|p|vp|)mul[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%s(?:i|v|p|vp|)div[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%spopcnt[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%scrc32[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%s(?:%s\s+)?v?p?and[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?v?p?or[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%s(?:%s\s+)?v?p?xor[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%sv?p?test[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%ss[ah][lr][a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%ssar[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sro(?:r|l)[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%src(?:r|l)[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%s(?:%s\s+)?bt[a-z]*\s+%s)" %(SEP, PFX, LOCK, MEMORYANY),
    "(?:%s%sbs[fr][a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%s[lt]zcnt[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sblsi[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sblsmsk[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sblsr[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sbextr[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sbzhi[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%spdep[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%spext[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%s(?:%s\s+)?lods[a-z]*(?:\s+%s|\s*(?:#|$)))" %(SEP, PFX, REP, MEMORYSRC),
    "(?:%s%s(?:%s\s+)?scas[a-z]*(?:\s+%s|\s*(?:#|$)))" %(SEP, PFX, REP, MEMORYSRC),
    "(?:%s%s(?:%s\s+)?outs[a-z]*(?:\s+%s|\s*(?:#|$)))" %(SEP, PFX, REP, MEMORYSRC),
    "(?:%s%s(?:%s\s+)?cmps[a-z]*(?:\s+%s|\s*(?:#|$)))" %(SEP, PFX, REP, MEMORYSRC),
    "(?:%s%s(?:%s\s+)?movs[a-z]*(?:\s+%s|\s*(?:#|$)))" %(SEP, PFX, REP, MEMORYSRC),
    "(?:%s%slddqu\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?pack[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?punpck[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?pshuf[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?palign[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?pblend[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%svperm[a-z0-9]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?p?insr[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%svinsert[a-z0-9]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?p?expand[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%svp?broadcast[a-z0-9]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%svp?gather[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?pavg[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?p?min[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?p?max[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?phminpos[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?pabs[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?psign[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?m?psad[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?psll[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?psrl[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?psra[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?pclmulqdq\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?aesdec(?:last)?\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?aesenc(?:last)?\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?aesimc\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?aeskeygenassist\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?sha(?:1|256)(?:nexte|rnds4|msg1|msg2)\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?cvt[a-z0-9]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?rcp(?:ss|ps)\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?u?comis[sd]\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?round[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?dpp[sd]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sv?r?sqrt[a-z]*\s+%s)" %(SEP, PFX, MEMORYSRC),
    "(?:%s%sv?ldmxcsr\s+%s)" %(SEP, PFX, MEMORYOP),
    "(?:%s%sf?x?rstors?\s+%s)" %(SEP, PFX, MEMORYOP),
    "(?:%s%sl[gi]dt\s+%s)" %(SEP, PFX, MEMORYOP),
    "(?:%s%slmsw\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%svmptrld\s+%s)" %(SEP, PFX, MEMORYOP),
    "(?:%s%sf(?:b|i|)ld[a-z0-9]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sfi?add[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sfi?sub[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sfi?mul[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sfi?div[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
    "(?:%s%sf(?:i|u|)com[a-z]*\s+%s)" %(SEP, PFX, MEMORYANY),
]

RET = "(?:%s%sret[a-z]*(?:\s+%s)?(?:#|$))" %(SEP, PFX, IMMEDIATE)
MEM_INDBR = "(?:%s%s(call|jmp)[a-z]*\s+%s%s)" %(SEP, PFX, ATTSTAR, MEMORYOP)
REG_INDBR = "(?:%s%s(call|jmp)[a-z]*\s+%s)" %(SEP, PFX, REG)

#
# File Operations - read/write
#
def read_file(sfile):
    f = open(sfile, 'r')
    lines = f.readlines()
    f.close()
    return lines

def write_file(tfile, lines):
    f = open(tfile, 'w')
    for line in lines:
        f.write(line)
    f.close()
    return

def insert_lfence(infile, outfile):
    pattern = '|'.join('(?:%s)' % l for l in LFENCE)
    lines = read_file(infile)
    outputs = lines
    for i in range(0, len(lines)):
        if lines[i].strip().startswith(';') or lines[i].strip().startswith('%') or lines[i].strip().startswith('['):
            continue
        m = re.search(pattern, lines[i])
        if m:
            load_mitigation = "    lfence\n"
            outputs[i] = outputs[i] + load_mitigation

        m = re.search(RET, lines[i])
        if m:
            ret_mitigation = "    not QWORD[rsp]\n     not QWORD[rsp]\n    lfence\n"
            outputs[i] = ret_mitigation + outputs[i]
        m = re.search(REG_INDBR, lines[i])
        if m:
            if outputs[i-1][-7:-1] != "lfence":
                outputs[i] = "    lfence\n" + outputs[i]
        m = re.search(MEM_INDBR, lines[i])
        if m:
            print ("Warning: indirect branch with memory operand, line %d" %(i))

    write_file(outfile, outputs)

def parse_options():
    mitigation = False
    options = []
    for arg in sys.argv[1:]:
        if arg == '-DMITIGATION_FULL':
            mitigation = True
        else:
            if arg.startswith('/Ta') and len(arg) > 3:
                options.append('/Ta')
                arg = arg[3:]
            if arg.find(' ') > 0:
                arg = '\"' + arg + '\"'
            options.append(arg)
    return (mitigation, options)

rand = 0
def get_rand():
    global rand
    while rand == 0:
        rand = random.randint(0,100000)
    return rand

def get_mitigated_file(src):
    return src + '.mitigated.%d' %(get_rand())
def get_preprocess_file(src):
    return src + '.preprocess.%d' %(get_rand())

def get_src_index(options):
    src_index = -1
    for i in range(0,len(options)):
        if options[i].endswith('.asm'):
            if(src_index != -1):
                print ('source files conflict')
                exit(-1)
            src_index = i
    if src_index == -1:
        print ('cannot find the source file')
        exit(-1)
    return src_index

def get_dst_index(options):
    dst_index = -1
    for i in range(0,len(options)):
        if options[i] == '-o':
            if(dst_index != -1):
                print ('target files conflict')
                exit(-1)
            dst_index = i+1
    if dst_index == -1:
        print ('cannot find the target file')
        exit(-1)
    return dst_index

def get_preprocess_cmd(compiler, options, src_index):
    pre_file = get_preprocess_file(src_file)
    if compiler == 'ml64.exe':
        pre_cmd = compiler + ' /EP ' + ' '.join(options) + ' > ' + pre_file
    elif compiler == 'nasm.exe':
        ops = options
        dst_index = get_dst_index(options)
        tmp_file = ops[dst_index]
        ops[dst_index] = get_preprocess_file(src_file)
        pre_cmd = compiler + ' -E ' + ' '.join(ops)
        ops[dst_index] = tmp_file
    else:
        pre_cmd = None
    return pre_cmd

if __name__ == "__main__":
    (mitigation, options) = parse_options()

    if sys.argv[0].find('ml64') > 0:
        compiler = 'ml64.exe'
    elif sys.argv[0].find('nasm') > 0:
        compiler = 'nasm.exe'

    (mitigation, options) = parse_options()
    src_index = get_src_index(options)
    src_file = options[src_index]

    # preprocess the source file
    pre_cmd = get_preprocess_cmd(compiler, options, src_index)
    print ("pre_cmd: " + pre_cmd)
    os.system(pre_cmd)
    # insert lfence
    insert_lfence(get_preprocess_file(src_file), get_mitigated_file(src_file))
    # compile use the mitigated file
    ops = options
    ops[src_index] = get_mitigated_file(src_file)
    as_cmd = compiler + ' ' + ' '.join(ops)
    #print as_cmd
    os.system(as_cmd)
