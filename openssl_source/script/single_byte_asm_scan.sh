#!/bin/bash

# jan 30, 2020
# markg
# add command line parsing to choose, for now, new or old behavior
# april 2, 2020
# markg
# in last step, assemble once with load level mitigations and then with cf level
# this is necessary in case load of register holding target address uses mnemonic
# but actual indirect branch uses constants and sgx ssl is built with cf level

DEBUG="false"

if [ "true" = "$DEBUG" ]; then
	set -x
	trap read debug
fi

# markg
# set -e causes script to exit if a command returns nonzero exit status
# i think use of it is good practice but it can cause subtle problems,
# for example, with grep, which returns 1 when no matches are found
# fortunately, you can do grep ... || true to undo effect of set -e.
# see for below for example of this.
# you can also do set -e - commmands - set +e - commands - set -e
set -e
set -u
set -o pipefail


BEHAVIOR="new"

# Function: Print a help message.
usage() {                                      
  echo "Usage: $0 [ -b old|new|keep ] <asm file>" 1>&2 
  echo "Use -b to specify Behavior" 1>&2
  echo "new behavior is to look for .title directives and to remove what they delimit (as well as" 1>&2 
  echo "the directives themselves)." 1>&2 
  echo "keep behavior is like new, but keep mnemonics as well as constants that are encoding instructions." 1>&2 
  echo "This will result in a number of lfences that is the number you would get with no analysis +" 1>&2 
  echo "the number that we've added manually + the number that still need to be added." 1>&2 
  echo "-b default: new" 1>&2 


}

# Function: Exit with error.
exit_abnormal() {                              
  usage
  exit 1
}

# Loop: Get the next option;
# use silent error checking (leading :);
# option b takes argument.
while getopts ":b:" options; do              

											                                         
  case "${options}" in                         
    b)                                         
      BEHAVIOR=${OPTARG}                       
      ;;
    :)                                         # If expected argument omitted:
      echo "Error: -${OPTARG} requires an argument."
      exit_abnormal                            
      ;;
    *)                                         # If unknown (any other) option:
      exit_abnormal                            
      ;;
  esac
done

shift "$(($OPTIND -1))"


file=$*

	cp $file $file.bytecode1.s
	# markg
	# we shouldn't hard-code this regex here; pass it in?
	# grep -E "^\s*\.(byte|long|quad|value|dc|double|fill|float|hword|int|octal|short|single|sleb128|struct|uleb128|word|2byte|4byte|8byte)" $file > $file.bytecode1.s
	# at this point, constant directives specifying data (vs code) need to have been removed
	# change non-matching lines to nops
	sed -i -E '/^\s*\.(type.*,@function|byte|long|quad|value|dc|double|fill|float|hword|int|octal|short|single|sleb128|struct|uleb128|word|2byte|4byte|8byte)/!c nop' $file.bytecode1.s
	sed -i -E 's/\.type\s*/prepare__/g' $file.bytecode1.s
	sed -i -E 's/,@function/:/g' $file.bytecode1.s
	as $file.bytecode1.s -o $file.bytecode.o
	objdump --no-show-raw-insn -d $file.bytecode.o > $file.bytecode2.disasm


# at this point $file.bytecode2.disasm, as disassembly output, has all mnemonics

# identify lines with actual instructions and then get rid of what we use to identify
# in order to have assemble-able result
grep -E "(^ *[0-9a-f]*:)|(^.*<.*>:)" $file.bytecode2.disasm > $file.bytecode3.s
sed -i 's/^ *[0-9a-f]*://g' $file.bytecode3.s
sed -i 's/^.*<//g' $file.bytecode3.s
sed -i 's/-.*>:/_>:/g' $file.bytecode3.s
sed -i 's/>//g' $file.bytecode3.s



# markg
# why do we worry about .text directive here when we didn't when we ran as above?

	sed -i '1 i.text\n.type bytecode,@function\n.align 16\nbytecode:' $file.bytecode3.s




#as -mlfence-before-indirect-branch=register -mlfence-before-ret=not $file.bytecode3.s -o $file.bytecode.o

	as -mlfence-after-load=yes -mlfence-before-ret=shl -c $file.bytecode3.s -o $file.bytecode.o

objdump -d $file.bytecode.o > $file.load.disasm
grep -A 2 -B 3 lfence $file.load.disasm > $file.error.log || true

	mv $file.error.log $file.load.error.log
	as -mlfence-before-indirect-branch=all -mlfence-before-ret=shl -c $file.bytecode3.s -o $file.bytecode.o
	objdump -d $file.bytecode.o > $file.cf.disasm
	grep -A 2 -B 3 lfence $file.cf.disasm > $file.cf.error.log

exit 0
