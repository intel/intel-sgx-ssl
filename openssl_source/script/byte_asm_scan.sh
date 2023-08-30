#!/bin/bash

# jan 30, 2020
# markg
# add command line parsing to choose, for now, new or old behavior

DEBUG="false"

if [ "true" = "$DEBUG" ]; then
	set -x
	trap read debug
fi


set -e
set -u
set -o pipefail

BEHAVIOR="new"
ASM_DIR_TOP="."

# Function: Print a help message.
usage() {                                      
  echo "Usage: $0 [-b old|new|keep] [-d <directory>]" 1>&2 
  echo "Use -b to specify Behavior" 1>&2
  echo "new behavior is to look for .title directives and to remove what they delimit (as well as" 1>&2 
  echo "the directives themselves)." 1>&2 
  echo "keep behavior is to keep mnemonics as well as constants that are encoding instructions." 1>&2 
  echo "This will result in a number of lfences that is the number you would get with no analysis +" 1>&2 
  echo "the number that we've added manually + the number that still need to be added." 1>&2 
  echo "-b default: new" 1>&2 
  echo "Use -d to specify directory with asm files to analyze" 1>&2 
  echo "-d default: current directory" 1>&2 
}

# Function: Exit with error.
exit_abnormal() {                              
  usage
  exit 1
}

# Loop: Get the next option;
# use silent error checking (leading :);
# options b and d take argument.
while getopts ":b:d:" options; do                

  case "${options}" in                         
    b)                                         
      BEHAVIOR=${OPTARG}                           
      ;;
    d)                                         
      ASM_DIR_TOP=${OPTARG}                           
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

var=0
asm_folder=asm_files792946
single_scan=single_byte_asm_scan.sh
clear_data=clear_data.sh


if [ -d "$asm_folder" ]; then
	rm -rfI $asm_folder
fi
mkdir -p $asm_folder
cp $single_scan $asm_folder
cp $clear_data $asm_folder

# copy renamed asm source files to the temp directory
# markg
# explain why "sgx_libm" shows up here?
for i in `find $ASM_DIR_TOP -name "*.S" -o -name "*.s" | grep -vE "sgx_libm|sparc|ia64" | xargs grep -EH "\.(byte|long|quad|value|dc|double|fill|float|hword|int|octal|short|single|sleb128|struct|uleb128|word|2byte|4byte|8byte)" | awk -F: '{print $1}' | sort | uniq`;
do
	var=$((var + 1))
	# markg
	# explain what this is doing, expecially */ inside {}
	file=${i##*/}_$var.asm
	cp $i $asm_folder/$file

done

cd $asm_folder

set +e

./$clear_data -b $BEHAVIOR
for i in *.asm;
do
	./$single_scan -b $BEHAVIOR $i
done

set -e

cd -

exit 0

