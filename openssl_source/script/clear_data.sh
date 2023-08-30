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

# Function: Print a help message.
usage() {                                      
  echo "Usage: $0 [ -b old|new ]" 1>&2 
  echo "Default: new" 1>&2
  echo "New behavior is to look for .title directives and to remove what they delimit (as well as" 1>&2 
  echo "the directives themselves)." 1>&2 
 
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

	echo "************* NEW *******************"
	sed -i -E '/\.title \"begin table\"/,/\.title \"end table\"/d' *.asm 
	# sed -i -E '/\.type.*\@object/d' *.asm
	# sed -i -E '/\.align/d' *.asm





exit 0
