#!/system/bin/sh


## WHEN NOT RUN OVER ADB (for example over termux)
#!/bin/bash


## output colors ##
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# help option
Help()
{
   # Display Help
   echo "Syntax: ./fuzzing_one.sh <app_path> <target_library> <class0> <input-dir> <output-dir> <fuzz-dir> <parallel-fuzzing[0|N]>  <cmplog[0|1]> <LD_PRELOAD>" 
   echo
   echo "Fuzz given native method"
   echo
   echo "Options:"
   echo "   -h, --help     Print this Help."
   echo "	<app_path>:  path to the app folder"
   echo "	<target_library>:  name of the target library"
   echo "	<class0>: Java name of the object class"
   echo "	<input-dir>: fuzzing input directory name"
   echo "	<output-dir>: fuzzing output directory name"
   echo "	<fuzz-dir>: directory where to fuzz"
   echo "	<parallel-fuzzing[0...#max_cores]>: Specify number N of cores to use for a parallel fuzzing campaign (if N > #cores, then max #cores is used)"
   echo "	<cmplog [0|1]: use cmplog fuzzing, not sure if it's a good idead to do cmplog + parallel fuzzing since it already starts 2 forkservers"
   echo "	<LD_PRELOAD>: Specify another library to ld_preload"
   echo ""
   echo
}

PATH_TO_TERMUX_BIN="/data/data/com.termux/files/usr/bin"

# ANDROLIB_CLASS0=com/example/hellolibs/NativeCall ANDROLIB_TARGET_LIBRARY=libhello-libs.so ANDROLIB_MEMORY=memory ANDROLIB_APP_PATH=hellolibs3 AFL_FORKSRV_INIT_TMOUT=99999999999999 LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/hellolibs3/lib/arm64-v8a:/system/lib64 AFL_DEBUG=1 ./afl-fuzz -c 0 -i in -o out -O ./harness

Fuzz()
{
	# arguments
	APP_PATH=$1
	TARGET_LIBRARY=$2
	CLASS=$3
	FUZZ_INPUT_DIR=$4
	FUZZ_OUTPUT_DIR=$5
	FUZZ_DIR=$6
	PARALLEL_FUZZING=$7
	CMPLOG=$8
	LD_PRELOAD=$9

	AFL="$(pwd)/afl-fuzz"

	# enter the fuzz directory
	cd $FUZZ_DIR

	# add AFL++ to path
	export PATH=$PATH_TO_TERMUX_BIN:$PATH

	# set up number cores
	NUM_CORES=$(nproc --all)
	if [ $PARALLEL_FUZZING -lt $NUM_CORES ] ; then
		NUM_CORES=$PARALLEL_FUZZING
	fi

	if [ "$CMPLOG" -eq "1" ] ; then 
		CMPLOG="-c 0"
	else 
		CMPLOG=""
	fi

	export AFL_PRELOAD="/data/data/com.termux/files/usr/lib/libc++_shared.so "$LD_PRELOAD
	export LD_LIBRARY_PATH="/apex/com.android.art/lib64:$(pwd):$(pwd)/$APP_PATH/lib/arm64-v8a:/system/lib64"
	export AFL_FORKSRV_INIT_TMOUT=90000
	export ANDROLIB_APP_PATH=$APP_PATH
	export ANDROLIB_TARGET_LIBRARY="$TARGET_LIBRARY"
	export ANDROLIB_CLASS0=$CLASS
	echo -e "${GREEN}[LOG]${NC} Fuzzing $ANDROLIB_APP_PATH - $FUNCTION" 
	# fuzz
	if [ $PARALLEL_FUZZING -gt 0 ] ; then
		for IDX in $(seq 1 $NUM_CORES) ; do
			export ANDROLIB_MEMORY="memory"$IDX
			echo -e "${GREEN}[LOG]${NC} Starting fuzzer on core #$IDX\n"
			if [ $IDX -eq 1 ] ; then
				$AFL -O $CMPLOG -i "$FUZZ_INPUT_DIR" -o "$FUZZ_OUTPUT_DIR" -M "Master" ./harness > /dev/null &
			else
				$AFL -O $CMPLOG -i "$FUZZ_INPUT_DIR" -o "$FUZZ_OUTPUT_DIR" -S "Slave_$IDX" ./harness > /dev/null &
			fi
			# wait a bit before starting the next fuzzing job (avoid slowdown during memory dumping)
			sleep 20
		done
	else
		export ANDROLIB_MEMORY="memory"
		# only one fuzzer instance
		$AFL -O $CMPLOG -i "$FUZZ_INPUT_DIR" -o "$FUZZ_OUTPUT_DIR" ./harness > /dev/null &
	fi
}

# Main
if [ "$#" -eq 0 ] ; then
    Help
    exit 1
elif [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    Help
    exit 0
elif [ "$#" -lt 8 ] ; then
    echo "Error usage..."
    Help
    exit 1
else
    Fuzz $1 $2 $3 $4 $5 $6 $7 $8 $9
    exit 0
fi
