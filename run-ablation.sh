#!/bin/bash

export NREMULATORS=8
export APKS="$(pwd)/apks.txt"
#export CLEAN=1

export SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

export FUZZ_DATA="${SCRIPT_DIR}/$(date +%s)_fuzzing_data"

rm -rf "${FUZZ_DATA}"
mkdir "${FUZZ_DATA}"

rm -rf target_APK/*/harnesses/*
python3 preprocess_orchestrated.py

# generate harnesses
export HARNESS_GEN_FLAGS="-jo_ok -cs_ph -cs_io -cs_ph_min_len 1 -ct_argval -fuzz --afl_coverage_on"
python3 gen_harnesses.py
export HARNESS_GEN_FLAGS="-jo_ok -cs_ph -cs_io -cs_ph_min_len 1 -fuzz --afl_coverage_on"
python3 gen_harnesses.py
export HARNESS_GEN_FLAGS="-jo_ok -ct_argval -fuzz --afl_coverage_on"
python3 gen_harnesses.py
export HARNESS_GEN_FLAGS="-jo_ok -fuzz --afl_coverage_on"
python3 gen_harnesses.py
export APP2FNAMES="${FUZZ_DATA}/app2fnames.json"
python3 queue_apk.py
python3 paper_data/get_unique_fs_cs.py
python3 fuzzing/orchestrate.py
cp fuzzing/fuzz.db "${FUZZ_DATA}/"

# coverage
python3 paper_data/get_data_showmap.py
python3 showmap_orchestrated.py "${FUZZ_DATA}/showmap.json"
python3 paper_data/ablation_plot.py
