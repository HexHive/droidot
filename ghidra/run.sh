#!/bin/bash

analyzeHeadless $(mktemp -d) HeadlessAnalysis -overwrite -import $1 -scriptPath $(pwd) -prescript setup_project.py -postscript ghidra_dump_native_calls_only.py ++app_path $2 ++output $3