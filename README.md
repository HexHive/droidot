# Fuzz Android Native Components

Framework to fuzz native libraries of an Android app

# Requirements

Droidot uses the arm64 Android emulator with KVM to fuzz arm64 native libraries shipped with apks.
The steps below assume you are running this on an arm64 machine.

For the artifact evaluation we ran Droidot on an arm64 machine with the 
NXP Lay-erscape LX2160A CPU.

# Setup

Build the docker:
```
./setup.sh
```

Spawn a shell in the docker (all following commands assume you are in the docker container shell)

```
./run.sh
```

## Preparation

### Target Collection

Populate the target_APK folder with the APKs. The structure should be the following:
```
 target_APK/
 ├── APPNAME/
    └── base.apk
```

### Start Emulator

Start an emulator with: 
```
./start_single_emu.py

adb devices # should display at least one emulator (emulator-55XX)
```

## Static Analysis

### Argument Value Analysis And JNI Function Offsets

Extract the information (argument value pass, jni functions and jni function library+offset) 
for a specific app in the **target_APK/** folder:

```
python3 static_analysis/preprocess.py --target [APPNAME] -s -l -f
```

For more options check the README in **static_analysis/**

After this step the following files should be present (for apps with native functions)

```
 target_APK/
 ├── APPNAME/
    └── base.apk
    └── static_analysis/
    └── lib/
    └── signatures_pattern.txt
    └── signatures_libraries_offsets.txt
```

### Call Sequence Pass

**TODO** 

## Generate Harnesses

With the information on the function signatures, harnesses for these functions can be generated using the script **harness/harness_generator.py**.

Generate harness for a specific app in **target_APK/**:

```
python3 harness/harness_generator.py --target [APPNAME]
```
Note that the harness generator has a number of options, check the `run-ablation.sh` script to see which flags were used during the evaluation.

After this step, the following folder structure should be in place. Now all the necessary information for fuzzing is now present.

```
 target_APK/
 ├── APPNAME/
    └── base.apk
    └── static_analysis/
    └── lib/
    └── signatures_pattern.txt
    └── signatures_libraries_offsets.txt
    └── harnesses/
        └── fname-signature@cs_number-io_matching_possibility/
            └── harness.cpp
            └── harness_debug.cpp
            └── seeds/ (folder with seeds with the correct input byte structure)
```

## Fuzzing

Fuzz a specific harness:

``` 
python3 fuzzing/fuzz.py --target [APPNAME] --target_function [HARNESS_NAME] --device emulator-55XX -t [TIME-TO-FUZZ]
```

The output is stored in the fuzzing_output folder.

```
 target_APK/
 ├── APPNAME/
    └── base.apk
    └── static_analysis/
    └── lib/
    └── signatures_pattern.txt
    └── signatures_libraries_offsets.txt
    └── harnesses/
    └── fuzzing_output/
        └── fname-signature@cs_number-io_matching_possibility/
            └── output_deviceid_datetime/
```

## Triage

Attempt to reproduce crashes and deduplicate based on backtrace for crashes in the fuzzing_output directory:

```
python3 fuzzing/triage.py -c --target [APPNAME] --target_function [HARNESS_NAME] -r --device emulator-55XX
```

Reproduced crashes and backtraces are stored in the reproduced_crashes folder:

```
 target_APK/
 ├── APPNAME/
    └── base.apk
    └── static_analysis/
    └── lib/
    └── signatures_pattern.txt
    └── signatures_libraries_offsets.txt
    └── harnesses/
    └── fuzzing_output/
        └── fname-signature@cs_number-io_matching_possibility/
            └── reproduced_crashes/
```

Debug crashes on the emulator with gdb:

```
python3 fuzzing/triage.py -d --target [APPNAME] --target_function [HARNESS_NAME] -r --device emulator-55XX
```

Follow the printed instructions to replay the crashing seed on device with gdb attached to debug the crash.

## Components

```
.
├── emulator/
├── fuzzing/
├── harness/
├── static_analysis/
├── target_APK/
├── ghidra/
├── adb.py
└── README.md
```

* **/emulator**: scripts to install and setup the android emulator on an arm64 machine
* **/fuzzing**: scripts and fuzzing drivers to run/manage the fuzzing campaign over multiple phones
* **/harness**: harness/seed generation and compilation scripts
* **/static_analysis**: code to statically anaylze the apks, extract native function signatures corresponding library and the offset
* **/target_APK**: contains all the downloaded/analyzed apks, the generated harnesses/seeds and fuzzing output
* **adb.py**: python library to integrate ADB commands
* **ghidra**: ghidra scripts to get insights into jni native libraries
* **README.md**: this README
