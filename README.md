# Fuzz Android Native Components

Framework to fuzz native libraries of an Android app

# Triage

Information about triaging: [Triage Info](fuzzing/TRIAGE.md)

# Dataset Information

The dataset is available at https://7ff8-2001-62c-118-5c0-2-8ab4-0-15.ngrok-free.app/dataset.tar.gz

# Fuzzing

## Requirements
```
apt-get install adb
pip3 install -r requirements.txt
```

For the static analysis (static_analysis/) at least one phone rooted and setup must be connected to the current machine over ADB.

On an x86_64 machine compile afl-fuzz and frida-trace.so
```
cd afl
./build.sh
```

## Android devices

If on an arm64 machine with kvm use emulators instead of 
real device (see *emulator/*)

For fuzzing, check the list below:

* All Android devices must be rooted

* All Android devices must have a connection with the central machine through ADB, either over a TCP/IP connection or with multiple USB ports. Steps  to set-up TCP/IP connection (source [here](https://stackoverflow.com/questions/43973838/how-to-connect-multiple-android-devices-with-adb-over-wifi)):
  1. connect device with USB cable to PC
  2. `adb -d tcpip 5555`
  3. `adb connect <device_ip_addr>` and remove USB cable
  4. repeat for all other devices

## Preparation

### Target Collection

Populate the target_APK folder with the APKs. The structure should be the following:
```
 target_APK/
 ├── APPNAME/
    └── base.apk
```
The python script **apk_download/parse_download_apks.py** may be used to collect apks. The apks are collected by scraping the google play store and downloaded from androzoo. 

Scrape the google play store and download the newest version of the apks:

`python3 apk_download/parse_download_apks.py -gp -uc`

Download the newest version of a specific apk:

`python3 apk_download/parse_download_apks.py -ds [APPNAME]`

### Static Analysis

Gather the information to generate useful fuzzing harnesses.

(Optional): Run Path senstive callsequence extraction (Phenomenon)

Extract the native function signatures, the corresponding library name, some 
straightforward soot info and the function offset with the script in **static_analysis/preprocess.py**.

Extract the information for a specific app in the **target_APK/** folder:

`python3 static_analysis/preprocess.py --target [APPNAME] -s -l -f`

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

### Generate Harnesses

With the information on the function signatures, harnesses for these functions can be generated using the script **harness/harness_generator.py**.

Generate harness for a specific app in **target_APK/**:

`python3 harness/harness_generator.py --target [APPNAME]`

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

Note that the harness generator has a bunch of options, which are all about how the harness is generated.

## Fuzzing

### Testing & Debugging

To test or debug a harness for a app and native function use the **fuzzing/testing.py** script:

`python3 testing.py --target [APPNAME] --target_function [HARNESS_NAME]`


### Fuzzing
TODO

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

## Components

```
.
├── apk_download/
├── emulator/
├── fuzzing/
├── harness/
├── static_analysis/
├── target_APK/
├── ghidra/
├── adb.py
└── README.md
```

* **/apk_download**: scripts to scrape the google play store and download apks into the target_APK/ folder
* **/emulator**: scripts to install and setup the android emulator on an arm64 machine
* **/fuzzing**: scripts and fuzzing drivers to run/manage the fuzzing campaign over multiple phones
* **/harness**: harness/seed generation and compilation scripts
* **/static_analysis**: code to statically anaylze the apks, extract native function signatures corresponding library and the offset
* **/target_APK**: contains all the downloaded/analyzed apks, the generated harnesses/seeds and fuzzing output
* **adb.py**: python library to integrate ADB commands
* **ghidra**: ghidra scripts to get insights into native library
* **README.md**: this README
