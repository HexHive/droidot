# Fuzzing

The fuzzing drivers and the fuzzing manager 

## Fuzzing structure on the phone

```
 /data/local/tmp/fuzzing/
                    ├── target_APK/appname/
                    |   └── base.apk
                    |   └── lib
                    └── [APPNAME]-[FUNCTIONNAME]/
                    |   └── seeds/
                    |   └── output_[DEVICEID]_[DATE]
                    |   └── harness
                    └── fuzzing_one.sh
                    └── afl-fuzz
                    └── afl-frida-trace.so
                    └── libharness.so
```

## testing.py

To test or debug a harness for an app and native function, use the **testing.py** script. The script sets up the necessary files and folders on the phone to debug or fuzz the harness or native function.

`python3 fuzzing/testing.py --target com.example --target_function Java_com_example_testfunc@0-0 --device RF8N12BM5VN`

## orchestration

TODO

## triage.py

Rerun all crashes, get the backtraces and group crashes by the backtrace:

`python3 fuzzing/triage.py --target com.example --target_function Java_com_example_testfunc@0-0 --device R58MA20Q40M --rerun --rerun_crashes_backtrace --remove_duplicates --rerun_crashes_clean --debug`

## Components

```
.
├── fuzzing_one.sh 
├── fuzzing_manager.py
├── testing.py
├── triage.py
├── gdb/
├── qemu/
└── README.md
```

- **fuzzing_one.sh**: Fuzzing driver for a specific app and function
- **fuzzing_manager.py**: The fuzzing manager to fuzz a harness for a certain time on specified phones
- **testing.py**: Script to help with testing harnesses
- **triage.py**: Script to help with triage
- **gdb/**: folder with the gdbinit script and fork of gef that hardcodes the architecture to aarch64
- **qemu/**: afl-qemu compiled for Android (deprecated)
