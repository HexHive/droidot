# harness

This folder contains the scripts to generate harness c++ source files, to generate seeds for each harness and to compile the harnesses. 

## harness_generator.py

The harness generator reads the results from the static analysis in the folder **target_APK/[APPNAME]/**, **target_APK/[APPNAME]/static_analysis** and based on these generates the harnesses.

`python3 harness/harness_generator.py --selective_coverage -ct_cn_si -ct_si_sp -jo_ok --target com.example`

There's a lot of flags that can be used to change the generated harnesses.

Check the **harness_generator_design.md** file for some information on what the further plans are for the harness generation or **cpp/README.md** for some details on the implementation.

Check the **parse_analysis.md** file for more information on how the static analysis output is parsed.

### seed_generator.py

The **seed_generator.py** library exports functions to generate seeds for either fixed length values or values using length-value encoding.

## compile_harness

The **compile_harness.py** library exports some functions which can be used to compile the harness.

```python
def init_compilation(REMOTE_FOLDER, path=".", device_id=None)
def compile_harnesses(app, TARGET_APK_PATH, REMOTE_FOLDER, device_id=None)
def compile_harness(harness_folder, harnessess_path, REMOTE_FOLDER, device_id=None)
```

The **compile_harness.sh** script is a small bash script to be executed on the phone to compile the harnesses. **harness** is the harness for fuzzing and **harness_debug** is the harness for debugging (contains debug symbols)

## Components

```
.
├── cpp/
├── compile_harness.py
├── compile_harness.sh
├── harness_generator_design.md
├── harness_generator.py
├── parse_analysis.py
├── file_seeds/
├── evluation/
└── README.md
```

- **cpp/**: Contains the c++ skeleton source code for the harness
- **compile_harness.py**: Library to compile the harnesses on the phone
- **compile_harness.sh**: Shell script to compile a harness on the phone
- **harness_generator_design.md**: Design document on the harness generator
- **harness_generator.py**: Script to generate harnesses
- **parse_analysis.py**: Script to parse the output of the static analysis
- **file_seeds/**: files used for the seed generation
- **evulation/**: random script for evaluation of support for argument types
