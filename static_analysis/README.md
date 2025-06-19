# static_analysis

This folder contains the necessary scripts to analyze the apks in **target_APK/**. 

The results of the static analysis will be written into the **target_APK/[APPNAME]**/ folder.

## Phenomenon

Use the following link to download Phenomenon: https://www.file.io/9KzV/download/KRdiimbxws81

Use `run_phenom.py`, it will take care of copying the apks running phenomoenen and copying the analysis output to the correct folder. (Though you may need to adjust the paths used in the script)

## preprocess.py

Extracts the native function signatures using **NativeSignatures/** and then obtains the corresponding libraries and function offsets using **JNIOffset/**
Libraries may be rewritten using retrowrite

`python3 static_analysis/preprocess.py --target com.example -l --init -s -f --device asdf`

Afterwards two files will be created in **target_APK/[APPNAME]/**
- **signatures_pattern.txt** (created by the extractor pattern scripts, contains Java function names and the signature)
- **signatures_libraries_offsets.txt** (created by the JNIOffset scripts, contains the .so library name and the function offset along with the other information)

Atleast one phone setup needs to be connected over adb to run the JNI offset extraction.   

If the signature extraction doesn't work well, modify the jadx script to give more memory to the JVM.

## Components

```
.
├── JNIOFfset/
├── NativeSignatures/
├── preprocess.py
├── statistics.py
└── README.md
```

- **JNIOFfset/**: Contains the code to extract library names and function offsets
- **NativeSignatures/**: Contains the code to extract the native function signatures
- **preprocess.py**: Main script to statically analyze the apks and setup for harness generation
- **statistics.py**: Extract some info on signatures/argument types
