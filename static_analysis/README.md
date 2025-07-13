# static_analysis

This folder contains the necessary scripts to analyze the apks in **target_APK/**. 

The results of the static analysis will be written into the **target_APK/[APPNAME]**/ folder.

## preprocess.py

Extracts the native function signatures using **NativeSignatures/** and then obtains the corresponding libraries and function offsets using **JNIOffset/**
Libraries may be rewritten using retrowrite

```
python3 static_analysis/preprocess.py --target com.example -l --init -s --device $DEVICE 
```

Afterwards two files will be created in **target_APK/[APPNAME]/**
- **signatures_pattern.txt** (created by the extractor pattern scripts, contains Java function names and the signature)
- **signatures_libraries_offsets.txt** (created by the JNIOffset scripts, contains the .so library name and the function offset along with the other information)

Atleast one phone setup needs to be connected over adb to run the JNI offset extraction.   

If the signature extraction doesn't work well, modify the jadx script to give more memory to the JVM.

## argument analysis

Run argument analysis from `argument-analysis`, writes analysis output to the app's target_APK folder for later use by the harness generator. 

```
python3 static_analysis/preprocess.py --target com.example --argument_analysis --device $DEVICE
``` 

## call sequence

Run call-sequence analysis from `callsequence-analysis`, writes analysis output to the app's target_APK folder for later use by the harness generator. 

```
python3 static_analysis/preprocess.py --target com.example --callsequence_analysis --device $DEVICE
``` 

## Components

```
.
├── argument-analysis/
├── callsequence-analysis/
├── JNIOFfset/
├── NativeSignatures/
├── preprocess.py
└── README.md
```

- **callsequence-analysis/**: Contains the code to do call sequence analysis 
- **argument-analysis/**: Contains the code to do argument analysis 
- **JNIOFfset/**: Contains the code to extract library names and function offsets
- **NativeSignatures/**: Contains the code to extract the native function signatures
- **preprocess.py**: Main script to statically analyze the apks and setup for harness generation
