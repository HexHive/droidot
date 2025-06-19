# NativeSignatures

Uses qdox and jdax to extract the function signatures from the files. Hopefully to be replaced with some more sound analysis.

## analyze_native_signatures.sh

From static_analysis folder run to unpack and extract the native function signatures for a given app: 

```./NativeSignatures/analyze_native_signatures.sh [APPNAME]```

The script uses jdax to obtain the source files and then uses qdox to get the native function signatures.

## jadx/

Link to the jadx repository, needs to contain the jadx binary.

## extractor_pattern/

Contains the qdox files to extract the native signatures