# JNIOffset

The code here extracts the function offset of the native function. Previously this was part of the harness. In order to simplify the harness and ensrue that spurious crashes are not part of the fuzzing campaign this step was moved to the "static" analysis.

## harness

A random harness that exports the necessary symbols needed to load the retrowrite instrumented library.

## findJNIOffsets.sh

Wrapper script to be run on the phone to extract all function offsets for a given library.

`./findJNIOffsets.sh [APPNAME] [LIBRARYNAME] [REMOTEFOLDER]`

## cpp/

Contains the source code for the JNIOffsetfinder.

The JNIOffsetfinder loads the target library and looks for the native functions. If none are found, a barebones JVM is started an the registerNatives funciton is hooked to intercept the native functions. Then JNI_Onload (if exported by the library) is called.

The **/proc/self/maps** file is read to calculate the function offset from the function address.

## TODO

Currently overloaded functions are not properly handled...