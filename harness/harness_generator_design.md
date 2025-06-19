# Androlib Harness Generation

Python script to generate cpp code, which is inserted into a harness skeleton to fuzz a specific native function. It will also generate a number of valid seeds which can be used if no other target information is available to create seeds.

The script will take as input the target function signature (milestone 1), the constraints on the target function arguments (milestone 2), the preceding function calls (milestone 3), preceding function calls and it's constraints (milestone 4) and data dependencies from preceding calls (milestone 5).

## Harness

The harness takes 5 arguments, the target app, the target libraryname, the target functionname, the target function's offset inside the library and the path to the input data file.

## Milestone 1 & 2

The harness generator will insert code to parse/split the AFL bytestream to the corresponding target function arguments at the following location (after parsing the input file and before calling the targetFunction): 

```c++
        #ifdef __AFL_HAVE_MANUAL_CONTROL
          __AFL_INIT();
        #endif

        std::string inputFile = argv[5];
        std::ifstream file(inputFile, std::ios::binary | std::ios::ate);
        size_t buf_size = file.tellg();
        char* buf = (char*)malloc(sizeof(char) * buf_size);
        file.seekg(0, std::ios::beg);
        file.read(buf, buf_size);
        FuzzedDataProvider fuzzed_data((uint8_t*)buf, buf_size);

        /*
        LOCATION OF GENERATED CODE
        */

        targetFunctionPtr(env, CallerObj, jinput1, jinput2, ...);
```

It will also insert the targetFunctionDefinition and set the number of arguments:
```c++
extern "C"
{
	/***********************************/
	/* MODIFY TARGET FUNCTION DEF HERE */
	/***********************************/
    typedef jstring function_t(JNIEnv *, jobject, jstring);
}
int nrArgs = 1;
```

## Input Data Consumption

The harness will use the [FuzzedDataProvider](https://github.com/google/fuzzing/blob/master/docs/split-inputs.md#fuzzed-data-provider) to traverse the input byte stream and split it into the different arguments. 

For each function argument it will consume the requisite number of bytes needed for that argument type.

Example for an jint argument (consumeIntegral uses 4 bytes from the input byte stream to return the integer):
```c++
jint jinput1 = (jint)fuzzed_data.ConsumeIntegral();
```

For variable length types like string, byte[] a lenth value encoding is used. A number of bytes indicate the size of the variable length type, which is then read.

Example input data for a byte[] of length 4.

```
\x04AAAA
```

## Types Supported

Currently the following primitive java types are supported in the harness:

bool, byte, byte[], byteBuffer, double, float, int, long, short, string, char

## Constraints

Depending on the argument type and constraint type the constraint will be applied when the bytes are extracted or afterwards. For each combination of constraint type/argument type the harness will either use some cpp functions in a helper library or directly insert them. Only simple constraints are supported, since I think being able to reflect complex z3 constraints in dynamically generated c++ code would be too much effort /it's own project.

If an **argument is fixed** (static) then this value will be hardcoded into the harness and no input bytes will be consumed by that argument.
```c++
jint jinput2 = (jint)42;
```

### Numeric Values

**Value in a certain range** can be supported by using for exmaple:
```c++
jint jinput3 = (jint)fuzzed_data.ConsumeIntegralInRange(5, 24);
```

### Strings, Bytes

**Length constraints**: The harness consumes the number of bytes up to the seperator. If the length does not satisfy the constraint, the harness returns.

Example for minimal string length: 
```c++
std::string stringValue4 = fuzzed_data.ConsumeStringUpToSeperator();
        if(stringValue4.length() < min_length_constraint){
            return 1;
        }
        jstring jinput4 = env->NewStringUTF(stringValue4.c_str());
```

### String (filepath)

Read input string then write it to file and pass the filename to the fuzzed program
The generated c++ code to parse an input file

```c++
std::string string_value = consumeBytes2StringLV(&fuzzed_data, 1);
        std::fstream out;   
        std::string outpath = memoryPath + "/output0_0";    
        out.open(outpath,std::fstream::out | std::fstream::binary);
        out << string_value;
        out.close();
        jstring jinput0_0 = env->NewStringUTF(outpath.c_str());
        /* Call target function -- Fuzz */
		//std::cout << "CALLING..." << std::endl;
        targetFunctionPtr0(env, CallerObj0,jinput0_0);
```

### int (file descriptor)

Read input, write to file, open file and pass fd to program

If the length is fixed, no seperator is needed and the required amount of bytes are read.

**Constraints on data content**: After extracting the correct length byte string, the data content constraints are fulfilled by modifying the resulting bytes in place.


## Milestone 3 & 4

For preceding functions, the harness skeleton will need to be refactored to allow inserting multiple targetfunctions. However the logic for consuming the inputs for the arguments and enforcing constraints will be the same. For consuming the AFL bytes to input data, multiple functions will be abstracted to one big function and the input bytes consumed accordingly (along with the seed generation). However hopefully preceding initialization functions will have mostly static arguments.

In the skeleton, the appname, libraryname, classnames of calling functions and the offsets will be hardcoded. Only argument is the path to the apk folder and the input file.
It is assumed that dependant native calls are from the same class (may need to be changed) and from the same .so file.

A callSequences.json file is required in the target_APK folder mapping functionnames to callgraphs. 
In this example the call sequence would be Java_com_example_MainActivity_addJNI -> Java_com_example_MainActivity_StringFunction -> java_com_example_MainActivity_echoJNI

```
{"java_com_example_MainActivity_echoJNI": 
  ["Java_com_example_MainActivity_addJNI", "Java_com_example_MainActivity_StringFunction"]
}
```

Defining the target functions:

```c++
extern "C"
{
	/***********************************/
	/* MODIFY TARGET FUNCTION DEF HERE */
	/***********************************/
 GENERATOR_FUNCTIONDEFINTION =>  
  typedef void function_0(JNIEnv *, jobject, jint);
  typedef jstring function_1(JNIEnv *, jobject, jstring, jstring);
}
```

Defining the classname and the targetlibrary name:

```c++
/* globals definitions */
JavaVM *javaVM;
JNIEnv *env;
std::string targetAppPath;
std::string targetLibName;

int main(int argc, char *argv[]) {
		/* Check parameters*/
		if (argc != 3) {
			std::cerr << "Error calling harness: 2 parameters are needed! (path to app and input file)" << std::endl;
			return 1;
		}
    /* Get target app path (e.g. target_APK/app_name) */
    targetAppPath = std::string(argv[1]);

GENERATOR_LIBRARY_CLASSNAME =>
		targetLibName = "libhello-lib.so";
		std::string className0 = "/com/example/MainActivity";
    std::string className1 = "/com/example/MainActivity2";
```

Obtaining the pointers to the target functions

```c++
// get the targetFunction address
		long base = readMapsBase();
GENERATOR_FUNCTIONOFFSETS =>
		function_0* targetFunctionPtr0 = (function_0 *) (base + 105430);
    function_1* targetFunctionPtr1 = (function_1 *) (base + 234531);
```

Obtain the calling classes (note that if the same calling class is used
for calls, then the class is reused, in the hope of emulating how the library is called).

```c++
GENERATOR_CALLEROBJECT =>
		// allocate caller object (always passed as second argument)
		jclass CallerCls0 = env->FindClass(className0.c_str());
		jobject CallerObj0 = env->AllocObject(CallerCls0);
    jclass CallerCls1 = env->FindClass(className1.c_str());
		jobject CallerObj1 = env->AllocObject(CallerCls1);
```

Parsing the inputs

```c++
GENERATOR_INPUTPARSING => 
    jint jinput0_0 = consumeBytes2Jint(&fuzzed_data, INT_MIN, INT_MAX);
    jstring jinput1_0 = consumeBytes2JStringLV(&fuzzed_data);
    jstring jinput1_1 = consumeBytes2JStringLV(&fuzzed_data);

    /* Call target function -- Fuzz */
		std::cout << "CALLING..." << std::endl;

GENERATOR_CALLINGTARGETFUNCTION => 
    targetFunctionPtr0(env, CallerObj,jinput0_0);
    targetFunctionPtr1(env, CallerObj,jinput1_0,jinput1_1);
```

## Milestone 5

Data dependencies are modeled by mapping the output of a function to the argument index of the target function. 

Example for data dependencies:

```json
{
    "Java_com_example_hellolibs_MainActivity_BytearrayIntIntStringDoubleFloatByte":
    {"sequence": 
      ["Java_com_example_hellolibs_MainActivity_echoJNI", "Java_com_example_hellolibs_MainActivity_addJNI"],
      "data_dependencies": {
        "1": "1",
        "3": "0"
      }
    }
}
```

It is also possible to specify that the output of a function is the calling class of the target function, this is done by specifying the -1 index. Example for whatsapp:

```json
{
    "Java_com_facebook_animated_webp_WebPImage_nativeGetHeight":
    {"sequence": 
      ["Java_com_facebook_animated_webp_WebPImage_nativeCreateFromDirectByteBuffer"],
      "data_dependencies": {
        "-1": "0"
      }
    }
}
```

## Heuristics

In order to reduce the number of false positive crashes a number of heuristics may be applied. 

### Data dependency return type check

If a callsequence with some data dependency is given. The harness checks the return value, which will be used as input later on, to ensure that no invalid value is passed in further along.

**Return type** -> Check

- **long**: check if the value is not null. If it is return right away. Since longs are usually pointers to some native object a null pointer indicates that something went wrong during the initialization. 

- **jobject**: Check if the value is not null. If an object is supposed to be returned but the pointer is null then again very likely something has gone wrong.

