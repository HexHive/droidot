"""
Automatic harness generation based on output of static dalvik app analysis
v0.1: function signature
v0.2: function signature + constraints on arguments
v0.3: function with a callsequence
v0.4: function with a callsequence and dependencies
TODO: group functions by class but also take inheritance into account
TODO: add option to just instantiate a generic object for unsupported objects
"""
import sys
import argparse
import shutil
import logging
import os
import json
BASE_PATH = os.path.dirname(__file__)
sys.path.append(os.path.join(BASE_PATH, '..'))
sys.path.append(os.path.join(BASE_PATH,'./lib'))

import seed_generator
import parse_analysis
from lib.define import *
import lib.utils as utils

RED='\033[0;31m'                                                   
YELLOW='\033[0;33m'                                                                                                                          
GREEN='\033[0;32m'                                                                                                                           
NC='\033[0m'                                                                                                                                 
BLUE='\033[0;34m'         # Blue                                      
PURPLE='\033[0;35m'       # Purple                                                                                                           
CYAN='\033[0;36m'         # Cyan 

ALL_APPS = 0
FUNCTIONS_WITH_HARNESS = 0
ALL_FUNCTIONS = 0


logging.basicConfig(filename='harness_generation.log', encoding='utf-8', level=logging.ERROR, format='%(asctime)s %(message)s')


def generate_fname_meta(with_arg_value_constraints, with_phenomenon_callsequence, with_io_matching, with_arg_value_constraints_gaps):
    out = ''
    if with_arg_value_constraints:
        out += 'arg-'
    if with_arg_value_constraints_gaps:
        out += 'arg2-'
    if with_phenomenon_callsequence:
        out += 'cs-'
    if with_io_matching:
        out += 'io-'
    if len(out) > 1:
        out = out[:-1]
    return out


def generate_functionDefinition(index, arguments, return_type):
    """
    @arguments: list with dictionaries containing info on the arguments {"type": jint, ...[Constraints TODO]}
    @return_type: the return type of the function jstring, void, jint...
    @returns: a c++ codestring which can be inserted into harness_skeleton.cpp for the target function definition and the c++ codestring for the nr of arguments
    """
    if return_type in TYPE_MAPPING_HARNESS:
        functionDefinition = f"typedef {TYPE_MAPPING_HARNESS[return_type]} function_{index}(JNIEnv *, jobject,"
    else:
        functionDefinition = f"typedef {return_type} function_{index}(JNIEnv *, jobject,"
    for arg in arguments:
        if arg['type'] in TYPE_MAPPING_HARNESS:
            functionDefinition += f"{TYPE_MAPPING_HARNESS[arg['type']]},"
        else:
            functionDefinition += f"{arg['type']},"
    functionDefinition = functionDefinition[:-1]
    functionDefinition += ");\n"
    return functionDefinition


def generate_functionGlobal(index):
    """
    generate the global variable function decleartions
        function_0* targetFunctionPtr0;

    """
    global_def = f'function_{index}* targetFunctionPtr{index};\n'
    return global_def


def generate_libraryName(library):
    return f'\t\ttargetLibName = "{library}";\n'


def generate_className(function_name):
    # com_example_MainActivity = "/com/example/MainActivity";
    className = function_name.replace("_1", "#")
    if className.find("__") != -1:
        className = className[:className.find("__")]
    className = className[className.find("_")+1:className.rfind("_")]
    className = className.replace("_", "/")
    return className


def generate_functionOffsetDefintion(index, offset):
    offsetDef = f"\t\ttargetFunctionPtr{index} = (function_{index} *) (targetLibBase + {offset});\n"
    return offsetDef


def generate_fuzzingStub(function_index, argument, argument_index, last_arg=False):
    """
    This function mostly inserts the functions from harness.h
    @argument: dictionary containing info of the argument {"type": jint, ...[Constraints TODO]}, the constraints are in a form that can be directly inserted into the c++ code (translation done in constraint parsing)
    @index: Position of the argument in the function as well as the index into the input vector
    @returns: a c++ codestring which can be inserted into harness_skeleton.cpp as the fuzzing stub for that argument
    """
    fuzzingStub = ""
    jinput = f"jinput{function_index}_{argument_index}"
    # Fixed length argument types
    if argument["type"] == "jint":
        # static constraint
        if "constraints" in argument: 
            if "lengthof" in argument["constraints"]:
                lengthof_arg = f'jinput{function_index}_{argument["constraints"]["lengthof"]["bytearr_arg"]}'
                fuzzingStub += f"\t\tjint {jinput} =  env->GetArrayLength({lengthof_arg});\n"
            elif "filedescriptor" in argument["constraints"]:
                if last_arg:
                    fuzzingStub += f"\t\tstd::string {jinput}_string_value = fuzzed_data.ConsumeRemainingBytesAsString();\n"
                else:
                    fuzzingStub += f"\t\tstd::string {jinput}_string_value = consumeBytes2StringLV(&fuzzed_data, {NR_LV_SIZE_BYTES});\n"
                fuzzingStub += f"\t\tstd::fstream {jinput}_infile; std::string {jinput}_inpath = memoryPath + \"/{jinput}_infile\"; {jinput}_infile.open({jinput}_inpath,std::fstream::out | std::fstream::binary); {jinput}_infile << {jinput}_string_value; {jinput}_infile.close();\n"
                fuzzingStub += f"\t\tFILE * {jinput}_file = fopen({jinput}_inpath.c_str(), \"r\");"
                fuzzingStub += f"\t\tjint {jinput} = (jint) fileno({jinput}_file);\n"
            elif "equals" in argument["constraints"]:
                fuzzingStub += f"\t\tjint {jinput} = (jint) {argument['constraints']['equals']['value']};\n"
            elif "stdlib" in argument["constraints"]:
                logging.debug(f"stdlib constraint: {argument}")
                min_value = "INT_MIN"
                max_value = "INT_MAX"
                fuzzingStub += f"\t\tjint {jinput} = consumeBytes2Jint(&fuzzed_data, {min_value}, {max_value});\n"
            elif "same_var" in argument["constraints"]:
                same_var_ind = argument["constraints"]["var"]
                fuzzingStub += f"\t\tjint {jinput} = jinput{function_index}_{same_var_ind};\n" 
            else:
                print(f"{RED}[!!]{NC} unhandled contraint ", argument)
                exit(-1)
        else:
            min_value = "INT_MIN"
            max_value = "INT_MAX"
            fuzzingStub += f"\t\tjint {jinput} = consumeBytes2Jint(&fuzzed_data, {min_value}, {max_value});\n"
    elif argument["type"] == "jshort":
        # static constraint
        if "constraints" in argument:
            if "equals" in argument["constraints"]:
                fuzzingStub += f"\t\tjshort {jinput} = (jshort) {argument['constraints']['equals']['value']};\n"
            elif "same_var" in argument["constraints"]:
                same_var_ind = argument["constraints"]["var"]
                fuzzingStub += f"\t\tjshort {jinput} = jinput{function_index}_{same_var_ind};\n" 
        else:
            min_value = "SHRT_MIN"
            max_value = "SHRT_MAX"
            fuzzingStub += f"\t\tjshort {jinput} = consumeBytes2Jshort(&fuzzed_data, {min_value}, {max_value});\n"
    elif argument["type"] == "jboolean":
        # static constraint
        if "constraints" in argument:
            if "equals" in argument["constraints"]:
                fuzzingStub += f"\t\tjboolean {jinput} = (jboolean) {argument['constraints']['equals']['value']};\n"
            elif "same_var" in argument["constraints"]:
                same_var_ind = argument["constraints"]["var"]
                fuzzingStub += f"\t\tjboolean {jinput} = jinput{function_index}_{same_var_ind};\n" 
        else:
            fuzzingStub += f"\t\tjboolean {jinput} = consumeBytes2Jboolean(&fuzzed_data);\n"
    elif argument["type"] == "jbyte":
        # static constraint
        if "constraints" in argument:
            if "equals" in argument["constraints"]:
                fuzzingStub += f"\t\tjbyte {jinput} = (jbyte) {argument['constraints']['equals']['value']};\n"
            elif "same_var" in argument["constraints"]:
                same_var_ind = argument["constraints"]["var"]
                fuzzingStub += f"\t\tjbyte {jinput} = jinput{function_index}_{same_var_ind};\n"  
        else:
            fuzzingStub += f"\t\tjbyte {jinput} = consumeBytes2Jbyte(&fuzzed_data);\n"
    elif argument["type"] == "jchar":
        # static constraint
        if "constraints" in argument:
            if "equals" in argument["constraints"]:
                fuzzingStub += f"\t\tjchar {jinput} = (jchar) {argument['constraints']['equals']['value']};\n"
            elif "same_var" in argument["constraints"]:
                same_var_ind = argument["constraints"]["var"]
                fuzzingStub += f"\t\tjchar {jinput} = jinput{function_index}_{same_var_ind};\n"  
        else:
            fuzzingStub += f"\t\tjchar {jinput} = consumeBytes2Jchar(&fuzzed_data);\n"
    elif argument["type"] == "jlong":
        # static constraint
        if "constraints" in argument:
            if "equals" in argument["constraints"]:
                fuzzingStub += f"\t\tjlong {jinput} = (jlong) {argument['constraints']['equals']['value']};\n"
            elif "same_var" in argument["constraints"]:
                same_var_ind = argument["constraints"]["var"]
                fuzzingStub += f"\t\tjlong {jinput} = jinput{function_index}_{same_var_ind};\n"
        else:
            min_value = "LONG_MIN"
            max_value = "LONG_MAX"
            fuzzingStub += f"\t\tjlong {jinput} = consumeBytes2Jlong(&fuzzed_data, {min_value}, {max_value});\n"
    elif argument["type"] == "jfloat":
        # static constraint
        if "constraints" in argument:
            if "equals" in argument["constraints"]:
                fuzzingStub += f"\t\tjfloat {jinput} = (jfloat) {argument['constraints']['equals']['value']};\n"
            elif "same_var" in argument["constraints"]:
                same_var_ind = argument["constraints"]["var"]
                fuzzingStub += f"\t\tjfloat {jinput} = jinput{function_index}_{same_var_ind};\n"
        else:
            fuzzingStub += f"\t\tjfloat {jinput} = consumeBytes2Jfloat(&fuzzed_data);\n"
    elif argument["type"] == "jdouble":
        # static constraint
        if "constraints" in argument:
            if "equals" in argument["constraints"]:
                fuzzingStub += f"\t\tjdouble {jinput} = (jdouble) {argument['constraints']['equals']['value']};\n"
            elif "same_var" in argument["constraints"]:
                same_var_ind = argument["constraints"]["var"]
                fuzzingStub += f"\t\tjdouble {jinput} = jinput{function_index}_{same_var_ind};\n"
        else:
            fuzzingStub += f"\t\tjdouble {jinput} = consumeBytes2Jdouble(&fuzzed_data);\n"
    # Variable length argument types
    elif argument["type"] == "jstring":
        # static constraint
        if "constraints" in argument:
            if "filepath" in argument["constraints"]:
                if last_arg:
                    fuzzingStub += f"\t\tstd::string {jinput}_string_value = fuzzed_data.ConsumeRemainingBytesAsString();\n"
                else:
                    fuzzingStub += f"\t\tstd::string {jinput}_string_value = consumeBytes2StringLV(&fuzzed_data, {NR_LV_SIZE_BYTES});\n"
                fuzzingStub += f"\t\tstd::fstream {jinput}_infile; std::string {jinput}_inpath = memoryPath + \"/{jinput}_infile\"; {jinput}_infile.open({jinput}_inpath,std::fstream::out | std::fstream::binary); {jinput}_infile << {jinput}_string_value; {jinput}_infile.close();\n"
                fuzzingStub += f"\t\tjstring {jinput} = env->NewStringUTF({jinput}_inpath.c_str());\n"
            elif "equals" in argument["constraints"]:
                fuzzingStub += f"\t\tstd::string {jinput}_str = {argument['constraints']['equals']['value']};\n"
                fuzzingStub += f"\t\tjstring {jinput} = env->NewStringUTF({jinput}_str.c_str());\n"     
            elif "same_var" in argument["constraints"]:
                same_var_ind = argument["constraints"]["var"]
                fuzzingStub += f"\t\tjstring {jinput} = jinput{function_index}_{same_var_ind};\n"
            else:
                logging.error(f"unknown constraint for {argument}")
        else:
            if last_arg:
                fuzzingStub += f"\t\tjstring {jinput} = consumeBytes2Jstring(&fuzzed_data, env);\n"
            else:
                fuzzingStub += f"\t\tjstring {jinput} = consumeBytes2JstringLV(&fuzzed_data, env, {NR_LV_SIZE_BYTES});\n"
    elif argument["type"] == "jbyteArray":
       # static constraint
        if "constraints" in argument:
            if "equals" in argument["constraints"]:
                fuzzingStub += f"\t\tstd::vector<uint8_t> {jinput}_vector = {argument['constraints']['equals']['value']};\n"
                fuzzingStub += f"\t\tuint8_t* {jinput}_native = (uint8_t *) calloc({jinput}_vector.size(), sizeof(uint8_t));\n"
                fuzzingStub += f"\t\tmemcpy({jinput}_native, &{jinput}_vector[0], {jinput}_vector.size() * sizeof(uint8_t));\n"
                fuzzingStub += f"\t\tjbyteArray {jinput} = env->NewByteArray({jinput}_vector.size());\n"
                fuzzingStub += f"\t\tenv->SetByteArrayRegion({jinput}, 0,  {jinput}_vector.size(), (jbyte *){jinput}_native);\n"
            elif "empty_array" in argument["constraints"]:
                if "len" in argument["constraints"]["empty_array"]:
                    lenght = argument["constraints"]["empty_array"]["len"]
                    fuzzingStub += f'\t\tjbyteArray {jinput} = env->NewByteArray({lenght});\n'
                else:
                    min_value = "INT_MIN"
                    max_value = "INT_MAX"
                    fuzzingStub += f"\t\tjint {jinput}_size = consumeBytes2Jint(&fuzzed_data, {min_value}, {max_value});\n"
                    fuzzingStub += f'\t\tjbyteArray {jinput} = env->NewByteArray({jinput}_size);\n'
            elif "max_array_length" in argument["constraints"]:
                print("TODO implement max_array_length!!")
                exit(-1)
                """
                length = argument["constraints"]["max_array_length"]["len"]
                fuzzingStub += f"\t\tstd::vector<uint8_t> {jinput}_vector = {argument['constraints']['equals']['value']};\n"
                fuzzingStub += f"\t\tuint8_t* {jinput}_native = (uint8_t *) calloc({jinput}_vector.size(), sizeof(uint8_t));\n"
                fuzzingStub += f"\t\tmemcpy({jinput}_native, &jinput{jinput}_vector[0], {jinput}_vector.size() * sizeof(uint8_t));\n"
                fuzzingStub += f"\t\tint {jinput}_size = {length};\n"
                fuzzingStub += f"\t\tif({length}<{jinput}_vector.size()){jinput}_size = {jinput}_vector.size();\n"
                fuzzingStub += f"\t\tjbyteArray {jinput} = env->NewByteArray({jinput}_size);\n"
                fuzzingStub += f"\t\tenv->SetByteArrayRegion({jinput}, 0,  {jinput}_size, (jbyte *){jinput}_native);\n"
                """
            elif "same_var" in argument["constraints"]:
                same_var_ind = argument["constraints"]["var"]
                fuzzingStub += f"\t\tjbyteArray {jinput} = jinput{function_index}_{same_var_ind};\n"
            else:
                print(f'unknown constraint: {argument}')
                exit(-1)
        else:
            if last_arg:
                fuzzingStub += f"\t\tjbyteArray {jinput} = consumeBytes2JbyteArray(&fuzzed_data, env);\n"
            else:
                fuzzingStub += f"\t\tjbyteArray {jinput} = consumeBytes2JbyteArrayLV(&fuzzed_data, env, {NR_LV_SIZE_BYTES});\n"
    elif argument["type"] == "ByteBuffer":
        # TODO support constraints
        if "constraints" in argument:
            if "same_var" in argument["constraints"]:
                same_var_ind = argument["constraints"]["var"]
                fuzzingStub += f"\t\tjobject {jinput} = jinput{function_index}_{same_var_ind};\n"
        if last_arg:
            fuzzingStub += f"\t\tjobject {jinput} = consumeBytes2ByteBuffer(&fuzzed_data, env);\n"
        else:
            fuzzingStub += f"\t\tjobject {jinput} = consumeBytes2ByteBufferLV(&fuzzed_data, env, {NR_LV_SIZE_BYTES});\n"
    elif argument["type"] == "jbooleanArray":
        if "constraints" in argument:
            if "empty_array" in argument["constraints"] and "len" in argument["constraints"]["empty_array"]:
                length = argument["constraints"]["empty_array"]["len"]
                fuzzingStub += f"\t\tjbooleanArray {jinput} = env->NewBooleanArray({length});\n"
            else:
                fuzzingStub += f"\t\tjbooleanArray {jinput} = nullptr;\n"
        else:
            fuzzingStub += f"\t\tjbooleanArray {jinput} = env->NewBooleanArray(1);\n"
    elif argument["type"] == "jcharArray":
        if "constraints" in argument:
            if "empty_array" in argument["constraints"] and "len" in argument["constraints"]["empty_array"]:
                length = argument["constraints"]["empty_array"]["len"]
                fuzzingStub += f"\t\tjcharArray {jinput} = env->NewCharArray({length});\n"
            else:
                fuzzingStub += f"\t\tjcharArray {jinput} = nullptr;\n"
        else:
            fuzzingStub += f"\t\tjcharArray {jinput} = env->NewCharArray(1);\n"
    elif argument["type"] == "jshortArray":
        if "constraints" in argument:
            if "empty_array" in argument["constraints"] and "len" in argument["constraints"]["empty_array"]:
                length = argument["constraints"]["empty_array"]["len"]
                fuzzingStub += f"\t\tjshortArray {jinput} = env->NewShortArray({length});\n"
            else:
                fuzzingStub += f"\t\tjshortArray {jinput} = nullptr;\n"
        else:
            fuzzingStub += f"\t\tjshortArray {jinput} = env->NewShortArray(1);\n"
    elif argument["type"] == "jintArray":
        if "constraints" in argument:
            if "empty_array" in argument["constraints"] and "len" in argument["constraints"]["empty_array"]:
                length = argument["constraints"]["empty_array"]["len"]
                fuzzingStub += f"\t\tjintArray {jinput} = env->NewIntArray({length});\n"
            else:
                fuzzingStub += f"\t\tjintArray {jinput} = nullptr;\n"
        else:
            fuzzingStub += f"\t\tjintArray {jinput} = env->NewIntArray(1);\n"
    elif argument["type"] == "jlongArray":
        if "constraints" in argument:
            if "empty_array" in argument["constraints"] and "len" in argument["constraints"]["empty_array"]:
                length = argument["constraints"]["empty_array"]["len"]
                fuzzingStub += f"\t\tjlongArray {jinput} = env->NewLongArray({length});\n"
            else:
                fuzzingStub += f"\t\tjlongArray {jinput} = nullptr;\n"
        else:
            fuzzingStub += f"\t\tjlongArray {jinput} = env->NewLongArray(1);\n"
    elif argument["type"] == "jfloatArray":
        if "constraints" in argument:
            if "empty_array" in argument["constraints"] and "len" in argument["constraints"]["empty_array"]:
                length = argument["constraints"]["empty_array"]["len"]
                fuzzingStub += f"\t\tjfloatArray {jinput} = env->NewFloatArray({length});\n"
            else:
                fuzzingStub += f"\t\tjfloatArray {jinput} = nullptr;\n"
        else:
            fuzzingStub += f"\t\tjfloatArray {jinput} = env->NewFloatArray(1);\n"
    elif argument["type"] == "jdoubleArray":
        if "constraints" in argument:
            if "empty_array" in argument["constraints"] and "len" in argument["constraints"]["empty_array"]:
                length = argument["constraints"]["empty_array"]["len"]
                fuzzingStub += f"\t\tjdoubleArray {jinput} = env->NewDoubleArray({length});\n"
            else:
                fuzzingStub += f"\t\tjdoubleArray {jinput} = nullptr;\n"
        else:
            fuzzingStub += f"\t\tjdoubleArray {jinput} = env->NewDoubleArray(1);\n"
    elif argument["type"] == "jobject":
        # argument is a generic jobject just instantiate it
        if "constraints" in argument: 
            if "equals" in argument["constraints"] and argument["constraints"]["equals"]["value"] == "null":
                fuzzingStub += f'\t\tjobject {jinput} = nullptr;\n'
            elif "same_var" in argument["constraints"]:
                same_var_ind = argument["constraints"]["var"]
                fuzzingStub += f"\t\tjobject {jinput} = jinput{function_index}_{same_var_ind};\n"
            else:
                print(f'unknown object constraint {argument}')
                fuzzingStub += f'\t\tjclass {jinput}_cls = env->FindClass("java/lang/Object");\n'
                fuzzingStub += f'\t\tjobject {jinput} = env->AllocObject({jinput}_cls);\n'
        else:
            fuzzingStub += f'\t\tjclass {jinput}_cls = env->FindClass("java/lang/Object");\n'
            fuzzingStub += f'\t\tjobject {jinput} = env->AllocObject({jinput}_cls);\n'
    else: 
        print(f"{RED}[+]{NC} Unsupported type {argument['type']}!")
        exit(1)
    return fuzzingStub


def generate_functionCall(index, arguments, ret_type, data_dependencies, last_call=False, afl_coverage_on=False):
    if "-1" in data_dependencies:
        callerObj = f"jout{data_dependencies['-1']['findex']}"
    else:
        callerObj = f"CallerObj0"
    if ret_type == "void":
        functionCall = f"\t\ttargetFunctionPtr{index}(env, {callerObj},"
    else:
        if ret_type in TYPE_MAPPING_HARNESS:
            functionCall = f"\t\t{TYPE_MAPPING_HARNESS[ret_type]} jout{index} = targetFunctionPtr{index}(env, {callerObj},"
        else:
            functionCall = f"\t\t{ret_type} jout{index} = targetFunctionPtr{index}(env, {callerObj},"
    need_checks_long = []
    for i, arg in enumerate(arguments):
        if str(i) in data_dependencies:
            functionCall += f"jout{data_dependencies[str(i)]['findex']},"
            if arg["type"] == "jlong":
                # if an argument is long, based on data dependency
                need_checks_long.append(data_dependencies[str(i)]['findex'])
        else:
            functionCall += f"jinput{index}_{i},"
    functionCall = functionCall[:-1]
    functionCall += ");\n"
    if len(need_checks_long) > 0:
        check = ""
        for ind in need_checks_long:
            check += f"\t\tif(jout{ind}==0 || jout{ind} == -1){{_exit(1);}}\n"
        functionCall = check + functionCall
    functionCall = "if (env->ExceptionCheck()) {env->ExceptionClear();}\n" + functionCall
    if afl_coverage_on:
        if last_call:
            afl_coverage_reset = "memcpy(__my_dummy, *afl_area_ptr, 65536); \n"
            return afl_coverage_reset + functionCall
        if index == 0:
            afl_coverage_backup = "memcpy(*afl_area_ptr, __my_dummy, 65536); \n"
            return afl_coverage_backup + functionCall
    return functionCall


def generate_harness(harness_skeleton, callsequence, afl_coverage_on=False):
    """
    Opens the harness skeleton and inserts the necessary code for the harness
    callsequence is a list of the form [{"name": "[FUNCTIONNAME]", "arguments":[ARGUMENTS]}]
    """
    info_json = {} #json file holding some info about the harness
    # Insert the necessary code
    # generate function definition
    fDef = ""
    for i, f in enumerate(callsequence):
        fDef += generate_functionDefinition(i, f["signature"]["args"], f["signature"]["ret_type"])
    logging.debug(f"[+] generated function definition: {fDef}")
    harness_skeleton = harness_skeleton.replace("GENERATOR_FUNCTIONDEFINTION", fDef)
    # generate function offsets
    globF = ""
    for i, f in enumerate(callsequence):
        globF += generate_functionGlobal(i)
    harness_skeleton = harness_skeleton.replace("GENERATOR_GLOBALFUNCTIONS", globF)
    functionOffsets = ""
    for i, f in enumerate(callsequence):
        functionOffsets += generate_functionOffsetDefintion(i, f["signature"]["offset"])
    harness_skeleton = harness_skeleton.replace("GENERATOR_FUNCTIONOFFSETS", functionOffsets)
    logging.debug(f"generated function offset definitions: {functionOffsets}")
    # generate object creation
    # generate data consumers
    fuzzingStubs = ""
    logging.debug(f'{callsequence} generating fuzzing stub')
    for i, f in enumerate(callsequence):
        for j, arg in enumerate(f["signature"]["args"]):
            # if the input value depends on the output of a previous function, we don't need to consume any input for that input
            if str(j) in f["data_dependencies"]:
                continue
            else:
                # TODO: check if following arguments are constrained/don't consume input
                last_arg = (i==len(callsequence)-1 and j==len(f["signature"]["args"])-1)
                if not last_arg:
                    all_args_found = True
                    # finish for current function
                    for k in range(j+1, len(f["signature"]["args"])):
                        arg_tmp = f["signature"]["args"][k]
                        if str(k) not in f["data_dependencies"] and not ("constraints" in arg_tmp and ("equals" in arg_tmp["constraints"] or "lengthof" in arg_tmp["constraints"])):
                            #print(f"{f}, setting to False")
                            all_args_found = False
                            break
                    # check all following functions
                    for k in range(i+1, len(callsequence)):
                        for m, arg_tmp in enumerate(callsequence[k]["signature"]["args"]):
                            if str(m) not in callsequence[k]["data_dependencies"] and not ("constraints" in arg_tmp and ("equals" in arg_tmp["constraints"] or "lengthof" in arg_tmp["constraints"])):
                                all_args_found = False
                                break
                    if all_args_found:
                        last_arg = True
                fuzzingStubs += generate_fuzzingStub(i, arg, j, last_arg=last_arg)
    harness_skeleton = harness_skeleton.replace("GENERATOR_INPUTPARSING", fuzzingStubs)
    logging.debug(f"[+] generated fuzzing stubs: {fuzzingStubs}")
    # generate function calls
    fCalls = ""
    for i, f in enumerate(callsequence):
        last_call = i == (len(callsequence)-1) 
        fCalls += generate_functionCall(i, f["signature"]["args"], f["signature"]["ret_type"], f["data_dependencies"], last_call=last_call, afl_coverage_on=(afl_coverage_on and len(callsequence)>1))
    harness_skeleton = harness_skeleton.replace("GENERATOR_CALLINGTARGETFUNCTION", fCalls)
    logging.debug(f"[+] generated targetfunction Call: {fCalls}")
    info_json["targetlibrary"] = callsequence[-1]["signature"]["library"]
    info_json["targetclassname"] = generate_className(callsequence[-1]["name"])
    info_json["callsequence"] = callsequence
    return harness_skeleton, info_json


def insert_targetlibraries(afljs_skeleton, app, callsequence):
    """
    looks which libraries may be used by the target library and inserts these to be instrumented by frida
    """
    lib_name = callsequence[-1]["signature"]["library"]
    lib_path = os.path.join(TARGET_APK_PATH, app, "lib", "arm64-v8a", lib_name)
    libs_to_instrument = utils.get_shared_libs(lib_path)
    libs_to_instrument.append(lib_name)
    logging.info(f"[FRIDA] libraries to add {libs_to_instrument}")
    libs_js_string = ""
    for lib in libs_to_instrument:
        libs_js_string += f'"{lib}", '
    libs_js_string = libs_js_string[:-2]
    afljs_skeleton = afljs_skeleton.replace("GENERATOR_TARGETLIBRARIES", libs_js_string)
    return afljs_skeleton


def insert_performance_hack(afljs_skeleton, with_unmapping=False):
    hack_code = """
                var performance_hack = Module.findExportByName('libharness.so', '_Z16performance_hackv');
                Afl.print('loaded performance_hack' + performance_hack);
                const func_performance_hack = new NativeFunction(performance_hack, 'void', []);
                Afl.print('loaded performance_hack function' +  func_performance_hack);
                func_performance_hack();
                Afl.print('finished running hack');
                """
    if with_unmapping:
        afljs_skeleton = afljs_skeleton.replace("GENERATOR_PERFORMANCE_HACK", hack_code)
    else:
        afljs_skeleton = afljs_skeleton.replace("GENERATOR_PERFORMANCE_HACK", "// no hack")
    return afljs_skeleton

def generate_harness_seeds_for_APK(target, use_existing_harness_generation_callsequences, 
 with_arg_value_constraints, with_arg_value_constraints_gaps, with_phenomenon_callsequence, phenom_cs_min_length,
 with_cs_io_gaps, with_callsequence_heuristic, with_constraints_heuristic, 
 with_io_matching, with_generic_jobject, only_constrained, only_fuzzable, with_unmapping=False, afl_coverage_on=False, with_harness_vis=False):
    """
    Writes the generated harnesses into the target APK/harnesses/[FUNCTIONNAME]/harness.cpp
    Also generates seeds in APK/harnesses/[FUNCTIONNAME]/seeds
    @target: The target APK foldername containing the analysis output
    """
    print(f"{PURPLE}[HARNESS]{NC} Generating harnesses for {target}")
    global ALL_APPS, ALL_FUNCTIONS, FUNCTIONS_WITH_HARNESS 
    ALL_APPS += 1
    harnessess_path = os.path.join(TARGET_APK_PATH, target, "harnesses")
    if not os.path.exists(harnessess_path):
        os.mkdir(harnessess_path)
    if use_existing_harness_generation_callsequences:
        if not os.path.exists(os.path.join(TARGET_APK_PATH, target, "harness_generation_callsequences.json")):
            print(f"{RED}[HARNESS]{NC} no harness_generation_callsequences.json file, exiting")
            exit(0)
        with open(os.path.join(TARGET_APK_PATH, target, "harness_generation_callsequences.json"), "r") as f:
            harness_generation_callsequence = json.loads(f.read())
    else:
        harness_generation_callsequence = parse_analysis.parse_static(target, 
                                            with_arg_value_constraints=with_arg_value_constraints,
                                            with_arg_value_constraints_gaps=with_arg_value_constraints_gaps,
                                            with_phenomenon_callsequence=with_phenomenon_callsequence,
                                            with_cs_io_gaps=with_cs_io_gaps,
                                            phenom_cs_min_length=phenom_cs_min_length,
                                            with_callsequence_heuristic=with_callsequence_heuristic,
                                            with_constraints_heuristic=with_constraints_heuristic,
                                            with_io_matching=with_io_matching,
                                            with_generic_jobject=with_generic_jobject,
                                            only_constrained=only_constrained,
                                            only_fuzzable=only_fuzzable)
    meta_harness_2_nr_fuzz_args = {}
    fname_meta_info = generate_fname_meta(with_arg_value_constraints, with_phenomenon_callsequence, with_io_matching, with_arg_value_constraints_gaps)
    for fname in harness_generation_callsequence:
        harness_name = "harness.cpp"
        harness_debug_name = "harness_debug.cpp"
        func_name = fname.split("@")[0]
        counter = fname.split("@")[1]
        fname_ouput = func_name + "@" + fname_meta_info + "@" + counter
        ALL_FUNCTIONS += 1
        # setup harness folder structure
        harness_path = os.path.join(harnessess_path, fname_ouput)
        if not os.path.exists(harness_path):
            os.mkdir(harness_path)
        # generate the fuzzing harness
        with open(f"{BASE_PATH}/cpp/harness_skeleton.cpp", "r") as f:
            harness_skeleton = f.read()
        logging.debug(f'second generating harness {fname} {harness_generation_callsequence[fname]}')
        harness, info_json = generate_harness(harness_skeleton, harness_generation_callsequence[fname], afl_coverage_on=afl_coverage_on)
        output_path = os.path.join(harness_path, harness_name)
        with open(output_path, "w") as f:
            f.write(harness)
        # for the fuzzing harness generate corresponding afl.js
        with open(f"{BASE_PATH}/cpp/afl_skeleton.js", "r") as f:
            afljs_skeleton = f.read()
        afl_js = insert_targetlibraries(afljs_skeleton, target, harness_generation_callsequence[fname])
        afl_js = insert_performance_hack(afl_js, with_unmapping)
        output_path = os.path.join(harness_path, "afl.js")
        with open(output_path, "w") as f:
            f.write(afl_js)
        # generate the debug harness
        with open(f"{BASE_PATH}/cpp/harness_skeleton_debug.cpp", "r") as f:
            harness_skeleton = f.read()
        harness_debug, _ = generate_harness(harness_skeleton, harness_generation_callsequence[fname])
        output_path = os.path.join(harness_path, harness_debug_name)
        with open(output_path, "w") as f:
            f.write(harness_debug)
        seed_dir = os.path.join(harness_path, f"seeds")
        # collapse the arguments for all functions into one for the seed generation
        all_args = []
        for f in harness_generation_callsequence[fname]:
            for i, arg in enumerate(f["signature"]["args"]):
                if str(i) in f["data_dependencies"]:
                    # the argument comes from a previous function call, skip check if the type is supported
                    continue
                tofuzz, _ = utils.get_fuzz_needed_type(arg)
                if not tofuzz:
                    continue
                all_args.append(arg)
        if not os.path.exists(seed_dir):
            os.makedirs(seed_dir)
        seeds, nr_args, seed_arg_list = seed_generator.gen_seeds(all_args)
        meta_harness_2_nr_fuzz_args[fname] = nr_args
        info_json["args"] = nr_args
        info_json["seed_arg_list"] = seed_arg_list
        i = 0
        for s_name, value in seeds:
            i += 1
            with open(os.path.join(seed_dir, f"seed_{s_name}_{i}"), "wb") as f:
                f.write(value)
        with open(os.path.join(harness_path, "info.json"), "w") as f:
            f.write(json.dumps(info_json))
        FUNCTIONS_WITH_HARNESS += 1
    with open(os.path.join(TARGET_APK_PATH, target, "harnesses", "meta_harness2nrfuzzargs.json"), "w") as f:
        f.write(json.dumps(meta_harness_2_nr_fuzz_args))
    print(f"{CYAN}[HARNESS]{NC} Finished generating harnesses")
    if with_harness_vis:
        import vis_harnesses
        print(f"[HARNESS]\t Generating Visualization")
        vis_harnesses.draw_harness_graphs(target)
        print(f"[HARNESS]\t Finished generating Visualization")
    
"""
-fuzz -jo_ok # flags for nothing run
-cs_ph -fuzz -jo_ok # flags for phenom only cs pass
-ct_argval2 -fuzz -jo_ok # flags for GAPS argval single function fuzzing
-ct_argval2 -cs_ph -cs_io_argval2 -cs_io -jo_ok -fuzz #ultimate flags for GAPS argval + callsequence
"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='generate harness based on output of static dalvik app analysis')
    parser.add_argument("--target", type=str, required=True, help="name of the app for which to generate the harness, by defaults generates harnesses for all apps in the target_APK folder")
    parser.add_argument("-cl", "--cleanup", required=False, default=False, action="store_true", help="cleanup all harnesses in target_APK")
    parser.add_argument("-ue", "--use_existing_harness_generation_callsequences", default=False, action="store_true", help="don't to static analysis parsing, instead use the existing harness_generatioN_callsequences.json file")
    parser.add_argument("-ct_argval", "--with_arg_value_constraints", default=False, action="store_true", help="parses the output of the argument value analysis and adds the info to the callsequence")
    parser.add_argument("-ct_argval2", "--with_arg_value_constraints_gaps", default=False, action="store_true", help="parses the output of the argument value analysis and adds the info to the callsequence (using output from GAPS)")
    parser.add_argument("-cs_ph", "--with_phenomenon_callsequence", default=False, action="store_true", help="parse the CS_app-debug.json file and add the calls to the callsequence")
    parser.add_argument("-cs_io_argval2", "--with_cs_io_gaps", default=False, action="store_true", help="use the gaps constraints to enrich the callsequence")
    parser.add_argument("-cs_ph_min_len", "--phenom_cs_min_length", type=int, default=1, help="only generate harnesses for functions with phenomenon callsequences of this length (minus main function), default is 1 meaning a callsequnce of length at least 2")
    parser.add_argument("-cs_dh", "--with_callsequence_data_heuristics", default=False, action="store_true", help="generate the harnesses using heuristics to generate data dependencies (STRANGE BEHAVIOR WHEN USED WITH PHENOM CS!!!!)")
    parser.add_argument("-cs_io", "--with_input_output_matching", default=False, action="store_true", help="generate the harnesses with input output matching for data dependencies")
    parser.add_argument("-ct_hr", "--with_enrich_constraints_heuristics", default=False, action="store_true", help="generate the harnesses using (spicy) heuristics to add some data constraints")
    parser.add_argument("-jo_ok", "--use_generic_jobject", default=False, action="store_true", help="if set harnesses for all callsequences are generated, any unsupported argument type ")
    parser.add_argument("-unmap", "--with_unmapping", default=False, action="store_true", help="if set harnesses for fuzzing do the memory dumping hack to increase performance by 3x")
    parser.add_argument("-fuzz", "--only_fuzzable", default=False, action="store_true", help="only generate harnesses for callsequences/functions with at least one byte[], String, ByteBuffer arguments")
    parser.add_argument("-constr", "--only_constrained", default=False, action="store_true", help="only generate harnesses for callsequences/functions with at least one constraint")
    parser.add_argument("--afl_coverage_on", default=False, action="store_true", help="only collect coverage for final function")
    parser.add_argument("--harness_vis", default=False, action="store_true", help="generate the harness_vis folder to visualize the harnesses")
    args = parser.parse_args()

    if args.cleanup:
        print(f"{PURPLE}[CLEAN]{NC} starting cleanup..")
        harness_folder = os.path.join(TARGET_APK_PATH, args.target, "harnesses")
        if os.path.exists(harness_folder):
            shutil.rmtree(harness_folder)
        exit(0)

    if args.with_enrich_constraints_heuristics:
        print(f"{RED} YOU'RE USING A SCIENTIFICALLY UNSOUND FLAG!!!!")
    if args.with_callsequence_data_heuristics:
        print(f"{RED} YOU'RE USING A SCIENTIFICALLY UNSOUND FLAG!!!!")

    if args.with_arg_value_constraints_gaps and args.with_arg_value_constraints:
        print(f'{RED} ONLY USE EITHER -ct_argval or -ct_argval2!!!{NC}')
        exit(-1)

    generate_harness_seeds_for_APK(target=args.target, 
            use_existing_harness_generation_callsequences=args.use_existing_harness_generation_callsequences, 
            with_arg_value_constraints=args.with_arg_value_constraints, 
            with_arg_value_constraints_gaps=args.with_arg_value_constraints_gaps,
            with_phenomenon_callsequence=args.with_phenomenon_callsequence, 
            phenom_cs_min_length=args.phenom_cs_min_length,
            with_cs_io_gaps=args.with_cs_io_gaps,
            with_callsequence_heuristic=args.with_callsequence_data_heuristics,
            with_constraints_heuristic=args.with_enrich_constraints_heuristics,
            with_io_matching=args.with_input_output_matching,
            with_generic_jobject=args.use_generic_jobject,
            only_fuzzable=args.only_fuzzable,
            only_constrained=args.only_constrained,
            with_unmapping=args.with_unmapping,
            afl_coverage_on=args.afl_coverage_on,
            with_harness_vis=args.harness_vis)
        
