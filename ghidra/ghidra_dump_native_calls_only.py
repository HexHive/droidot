# use it with:
# analyzeHeadless $(mktemp -d) HeadlessAnalysis -overwrite -import <file> -scriptPath $(pwd) -postscript ghidra_dump_native_calls.py
import re
import os
from argparse import ArgumentParser
import json
import subprocess

from  ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import Address
from ghidra.program.model.address import DefaultAddressFactory 

from jni_convert import convert

# analyzeHeadless $(mktemp -d) HeadlessAnalysis -overwrite -import ../target_APK/hellolibs2/lib/arm64-v8a/libhello-libs.so -scriptPath $(pwd) -postscript ghidra_dump_native_calls.py ++app_path ../target_APK/hellolibs ++output helloout.txt

# no symbols (isn't able to handle cases where one argument is converted to another => but ok since without symbols this is never used anyways
jni_regex_nosymb = r"([_a-zA-Z0-9]+ = )?(?:\([A-Za-z0-9]+ ?\*?\))?\(\*\*\(code \*\*\)\(\*param_1 \+ ((?:0x)?[a-fA-F0-9]+)\)\)\((.*)\)"
# with symobls
jni_regex_symb = r"([_a-zA-Z0-9]+ = )?_JNIEnv::([A-Za-z0-9]+)\(([^\)]+)\)"
# => set some options then get the param1 usages and analyze that function

function_calls = r"([^ ,\)\*]+)(\([a-z_A-Z0-9,&*\(\)]+\))"

arg_parser = ArgumentParser(description="Opcode statistical analysis", prog='script',
                            prefix_chars='+')
arg_parser.add_argument('+o', '++output', required=True, help='Output file for JSON')
arg_parser.add_argument('+p', '++app_path', required=True, help='Path to app')
args = arg_parser.parse_args(args=getScriptArgs())


if not os.path.exists(args.output):
    os.system("mkdir " + args.output)


def demangle(name):
    args = ['c++filt']
    args.extend(name)
    pipe = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, _ = pipe.communicate()
    demangled = stdout.split(b"\n")
    return demangled.decode()


def parse_sig_lib_offsets(filepath, libname):
    """
    parse the content of the signatures_libraries_offsets.txt file
    returns a list of functionInfo objects
    """
    if libname.endswith("_nocov"):
        libname = libname.split("_nocov")[0]
    output_list = {}
    sigs_libs_offsets = open(filepath).read().split("\n")
    # TODO: handle overloading
    for line in sigs_libs_offsets:
        if line == '':
            continue
        split = line.split(" ")
        fname = split[0]
        sig = split[1]
        ret_type = sig.split(":")[0]
        arg_list = sig.split(":")[1].split(",")
        library = split[2]
        offset = int(split[3])
        if library == libname:
            output_list[offset] = {'java_name': fname, 'args': arg_list, 'ret': ret_type}
    return output_list


def parse_jni_usages_symb(usages):
    output_json = []
    for usage in usages:
        if len(usage) == 3:
            api = usage[1]
        elif len(usage) == 2:
            api = usage[0]
        else:
            print(usage)
            return {}
        output_json.append(api)
    return output_json


def parse_jni_usages_nosymb(usages):
    output_json = []
    for usage in usages:
        if len(usage) == 3:
            offset = usage[1]
        elif len(usage) == 2:
            offset = usage[0]
        else:
            print(usage)
            return {}
        jnifunc = convert(offset)
        output_json.append(jnifunc)
        #print(extract_string)
    return output_json


def parse_function_call(calls):
    output = []
    output_json = []
    for call in calls:
        fname = call[0]
        if "JNIEnv" in fname:
            continue
        params = call[1][1:-1].split(",")
        if "param_1" == params[0]: # hack to only follow cases where jnienv is the first argument
            output_json.append({"fname": fname, "params": params})
            output.append(fname + call[1])
    return output, output_json


program = currentProgram
memory = program.getMemory()
addressFactory = currentProgram.getAddressFactory()
binaryPath = currentProgram.getExecutablePath()
if "/lib/arm64-v8a/" in binaryPath:
    app = binaryPath.split("/")[-4]
else:
    app = ""
filename = os.path.basename(binaryPath)
print(binaryPath)
print("===================jni script analyzing: " + filename + "==========================")

if filename.endswith("nocov"):
    sig_lib_path = os.path.join(args.app_path, "signatures_libraries_offsets_nocov.txt")
else:
    sig_lib_path = os.path.join(args.app_path, "signatures_libraries_offsets.txt")

if not os.path.exists(sig_lib_path):
    print("no singature libraries offsets file, exiting")
    exit(0)

libfunctions = parse_sig_lib_offsets(sig_lib_path, filename) # return dictioniary offset2fname+signature

if len(libfunctions) == 0:
    print("no java signatures for library, exiting")
    exit(0)

outpath = os.path.join(args.output, app + "_" + filename + ".jnifuncs")
outpath_json = os.path.join(args.output, app + "_" + filename + ".jnifuncs.json")
outjson = []
outfile = open(outpath, "w")

base_address = program.getImageBase().getUnsignedOffset()

decompinterface = DecompInterface()
decompinterface.openProgram(program)
functions = program.getFunctionManager().getFunctions(True)
func_dict = {}
for function in list(functions):
    func_dict[str(function)] = function

for function in func_dict.values():
    # TODO: use the offsets from signatures_libraries_offsets to do this
    function_offset = int(function.getEntryPoint().getUnsignedOffset() - base_address)
    #print(function_offset, function.getName())
    if function.getName().startswith("Java"):
        print(function)
        print("f_offset:", function.getEntryPoint().getUnsignedOffset())
        print(function_offset)
    if function_offset in libfunctions:
        java_fname = libfunctions[function_offset]["java_name"]
        ret_type = libfunctions[function_offset]["ret"]
        arguments = libfunctions[function_offset]["args"]
        print("analyzing function: ", java_fname)
        decomp_results = decompinterface.decompileFunction(function, 30, monitor)
        outfile.write(java_fname + " " + ret_type + ":" + ",".join(arguments) + "\n")
        if decomp_results.decompileCompleted():
            fn_sig = decomp_results.getDecompiledFunction().getSignature()
            outfile.write("ghidra signature:" + fn_sig+"\n")
            fn_code = decomp_results.getDecompiledFunction().getC()
            #print(java_fname, fn_code)
            lines = fn_code.split("\n")
            function_data = {"java_function": libfunctions[function_offset], "jni_api_calls": [], "status": "decompiled_success"}
            for l in lines:
                jni_found = False
                jniapi_usages = re.findall(jni_regex_nosymb, l)
                if len(jniapi_usages) > 0:
                    jni_calls_json = parse_jni_usages_nosymb(jniapi_usages)
                    function_data["jni_api_calls"].append(jni_calls_json)
                jniapi_usages = re.findall(jni_regex_symb, l)
                if len(jniapi_usages) > 0:
                    jni_calls_json = parse_jni_usages_symb(jniapi_usages)
                    function_data["jni_api_calls"].append(jni_calls_json)
            outfile.write("\n" + 0x40*"=" + "\n")      
            outjson.append(function_data)
        else:
            function_data = {"java_function": libfunctions[function_offset], "jni_api_calls": [], "status": "decompiled_error"}
            outjson.append(function_data)
            outfile.write("decompiliation failed+\n")
            outfile.write("\n" + 0x40*"=" + "\n")
            print("error decompiling") 

with open(outpath_json, "w") as f:
    f.write(json.dumps(outjson))
print("finished analysis, writing output to ", outfile.name)
    