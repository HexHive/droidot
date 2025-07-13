import sys
import os
import shutil
import argparse
import subprocess
import json
import logging
from androguard.core.apk import APK
BASE_PATH = os.path.dirname(__file__)
sys.path.append(os.path.join(BASE_PATH, ".."))
# change current path into static_analysis
sys.path.append(os.path.join(BASE_PATH, '..'))

import adb

RED='\033[0;31m'                                                   
YELLOW='\033[0;33m'                                                                                                                          
GREEN='\033[0;32m'                                                                                                                           
NC='\033[0m'                                                                                                                                 
BLUE='\033[0;34m'         # Blue                                      
PURPLE='\033[0;35m'       # Purple                                                                                                           
CYAN='\033[0;36m'         # Cyan 

logging.basicConfig(filename='preprocessor.log', encoding='utf-8', level=logging.DEBUG, format='%(asctime)s %(message)s')

TARGET_APK_PATH = os.path.join(BASE_PATH, "../target_APK")
# folder in which the jniOffsetFinder is run
REMOTE_FOLDER = "/data/local/tmp/offsetFinding/"

LD_PRELOAD_DEFAULT = "/data/data/com.termux/files/usr/lib/libc++_shared.so"

SPECIAL_LOCATIONS = {
    "com.whatsapp": ["/data/data/com.whatsapp/files/decompressed/libs.spk.zst/"],
    "com.facebook.lite": ["/data/data/com.facebook.lite/lib-compressed/"],
    "com.facebook.orca": ["/data/data/com.facebook.orca/lib-compressed/"],
    "com.instagram.android": ["/data/data/com.instagram.android/lib-compressed/"],
    "com.facebook.pages.app": ["/data/data/com.facebook.pages.app/lib-compressed/"],
    "com.microsoft.office.officehubrow": ["/data/data/com.microsoft.office.officehubrow/files/data/applibs/"],
    "com.whatsapp.w4b": ["/data/data/com.whatsapp.w4b/files/decompressed/libs.spk.zst/"]
}

PHENOM_TIMEOUT = 6*60*60
FLOWDROID_TIMEOUT = 10*60


def getlibs_sig_offsets(appname):
    filename = os.path.join(TARGET_APK_PATH, appname, "signatures_libraries_offsets.txt")
    with open(filename, "r") as f:
        lines = f.read().splitlines()
    libs = set()
    for l in lines:
        library = l.split(" ")[2]
        libs.add(library)
    return libs


def get_mangled_signature(sig):
    # https://docs.oracle.com/en/java/javase/11/docs/specs/jni/design.html
    args = sig.split(":")[1]
    args = args.split(",")
    type_mapping = {"boolean": "Z", "byte": "B", "char": "C", "short": "S", "int":"I", "long": "J", "float":"F", "double":"D", "String": "Ljava_lang_String_2", "rest": "Ljava_lang_Object_2"}
    mangled_arg_sig = ""
    for arg in args:
        if arg == '':
            continue
        if arg in type_mapping:
            mangled_arg_sig += type_mapping[arg]
        elif arg[-2:] == "[]":
            if arg[:-2] in type_mapping:
                mangled_arg_sig += "_3" + type_mapping[arg[:-2]]
            else:
                mangled_arg_sig += "_3" + type_mapping["rest"]
        else:
            mangled_arg_sig += type_mapping["rest"]
    return mangled_arg_sig


def idnative_2_signatures_patterns(idnative):
    output = ""
    functions = set()
    for f in idnative:
        ins = f["instruction"]
        classname = ins[ins.find("<")+1:ins.rfind(":")]
        classname = classname.replace("_", "#")
        classname = classname.replace(".", "_")
        classname = classname.replace("#", "_1")
        fname = f["nativeName"]
        fname = fname.replace("_", "_1")
        if fname in functions:
            continue
        functions.add(fname)
        ret_type = ins[ins.find("<")+1:ins.rfind(">")]
        ret_type = ret_type.split(":")[1]
        print(ret_type)
        ret_type = ret_type.split(" ")[1]
        ret_type = ret_type.split(".")[-1]
        print(classname, ret_type)
        args = ""
        for arg in f["params"]:
            args += arg.split(".")[-1] + ","
        output += f"Java_{classname}_{fname} {ret_type}:{args}\n"
    print(output)
    return output


def extract_libs(appname):
    apk = APK(os.path.join(TARGET_APK_PATH, appname, "base.apk"))
    files = apk.get_files()
    if not os.path.exists(os.path.join(TARGET_APK_PATH, "lib")):
        os.mkdir(os.path.join(TARGET_APK_PATH, "lib"))
    if not os.path.exists(os.path.join(TARGET_APK_PATH, "lib", "arm64-v8a")):
        os.mkdir(os.path.join(TARGET_APK_PATH, "lib", "arm64-v8a"))
    print("Files:", files)
    for filepath in files:
        file_path = os.path.normpath(filepath).split("/")
        if len(file_path) > 2:
            if file_path[0] == "lib" and (file_path[1] == "arm64-v8a" or file_path[1] == "arm64"):
                lib = file_path[2]
                data = apk.get_file(filepath)


def extract_signatures(appname, use_idNative=False, fixup_overloaded=True):
    if not use_idNative:
        print(f"{PURPLE}[SIGS]{NC} Extracting signatures using jadx/qdox")
        logging.info(f"Starting to extract native function signatures for with jadx/qdox: {appname}")
        os.system(f"{BASE_PATH}/NativeSignatures/analyze_native_signatures.sh {appname}")
        logging.info(f"Finished extracting native function signatures for: {appname}")
        print(f"{GREEN}[SIGS]{NC} Finished signature extraction using jadx/qdox")
        os.system(f"echo {appname} >> {os.path.join(TARGET_APK_PATH, 'analyzed_signatures.txt')}")
    else:
        idnative_path = os.path.join(TARGET_APK_PATH, appname, "static_analysis", f"{appname}.json")
        if not os.path.exists(idnative_path):
            # fall back to qdox + jadx
            print(f"{PURPLE}[SIGS]{NC} No JSON! Extracting signatures using jadx/qdox")
            logging.info(f"Starting to extract native function signatures for with jadx/qdox: {appname}")
            os.system(f"{BASE_PATH}/NativeSignatures/analyze_native_signatures.sh {appname}")
            logging.info(f"Finished extracting native function signatures for: {appname}")
            print(f"{GREEN}[SIGS]{NC} Finished signature extraction using jadx/qdox")
            os.system(f"echo {appname} >> {os.path.join(TARGET_APK_PATH, 'analyzed_signatures.txt')}")
        else:
            print(f"{PURPLE}[SIGS]{NC} loading signatures from json")
            # parse the json file and write the output to signatures_pattern.txt
            with open(idnative_path, "r") as f:
                idnative_json = json.loads(f.read())
            signature_data = idnative_2_signatures_patterns(idnative_json)
            with open(os.path.join(TARGET_APK_PATH, appname, "signatures_pattern.txt"), "w") as f:
                f.write(signature_data)
            print(f"{GREEN}[SIGS]{NC} finished loading signatures from json")
    if fixup_overloaded:
        print(f"{PURPLE}[SIGS]{NC} fixing up overloaded signatures")
        # fixup overloaded functions
        output_path = os.path.join(TARGET_APK_PATH, appname, "signatures_pattern.txt")
        with open (output_path, "r") as f:
            found = f.read().splitlines()
        overloaded = set()
        for i,f in enumerate(found):
            fname = f.split(" ")[0]
            for k,f2 in enumerate(found):
                if k == i:
                    continue
                if fname == f2.split(" ")[0]:
                    overloaded.add((i,f))
                    overloaded.add((k,f2))
        for i,f in overloaded:
            print(f"[SIGS] fixing up overloaded function {f}")
            fname = f.split(" ")[0]
            sig = f.split(" ")[1]
            fname = fname + "__" + get_mangled_signature(sig)
            found[i] = fname + " " + sig
        output = "\n".join(found)
        with open(output_path, "w") as f:
            f.write(output)
        print(f"{GREEN}[SIGS]{NC} done fixing up overloaded signatures")
    print(f"{CYAN}[SIGS]{NC} finished signature extraction")


def init_JNIOffset(device_id=None):
    print(f"{PURPLE}[SETUP]{NC} Setting up JNIOffset on phone..")
    adb.execute_privileged_command(f"mkdir -p {REMOTE_FOLDER}", device_id=device_id)
    # upload a bogus harness that exports the necessary AFL_AREA_PTR
    adb.push_privileged(os.path.join(BASE_PATH, "JNIOffset", "harness"), REMOTE_FOLDER, device_id=device_id)
    adb.push_privileged(os.path.join(BASE_PATH, "JNIOffset", "example_harness"), REMOTE_FOLDER, device_id=device_id)
    adb.push_privileged(os.path.join(BASE_PATH, "JNIOffset", "cpp", "jniOffsetFinder.cpp"), REMOTE_FOLDER, device_id=device_id)
    adb.push_privileged(os.path.join(BASE_PATH, "JNIOffset", "cpp", "jniOffsetFinder.h"), REMOTE_FOLDER, device_id=device_id)
    adb.execute_privileged_command(f"/data/data/com.termux/files/usr/bin/clang++ -std=c++17 -v -Wl,--export-dynamic -g -O0 {REMOTE_FOLDER}jniOffsetFinder.cpp -o {REMOTE_FOLDER}jniOffsetFinder", device_id=device_id)
    adb.push_privileged(os.path.join(BASE_PATH, "JNIOffset", "findJNIOffsets.sh"), REMOTE_FOLDER, device_id=device_id)
    adb.execute_privileged_command(f"chmod +x {REMOTE_FOLDER}/findJNIOffsets.sh", device_id=device_id)
    print(f"{GREEN}[SETUP]{NC} Done setting up JNIOffset on phone")


def extract_library_offset(appname, cleanup=True, library_specific=None, device_id=None):
    print(f"{PURPLE}[OFFSET]{NC} Starting to look for native functions")
    logging.info(f"[{appname}] Starting to look for native functions")
    # read nr of native libraries if 0 return
    app_path = os.path.join(TARGET_APK_PATH, appname)
    libraries = []
    if appname in SPECIAL_LOCATIONS:
        for custom_lib_location in SPECIAL_LOCATIONS[appname]:
            logging.debug(f"[{appname}] handling speial library location")
            out, err = adb.execute_privileged_command(f"ls {custom_lib_location}", device_id=device_id)
            out = out.decode()
            entries = out.split("\n")
            for l in entries:
                if ".so" in l:
                    # download all the special libraries if not already done
                    if not os.path.exists(os.path.join(TARGET_APK_PATH, appname, 'lib', 'arm64-v8a', l)):
                        adb.pull_privileged(os.path.join(custom_lib_location,l), os.path.join(TARGET_APK_PATH, appname, 'lib', 'arm64-v8a'), device_id=device_id)
    # disregards the case where the app only has native libraries elsewhere
    if not os.path.isdir(os.path.join(app_path, "lib", "arm64-v8a")):
        print(f"{YELLOW}[OFFSET]{NC} no native libraries, nothing to be done")
        logging.info(f"[{appname}] No native libraries!")
        return
    for lib in os.listdir(os.path.join(app_path, "lib", "arm64-v8a")):
        libraries.append(lib)
    # parse the signatures and extract the function signatures into a list
    if not os.path.exists(os.path.join(app_path, "signatures_pattern.txt")):
        print(f"{RED}[OFFSET]{NC} No signatures_pattern.txt, make sure to first get the native signatures")
        logging.info(f"[{appname}] No signatures_pattern.txt")
        return
    with open(os.path.join(app_path, "signatures_pattern.txt")) as f:
        signature_data = f.read()
    signatures = []
    signature_data = signature_data.split("\n")
    for s in signature_data:
        if s == '':
            continue
        signatures.append({"fname": s.split(" ")[0], "signature": s.split(" ")[1]})
    if len(signatures) == 0:
        print(f"{RED}[OFFSET]{NC} no native function signatures, nothing to be done")
        logging.info(f"[{appname}] No native function signatures")
        return
    out, err = adb.execute_privileged_command(f"ls {REMOTE_FOLDER}", device_id=device_id)
    init_JNIOffset(device_id=device_id)
    # upload app folder to workdir
    print(f"{PURPLE}[OFFSET]{NC} uploading necessary files from {app_path} to phone")
    logging.info(f"[{appname}] uploading {app_path} to phone")
    adb.execute_privileged_command(f"mkdir {REMOTE_FOLDER}{appname}", device_id=device_id)
    adb.push_privileged(os.path.join(app_path, "base.apk"), os.path.join(REMOTE_FOLDER,appname), device_id=device_id)
    adb.push_privileged(os.path.join(app_path, "signatures_pattern.txt"), os.path.join(REMOTE_FOLDER,appname), device_id=device_id)
    adb.push_privileged(os.path.join(app_path, "lib"), os.path.join(REMOTE_FOLDER,appname), is_directory=True, device_id=device_id)
    # LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd)/target_APK/<app_name>/lib/arm64-v8a:/system/lib64 ./jniOffsetfinder <app_name> <target_library_name> <target_function_name> <target_function_signature>
    # iterate over function signatures, iterate over libraries. Run jniOffsetfinder and check if function is found. If yes continue on to next function
    print(f"{GREEN}[OFFSET]{NC} finished uploading to phone")
    logging.info(f"[{appname}] finished uploading {app_path} to phone")
    # move custom libraries into the common folder
    out = b''
    err = b''
    print(f"{PURPLE}[OFFSET]{NC} Looking for native function offset...")
    if library_specific is not None:
        libraries = [library_specific]
    for lib in libraries:
        ld_preload = ""
        if "libc++_shared.so" in libraries:
            ld_preload = os.path.join(REMOTE_FOLDER, appname, "lib", "arm64-v8a", "libc++_shared.so")
        try:
            out, err = adb.execute_privileged_command(f"{REMOTE_FOLDER}findJNIOffsets.sh {appname} {lib} {REMOTE_FOLDER} {ld_preload}", timeout=60, device_id=device_id)
            logging.debug(f"[{appname}] JNIOFfsets output: {out}, {err}")
        except adb.DeviceTimeoutException:
            logging.error(f"[{appname}] crash while checking library {lib}, continuing")
        if err == b'' and b"RETURN CODE 0" in out:
            logging.info(f"[{appname}] Finished running jniOffsetfinder for library {lib}")
            # no error returned and return code was 0 -> function found
        elif err != b'' and b"RETURN CODE 1" in out:
            logging.info(f"[{appname}] jniOffsetfinder returned code of 1 for library {lib}")
            # didn't find what we were looking for keep looking
            pass
        else:
            # something weird happened most likely jniOffsetfinder crashed
            logging.error(f"[{appname}] jniOffsetfinder Error when checking library {lib}. Error: {err}")
    # download the signatures_libraries_offsets.txt file, remove the uploaded apk
    adb.pull_privileged(f"{REMOTE_FOLDER}/{appname}/signatures_libraries_offsets.txt", app_path, device_id=device_id)
    #cleanup of uploaded app folder
    if cleanup:
        adb.execute_privileged_command(f"rm -r {REMOTE_FOLDER}{appname}", device_id=device_id)
    if not os.path.exists(os.path.join(app_path, "signatures_libraries_offsets.txt")):
        nr_found_functions = 0
        with open(os.path.join(app_path, "signatures_libraries_offsets.txt"), 'w') as fp:
            pass
    else:
        with open(os.path.join(app_path, "signatures_libraries_offsets.txt")) as fp:
            nr_found_functions = len(fp.readlines())
    print(f"{CYAN}[OFFSET]{NC} Finished looking for native function offsets! Found: {nr_found_functions} offsets")
    logging.info(f"[{appname}] Finished looking for native function offsets! Found: {nr_found_functions} offsets")

    with open(os.path.join(app_path, "signatures_pattern.txt")) as fp:
        nr_signatures = len(fp.readlines())
    os.system(f"echo {appname} >> {os.path.join(TARGET_APK_PATH, 'analyzed_libraries_offsets.txt')}")
    logging.info(f"{appname} nr native functions found: {nr_found_functions}, nr of native functions defined: {nr_signatures}")


def analyze_single_apk(appname, signatures=False, libraries=False, argument_analysis=False, callsequence_analysis=False, library_specific=None, use_idNative=False, device_id=None):
    print(f"{PURPLE}[*]{NC} Analyzing {appname}")
    if not os.path.exists(os.path.join(TARGET_APK_PATH, appname)):
        print(f"{RED}[-]{NC} {os.path.join(TARGET_APK_PATH, appname)} does not exist!")
        logging.error(f"{os.path.join(TARGET_APK_PATH, appname)} does not exist!")
        exit(-1)
    if not os.path.exists(os.path.join(TARGET_APK_PATH, appname, "base.apk")):
        print(f"{RED}[-]{NC} {os.path.join(TARGET_APK_PATH, appname, 'base.apk')} does not exist!")
        logging.error(f"{os.path.join(TARGET_APK_PATH, appname, 'base.apk')} does not exist!")
        exit(-1)
    if argument_analysis:
        print(f"{PURPLE}[*]{NC} Starting argument analysis for {appname}")
        app_path = os.path.join(TARGET_APK_PATH, appname)
        p = subprocess.Popen(["java", "-jar", f"{BASE_PATH}/argument-analysis/FlowDroidAnalysis.jar", app_path, "abcd"])
        try:
            p.wait(FLOWDROID_TIMEOUT)
        except subprocess.TimeoutExpired:
            print(f"{RED}[-]{NC} timeout for app: {appname} :/")
            p.kill()
        print(f"{GREEN}[+]{NC} Finished argument flowdroid analysis for {appname}")
    if callsequence_analysis:
        print(f"{PURPLE}[*]{NC} Starting callsequence analysis for {appname}")
        print(BASE_PATH)
        app_path = os.path.join(TARGET_APK_PATH, appname, "base.apk")
        static_out = os.path.join(BASE_PATH, "callsequence-analysis", "nativesAnalysis", "CS_base.json")
        static_final_dir = os.path.join(TARGET_APK_PATH, appname, "static_analysis")
        static_final = os.path.join(static_final_dir, f"CS_{appname}.json")
        #ANDROID_HOME=/opt/androidsdk/platforms/ java -cp callseq-1.0-jar-with-dependencies.jar aaa.bbb.ccc.path.analyses.AndrolibDriver -j ../../target_APK/com.tplink.skylight/base.apk
        if not os.path.exists(static_final_dir):
            os.system(f'mkdir -p {static_final_dir}')
        if os.path.exists(static_out):
            os.system(f'rm {static_out}')
        env = os.environ.copy()
        env["ANDROID_HOME"] = "/opt/androidsdk/platforms"
        p = subprocess.Popen(["java", "-cp", "callseq-1.0-jar-with-dependencies.jar", "aaa.bbb.ccc.path.analyses.AndrolibDriver", "-j", app_path, "abcd"], env=env, cwd=os.path.join(BASE_PATH, "callsequence-analysis"))
        try:
            p.wait(FLOWDROID_TIMEOUT)
            if os.path.exists(static_out):
                os.system(f'cp {static_out} {static_final}')
                os.system(f'rm {static_out}')
        except subprocess.TimeoutExpired:
            print(f"{RED}[-]{NC} timeout for app: {appname} :/")
            p.kill()
        print(f"{GREEN}[+]{NC} Finished callsequence analysis for {appname}")
    if signatures:
        extract_signatures(appname, use_idNative)
    if libraries:
        extract_library_offset(appname, library_specific=library_specific, device_id=device_id)
    print(f"{CYAN}[+]{NC} Finished Analyzing {appname}")

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='extract the native function signatures and libries/offsets for all apks or a given apk')
    parser.add_argument("--target", type=str, required=True, help="the app to analyze, by default all apps inside the target_APK folder")
    #parser.add_argument("-e", "--extract", required=False, default=False, action="store_true", help="extract the native libraries from the apk into the libs folder (if libraries already exist backup copies are made)")
    parser.add_argument("-s", "--signatures", required=False, default=False, action="store_true", help="extract the native funciton signatures (with NativeSignatures i.e. jadx + qdox)")
    parser.add_argument("-s_idn", "--signatures_idNative", required=False, default=False, action="store_true", help="if this is set, the prepocssing script will look for static_analysis/{appname}.json for the native function signatures")
    parser.add_argument("-l", "--libraries", required=False, default=False, action="store_true", help="extract the native function library names/offset (with JNIOffset)")
    parser.add_argument("--libraries_specific", required=False, type=str, help="only extract function offsets from specific library")
    parser.add_argument("--argument_analysis", required=False, default=False, action="store_true", help="run the argument analysis")
    parser.add_argument("--callsequence_analysis", required=False, default=False, action="store_true", help="run the callsequence analysis")
    parser.add_argument("-c", "--cleanup", required=False, default=False, action="store_true", help="if set no analysis is done and instead all files created by the prepocessing are deleted")
    parser.add_argument("--init", required=False, default=False, action="store_true", help="if set the jniOffsetfinder and script are newly uploaded")
    parser.add_argument("-d", "--device", required=False, help="specify device to be used for the offset extraction task")
    #parser.add_argument("--target_APK_path", required=False, help="another path to target_APK_path")
    

    args = parser.parse_args()

    if args.cleanup:
        if args.target == "all":
            print("we're not just deleting everything sorry...")
            exit(0)
        os.system(f"cp {TARGET_APK_PATH}/{args.target}/base.apk /tmp/{args.target}.apk")
        os.system(f"rm -rf {TARGET_APK_PATH}/{args.target}/*")
        os.system(f"cp /tmp/{args.target}.apk {TARGET_APK_PATH}/{args.target}/base.apk")

    device_id = None
    if args.device is not None:
        device_id = args.device
    if len(adb.get_device_ids()) >= 1 and device_id is None:
        # no device specified but multiple devices present, choose first device
        device_id = adb.get_device_ids()[0]

    status = adb.check_device(device_id)
    if status != "OK" and args.libraries:
        print(f"{RED}[ERR]{NC} device {device_id} is not functional: {status} !!ABORTING!!")
        exit(-1)

    if args.init:
        init_JNIOffset(device_id=device_id)

    if not args.callsequence_analysis and not args.libraries and not args.signatures and not args.argument_analysis:
        # if no option is set we do all analysis passes
        args.libraries = True
        args.signatures = True
        args.argument_analysis = True
        args.callsequence_analysis = True

    #if args.extract:
    #    extract_libs(args.target)

    analyze_single_apk(args.target, args.signatures, args.libraries, argument_analysis=args.argument_analysis, callsequence_analysis=args.callsequence_analysis, 
        library_specific=args.libraries_specific, use_idNative=args.signatures_idNative, device_id=device_id)
