"""
Script to setup testing the harness for a specific app+library+function
generates the relevant commands for fuzzing, running or debugging
"""
import sys
import os
import argparse
import logging
import subprocess
BASE_PATH = os.path.dirname(__file__)
sys.path.append(os.path.join(BASE_PATH, '..'))
sys.path.append(os.path.join(BASE_PATH, '../harness'))
sys.path.append(os.path.join(BASE_PATH, '../harness/lib'))
import adb
import harness.compile_harness
import harness.parse_analysis
import re
import json

logging.basicConfig(filename='testing.log', encoding='utf-8', level=logging.DEBUG, format='%(asctime)s %(message)s', force=True)

RED='\033[0;31m'                                                   
YELLOW='\033[0;33m'                                                                                                                          
GREEN='\033[0;32m'                                                                                                                           
NC='\033[0m'                                                                                                                                 
BLUE='\033[0;34m'         # Blue                                      
PURPLE='\033[0;35m'       # Purple                                                                                                           
CYAN='\033[0;36m'         # Cyan 


TARGET_APK_PATH = os.path.join(BASE_PATH, "../target_APK")
REMOTE_FOLDER = "/data/local/tmp/testing/"
LD_PRELOAD = "/data/data/com.termux/files/usr/lib/libc++_shared.so"

def shell_escape(s):
    return s.replace('$', '\\$')

def clean(device_id=None):
    adb.execute_privileged_command(f"rm -r {REMOTE_FOLDER}", device_id=device_id)


def setup(app, function_name, harness_path, UPLOAD_APP=True, INIT_COMPILE=True, COMPILE_HARNESS=True, remote_folder=REMOTE_FOLDER, device_id=None):
    if COMPILE_HARNESS:
        print(f"{PURPLE}[SETUP]{NC} compiling harnesses for {function_name}")
        if INIT_COMPILE:
            harness.compile_harness.init_compilation(remote_folder, path=os.path.join(BASE_PATH, "..", "harness"), device_id=device_id)
        harness.compile_harness.compile_harness(function_name, os.path.join(TARGET_APK_PATH, app, "harnesses"), remote_folder, device_id=device_id)
        if INIT_COMPILE:
            harness.compile_harness.init_compilation(remote_folder, path=os.path.join(BASE_PATH, "..", "harness"), debug=True, device_id=device_id)
        harness.compile_harness.compile_harness(function_name, os.path.join(TARGET_APK_PATH, app, "harnesses"), remote_folder, debug=True, device_id=device_id)
        print(f"{GREEN}[SETUP]{NC} finsihed compiling harnesses!")
    else:
        if not os.path.exists(os.path.join(harness_path, "harness")):
            # compile harness
            print(f"{PURPLE}[SETUP]{NC} compiling harness for {function_name}")
            if INIT_COMPILE:
                harness.compile_harness.init_compilation(remote_folder, path=os.path.join(BASE_PATH, "..", "harness"), device_id=device_id)
            harness.compile_harness.compile_harness(function_name, os.path.join(TARGET_APK_PATH, app, "harnesses"), remote_folder, device_id=device_id)
            print(f"{GREEN}[SETUP]{NC} finsihed compiling harnesses!")
        if not os.path.exists(os.path.join(harness_path, "harness_debug")):
            # compile harness
            print(f"{PURPLE}[SETUP]{NC} compiling debug harness for {function_name}")
            if INIT_COMPILE:
                harness.compile_harness.init_compilation(remote_folder, path=os.path.join(BASE_PATH, "..", "harness"), debug=True, device_id=device_id)
            harness.compile_harness.compile_harness(function_name, os.path.join(TARGET_APK_PATH, app, "harnesses"), remote_folder, debug=True, device_id=device_id)
            print(f"{GREEN}[SETUP]{NC} finsihed compiling debug harness!")
    
    # upload harnesses
    harness_name = "harness"
    harness_name_debug = "harness_debug"
    print(f"{PURPLE}[SETUP]{NC} uploading harnesses to phone")
    adb.execute_privileged_command(f"mkdir -p {remote_folder}", device_id=device_id)
    adb.push_privileged(os.path.join(harness_path, harness_name), remote_folder, device_id=device_id)
    adb.push_privileged(os.path.join(harness_path, harness_name_debug), remote_folder, device_id=device_id)
    adb.push_privileged(os.path.join(harness_path, "afl.js"), remote_folder, device_id=device_id)
    adb.execute_privileged_command(f"chmod +x {remote_folder}/{harness_name}", device_id=device_id)
    adb.execute_privileged_command(f"chmod +x {remote_folder}/{harness_name_debug}", device_id=device_id)
    adb.push_privileged(os.path.join(harness_path, harness_name+".cpp"), remote_folder, device_id=device_id)
    adb.push_privileged(os.path.join(harness_path, harness_name_debug+".cpp"), remote_folder, device_id=device_id)
    adb.push_privileged(os.path.join(BASE_PATH, "..","harness", "cpp", "libharness.h"), remote_folder, device_id=device_id)
    adb.push_privileged(os.path.join(BASE_PATH, "..","harness", "cpp", "FuzzedDataProvider.h"), remote_folder, device_id=device_id)
    adb.push_privileged(os.path.join(BASE_PATH, "..","harness", "cpp", "libharness.cpp"), remote_folder, device_id=device_id)
    adb.push_privileged(os.path.join(BASE_PATH, "..","harness", "cpp", "libharness_debug.so"), remote_folder+"/libharness.so", device_id=device_id) #should not make a difference
    adb.push_privileged(os.path.join(BASE_PATH, "..","harness", "cpp", "libharness_debug.so"), remote_folder+"/libharness_nodebug.so", device_id=device_id) #should not make a difference
    adb.push_privileged(f"{BASE_PATH}/gdb/.gdbinit", remote_folder, device_id=device_id)
    adb.push_privileged(f"{BASE_PATH}/gdb/dump_bt.py", remote_folder, device_id=device_id)
    if not adb.path_exists(f'{remote_folder}/{harness_name}', device_id=device_id):
        print(f'FAILED {function_name} to copmile')
        exit(-1)
    if not os.path.exists("gdb/gef/gef.py"):
        print("Downloading gef.py...")
        subprocess.check_output(f"wget  -q https://gef.blah.cat/py  -O {BASE_PATH}/gdb/gef/gef.py", shell=True)
    adb.push_privileged(f"{BASE_PATH}/gdb/gef/gef.py", remote_folder, device_id=device_id)
    # upload seeds
    print(f"{PURPLE}[SETUP]{NC} uploading seeds to phone")
    adb.push_privileged(os.path.join(harness_path, "seeds"), remote_folder, is_directory=True, device_id=device_id)
    adb.execute_privileged_command(f"mkdir -p {remote_folder}output", device_id=device_id)
    if UPLOAD_APP:
        # upload the app
        print(f"{PURPLE}[SETUP]{NC} uploading app to phone")
        adb.execute_privileged_command(f"mkdir -p {remote_folder}{app}", device_id=device_id)
        adb.push_privileged(os.path.join(TARGET_APK_PATH, app, "base.apk"), f"{remote_folder}{app}", device_id=device_id)
        adb.push_privileged(os.path.join(TARGET_APK_PATH, app, "lib"), f"{remote_folder}{app}", is_directory=True, device_id=device_id)
    print(f"{GREEN}[SETUP]{NC} finished setup")
    if not adb.path_exists(os.path.join(remote_folder, "afl-fuzz"), device_id=device_id):
        adb.push_privileged(os.path.join(BASE_PATH, "..", "afl", "afl-fuzz"), remote_folder, device_id=device_id)

    if not adb.path_exists(os.path.join(remote_folder, "afl-frida-trace.so"), device_id=device_id):
        adb.push_privileged(os.path.join(BASE_PATH, "..", "afl", "afl-frida-trace.so"), remote_folder, device_id=device_id)

    adb.execute_privileged_command(f'chown nobody {remote_folder}', device_id=device_id)
    adb.execute_privileged_command(f'/data/data/com.termux/files/usr/bin/chmod -R +r+x /data/data/com.termux', device_id=device_id)

def setup_testing(app, function_name, device_id=None):
    print(f"{PURPLE}[TESTING]{NC} Setting up testing for {app}, {function_name}")
    clean(device_id=device_id)
    harness_path = os.path.join(TARGET_APK_PATH, app, "harnesses", function_name)
    offsets_file = os.path.join(TARGET_APK_PATH, app, "signatures_libraries_offsets.txt")
    info_json = os.path.join(harness_path, "info.json")
    if not os.path.exists(info_json):
        print(f'{RED}[ERROR]{NC} No info.json in harness folder! Please generate the harnesses again!')
        exit(-1)
    info_json = json.load(open(info_json))
    targetlibrary = info_json['targetlibrary']
    targetclassname = info_json['targetclassname']
    with open(offsets_file, "r") as f:
        functions = f.readlines()

    function_name_orig = function_name.split("@")[0]

    library = ""
    offset = ""
    for fn in functions:
        data = fn.split(" ")
        if data[0] == function_name_orig:
            library = data[2]
            offset = data[3].strip("\n")

    if library == "" or offset == "":
        print(f"{RED}[TEST]{NC} Unable to find library name / offset, exiting!")
        exit(1)

    setup(app, function_name, harness_path, device_id=device_id, INIT_COMPILE=True)

    harness_name = "harness"
    harness_name_debug = "harness_debug"

    # check if own libc++_shared.so is present in the app, if present load this along with standard libc++_shared.so
    own_libc = False
    for lib in os.listdir(os.path.join(TARGET_APK_PATH, app, "lib", "arm64-v8a")):
        if lib == "libc++_shared.so":
            own_libc = True

    ld_preload = ""
    afl_preload = ""
    if own_libc:
        # amend the LD_PRELOAD part of the command
        ld_preload = f'LD_PRELOAD="{LD_PRELOAD} $(pwd)/{app}/lib/arm64-v8a/libc++_shared.so" '
        afl_preload = f'AFL_PRELOAD="{LD_PRELOAD} $(pwd)/{app}/lib/arm64-v8a/libc++_shared.so" '

    print(f"{GREEN}[TESTING]{NC} Finished setting up testing")

    print(80 * "=")

    if device_id:
        print(f"Connect to device {device_id} to run the testing commands.")

    print("set PATH:")
    print("PATH=//data/data/com.termux/files/usr/bin:$PATH")

    # print the necessary commands
    DBG_CMD = f"{ld_preload}LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/{app}/lib/arm64-v8a:/system/lib64 \
ANDROLIB_APP_PATH={app} ANDROLIB_TARGET_LIBRARY={targetlibrary} ANDROLIB_CLASS0={targetclassname} ANDROLIB_MEMORY=memory \
gdb --command=.gdbinit --args ./{harness_name_debug} seeds/seed_generic_1 0 0"

    print("DEBUG COMMAND:")
    print(DBG_CMD)

    FUZZ_CMD = f"{afl_preload}AFL_FORKSRV_INIT_TMOUT=999999999 AFL_DEBUG=1 LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/{app}/lib/arm64-v8a:/system/lib64 \
ANDROLIB_APP_PATH={app} ANDROLIB_TARGET_LIBRARY={targetlibrary} ANDROLIB_CLASS0={targetclassname} ANDROLIB_MEMORY=memory \
./afl-fuzz -O -c 0 -i seeds -o output ./{harness_name}"

    print("\nFUZZING COMMAND:")
    print(FUZZ_CMD)

    EXEC_CMD = f"{ld_preload}LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/{app}/lib/arm64-v8a:/system/lib64 \
ANDROLIB_APP_PATH={app} ANDROLIB_TARGET_LIBRARY={targetlibrary} ANDROLIB_CLASS0={targetclassname}  ANDROLIB_MEMORY=memory \
./{harness_name_debug} seeds/seed_generic_1 0 0" 

    print("\nEXEC COMMAND:")
    print(EXEC_CMD)


def test_app(app, remote_folder=REMOTE_FOLDER, with_unmap=False, with_fork=True, device_id=None):
    """
    go through each harness, upload, compile and run once, log the results 
    nocov: run using the harness without coverage, otherwise harness with coverage is used  (makes no difference if library hasn't been instrumented)
    """
    clean(device_id=device_id)
    harness_debug_name = "harness_debug.cpp"
    harness_list = list(sorted(os.listdir(os.path.join(TARGET_APK_PATH, app, "harnesses"))))
    functions_to_test = []
    for fname in harness_list:
        if not os.path.exists(os.path.join(TARGET_APK_PATH, app, "harnesses", fname, harness_debug_name)):
            print(f"{RED}[TESTAPP]{NC} no harness for {fname}, skipping!")
            continue
        functions_to_test.append(fname)
    
    print(f"{YELLOW}[TESTAPP]{NC} from {len(harness_list)} functions, testing {len(functions_to_test)}")
    # setup everything for compilation
    harness.compile_harness.init_compilation(remote_folder, path="../harness", debug=True, device_id=device_id)
    # upload the target app
    adb.execute_privileged_command(f"mkdir -p {remote_folder}{app}", device_id=device_id)
    adb.push_privileged(os.path.join(TARGET_APK_PATH, app, "base.apk"), f"{remote_folder}{app}", device_id=device_id)
    adb.push_privileged(os.path.join(TARGET_APK_PATH, app, "lib"), f"{remote_folder}{app}", is_directory=True, device_id=device_id)

    result_dict = {}

    for function_name in functions_to_test:
        print(f"{PURPLE}[TESTAPP]{NC} Testing {function_name}")
        harness_path = os.path.join(TARGET_APK_PATH, app, "harnesses", function_name)
        setup(app, function_name, harness_path, nocov=nocov, INIT_COMPILE=False, COMPILE_HARNESS=True, UPLOAD_APP=False, remote_folder=remote_folder, device_id=device_id)
        print(f"{YELLOW}[TESTAPP]{NC} executing harness for {function_name}")
        if with_fork:
            fork = "1"
        else:
            fork = "0"
        if with_unmap:
            unmap = "1"
        else:
            unmap = "0"
        # check if own libc++_shared.so is present in the app, if present load this along with standard libc++_shared.so
        own_libc = False
        for lib in os.listdir(os.path.join(TARGET_APK_PATH, app, "lib", "arm64-v8a")):
            if lib == "libc++_shared.so":
                own_libc = True
        ld_preload = ""
        if own_libc:
            # amend the LD_PRELOAD part of the command
            ld_preload = f'"{LD_PRELOAD} $(pwd)/{app}/lib/arm64-v8a/libc++_shared.so" '
        try:
            out, err = adb.execute_privileged_command(f"cd {REMOTE_FOLDER} && ulimit -c unlimited && LD_PRELOAD={ld_preload} LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/{app}/lib/arm64-v8a:/system/lib64 ./harness_debug_nocov {app} memory ./seeds/seed_0 {unmap} {fork}", timeout=60, device_id=device_id)
        except adb.DeviceUnresponsiveException:
            logging.info(f"{app}-{function_name} timeout over 60s")
            print(f"{YELLOW}[TESTAPP]{NC} {app}-{function_name} timeout!")
            # on timeout kill the harness_debug_nocov processes
            ALL_PROC = adb.execute_privileged_command("ps -ef | grep harness_debug_nocov | grep -v grep", device_id=device_id)[0].decode('utf-8').split("\n")[:-1]
            ALL_PROC = list(map(lambda x: re.sub("\s+", " ", x).split(" ")[1], ALL_PROC))
            for P in ALL_PROC:
                adb.execute_privileged_command("kill -9 " + P, device_id=device_id)
            continue
        if b"CALLING" in out:
            if b"EXITED DUE TO SIGNAL b" in out or b"EXITED DUE TO SIGNAL 11" in out:
                logging.info(f"{app}-{function_name} called, exited with SEGFAULT")
                print(f"{YELLOW}[TESTAPP]{NC} {app}-{function_name} called, exited with SEGFAULT")
                result_dict[function_name] = "SEGFAULT"
            elif b"EXITED DUE TO SIGNAL 6" in out:
                logging.info(f"{app}-{function_name} called, exited with ABORT")
                print(f"{YELLOW}[TESTAPP]{NC} {app}-{function_name} called, exited with ABORT")
                result_dict[function_name] = "ABORT"
            elif b"EXITED NORMALLY:)" in out:
                logging.info(f"{app}-{function_name} called, exited normally!")
                print(f"{YELLOW}[TESTAPP]{NC} {app}-{function_name} called, exited normally!")
                result_dict[function_name] = "NORMAL"
            else:
                logging.info(f"{app}-{function_name} called, unknown exit code: {out.splitlines()[-4:-1]}, {err}")
                print(f"{YELLOW}[TESTAPP]{NC} {app}-{function_name} called, unknown exit code: {out.splitlines()[-4:-1]}, {err}")
                result_dict[function_name] = "UNKNOWN"
        else:
            logging.info(f"{app}-{function_name} not called, stderr: {out.splitlines()[-4:-1]}, {err}")
            print(f"{YELLOW}[TESTAPP]{NC} {app}-{function_name} not called, stderr: {out.splitlines()[-4:-1]}, {err}")
            result_dict[function_name] = "TIMEOUT"

    csv_name = 'harness_testing.csv'
    if only_rewritten:
        csv_name = 'harness_testing_only_rewritten.csv'
    csv_app_path = os.path.join(TARGET_APK_PATH, app, csv_name)
    import csv
    with open(csv_app_path, 'w', newline='') as csvfile:
        spamwriter = csv.writer(csvfile, delimiter=' ',
                            quotechar='|', quoting=csv.QUOTE_MINIMAL)
        for f in result_dict:
            r = result_dict[f]
            spamwriter.writerow([f , r])

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description=f'Setup testing for a specific app-function, testing folder is currently: {REMOTE_FOLDER}')
    parser.add_argument("--action", type=str, choices=["setup_testing", "test_app", "clean"], required=False, default="setup_testing", help="test_call tries to run all the generated harnesses and writes, set to clean if you want to clean up the testing directory")
    parser.add_argument("-t", "--target", type=str, default="none", required=False, help="The appname in target_APK")
    parser.add_argument("-f", "--target_function", default="none", type=str, required=False, help="The full java funcitonname of the native function")
    parser.add_argument("--device", type=str, required=False, help="specify a specific device on which to test")


    args = parser.parse_args()    

    device_id = None
    if args.device:
        device_id = args.device
    else:
        if len(adb.get_device_ids()) >= 1:
            device_id = adb.get_device_ids()[0]

    status = adb.check_device(device_id)
    if status != "OK":
        print(f"{RED}[!]{NC} device {device_id} is not functional: {status} !!ABORTING!!")
        exit(-1)

    if args.action == "setup_testing":
        if args.target != "none" and args.target_function != "none":
            setup_testing(args.target, args.target_function, device_id=device_id)
        else:
            print(f"{RED}[!]{NC} please specify the app and function with --target and --target_function!")
            exit(1)
    if args.action == "clean":
        clean(device_id=device_id)
    if args.action == "test_app":
        test_app(args.target, device_id=device_id)
