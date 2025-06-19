import logging
import adb
import os
BASE_PATH = os.path.dirname(__file__)

RED='\033[0;31m'                                                   
YELLOW='\033[0;33m'                                                                                                                          
GREEN='\033[0;32m'                                                                                                                           
NC='\033[0m'                                                                                                                                 
BLUE='\033[0;34m'         # Blue                                      
PURPLE='\033[0;35m'       # Purple                                                                                                           
CYAN='\033[0;36m'         # Cyan 

def init_compilation(REMOTE_FOLDER, debug=False, path="harness", device_id=None):
    if not REMOTE_FOLDER.endswith("/"):
        REMOTE_FOLDER += "/"
    logging.debug(f"Setting up necessary files on phone for compiling..")
    adb.execute_privileged_command(f"mkdir -p {REMOTE_FOLDER}", device_id=device_id)
    adb.push_privileged(os.path.join(BASE_PATH, "cpp", "libharness.h"), REMOTE_FOLDER, device_id=device_id)
    adb.push_privileged(os.path.join(BASE_PATH, "cpp", "libharness.cpp"), REMOTE_FOLDER, device_id=device_id)
    adb.push_privileged(os.path.join(BASE_PATH, "cpp", "FuzzedDataProvider.h"), REMOTE_FOLDER, device_id=device_id)
    adb.push_privileged(os.path.join(BASE_PATH, "cpp", "FuzzedDataProvider.cpp"), REMOTE_FOLDER, device_id=device_id)
    if debug:
        libharness_name = "libharness_debug.so"
    else:
        libharness_name = "libharness.so"
    if not os.path.exists(os.path.join(BASE_PATH, "cpp", libharness_name)):
        logging.info(f"compiling {libharness_name}!")
        compile_libharness(REMOTE_FOLDER, path, os.path.join(path, 'cpp'), debug=debug, device_id=device_id)
    if debug:
        adb.push_privileged(os.path.join(BASE_PATH, "cpp", "libharness_debug.so"), REMOTE_FOLDER+"/libharness.so", device_id=device_id)
    else:
        adb.push_privileged(os.path.join(BASE_PATH, "cpp", "libharness.so"), REMOTE_FOLDER+"/libharness.so", device_id=device_id)
    logging.debug(f"Done setting up on phone for compiling..")


def compile_libharness(REMOTE_FOLDER, path, out_path, debug=False, device_id=None):
    if not REMOTE_FOLDER.endswith("/"):
        REMOTE_FOLDER += "/"
    adb.push_privileged(os.path.join(BASE_PATH, "cpp", "libharness.h"), REMOTE_FOLDER, device_id=device_id)
    adb.push_privileged(os.path.join(BASE_PATH, "cpp", "libharness.cpp"), REMOTE_FOLDER, device_id=device_id)
    adb.push_privileged(os.path.join(BASE_PATH, "cpp", "FuzzedDataProvider.h"), REMOTE_FOLDER, device_id=device_id)
    flags = ""
    if debug:
        flags = "-g3 -O0"
    out, err = adb.execute_privileged_command(f'cd {REMOTE_FOLDER} && /data/data/com.termux/files/usr/bin/g++ -std=c++17 -fPIC -Wall {flags} -shared FuzzedDataProvider.cpp libharness.cpp -o libharness.so', device_id=device_id)
    if err:
        logging.debug(f"error encountered while compiling libharness.so in {REMOTE_FOLDER}, {err}")
    if debug:
        libharness_name = "libharness_debug.so"
    else:
        libharness_name = "libharness.so"
    adb.pull_privileged(f"{REMOTE_FOLDER}/libharness.so", os.path.join(out_path, libharness_name), device_id=device_id)


def compile_harness(harness_folder, harnessess_path, REMOTE_FOLDER, debug=False, device_id=None, delete=False, showmap=False):
    if not REMOTE_FOLDER.endswith("/"):
        REMOTE_FOLDER += "/"
    if debug:
        harness_name = "harness_debug"
        flags = "-g3 -O0"  
    elif showmap:
        flags = ""
        harness_name = "harness_showmap"
    else:
        harness_name = "harness"
        flags = ""
    logging.debug(f"compiling harness: {harness_folder}")
    harness_cpp = os.path.join(harnessess_path, harness_folder, harness_name+".cpp")
    if not os.path.exists(harness_cpp):
        print(f"{RED}[COMPILE]{NC} harness c++ file not found {harness_cpp}")
        return
    if not adb.path_exists(REMOTE_FOLDER + "/libharness.so"):
        print(f'{RED}[COMPILE]{NC} libharness.so not in remote folder, please initalize compilation!')
    adb.push_privileged(harness_cpp, REMOTE_FOLDER + f"/{harness_name}.cpp", device_id=device_id)
    out, err = adb.execute_privileged_command(f"cd {REMOTE_FOLDER} && /data/data/com.termux/files/usr/bin/g++ -std=c++17 -L. -lharness {flags} -Wall -std=c++17 -Wl,--export-dynamic {harness_name}.cpp -o {harness_name}", device_id=device_id)
    if err:
        logging.debug(f"error encountered while compiling {harnessess_path}, for harness: {harness_folder}, {err}")
        #out, err = adb.execute_privileged_command(f"ls {REMOTE_FOLDER}", device_id=device_id)
        #logging.debug(f"error while compiling, folder content: {out}")
    if not adb.path_exists(f"{REMOTE_FOLDER}/{harness_name}", device_id=device_id):
        print(f'{RED}[COMPILE]{NC} harness not compiled exiting!')
        return
    adb.pull_privileged(f"{REMOTE_FOLDER}/{harness_name}", os.path.join(harnessess_path, harness_folder, harness_name), device_id=device_id)
    if delete:
        adb.execute_privileged_command(f"rm {REMOTE_FOLDER}/{harness_name}", device_id=device_id)
    adb.execute_privileged_command(f"rm {REMOTE_FOLDER}/{harness_name}.cpp", device_id=device_id)
    logging.debug(f"finished compiling harness: {harness_folder}")


