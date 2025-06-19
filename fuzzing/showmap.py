"""
Script to run afl-showmap, retrieve the coverage map and to merge the coverage maps of multiple harneses into one
setup triaging environment on phone (harness)
"""
import sys
import time
import os
import argparse
import json
import logging
import subprocess
import shutil

BASE = os.path.dirname(__file__)

sys.path.append(os.path.join(BASE, ".."))
import adb
import harness.compile_harness

RED='\033[0;31m'                                                   
YELLOW='\033[0;33m'                                                                                                                          
GREEN='\033[0;32m'                                                                                                                           
NC='\033[0m'                                                                                                                                 
BLUE='\033[0;34m'         # Blue                                      
PURPLE='\033[0;35m'       # Purple                                                                                                           
CYAN='\033[0;36m'         # Cyan 

TARGET_APK_PATH = os.path.join(BASE, "..", "target_APK")
REMOTE_FOLDER = "/data/local/tmp/showmap/"
LD_PRELOAD = "/data/data/com.termux/files/usr/lib/libc++_shared.so"
NON_EXEC_CRASHES = "non_call_crashes"
REPRODUCED_CRASHES = "reproduced_crashes"
REPRODUCED_CRASHES_MIN = "reproduced_crashes_minimized"
REPRODUCED_CRASHES_DEDUP = "reproduced_crashes_minimized_deduplicated"


logging.basicConfig(filename='showmap.log', encoding='utf-8', level=logging.DEBUG, format='%(asctime)s %(message)s', force=True)


PARTIAL_COVERAGE = True

parse_from_argv = """
        std::string inputFile = argv[1];
        std::ifstream file(inputFile, std::ios::binary);
        file.seekg (0, file.end);
        size_t buf_size = file.tellg();
        file.seekg (0, file.beg);
        uint8_t* buffer = (uint8_t*)malloc(sizeof(char) * buf_size);
        file.read((char*)buffer, buf_size);
"""



def create_showmap_harness(harness_path, partial_coverage=False):
    harness_cpp = open(os.path.join(harness_path, "harness.cpp")).read()
    harness_showmap = harness_cpp.replace("""uint8_t buffer[1048576];
        size_t buf_size = 1048576;""", parse_from_argv)
    open(os.path.join(harness_path, "harness_showmap.cpp"), "w").write(harness_showmap)


def create_showmap_afl_js(ĥarness_path):
    afl_js = open(os.path.join(ĥarness_path, "afl.js")).read()
    afl_js_showmap = afl_js.replace("Afl.setPersistentHook(hook_module.afl_persistent_hook);\n", "")
    afl_js_showmap = afl_js_showmap.replace("Afl.setInMemoryFuzzing();\n", "")
    open(os.path.join(ĥarness_path, "afl_showmap.js"), "w").write(afl_js_showmap)
    

def do_showmap(app, fname, output_folder, device_id):

    app_path = os.path.join(TARGET_APK_PATH, app)
    adb.execute_privileged_command(f"mkdir -p {REMOTE_FOLDER}", device_id=device_id)
    harness.compile_harness.init_compilation(REMOTE_FOLDER, path="../harness", device_id=device_id)
    # upload app
    print(f"{PURPLE}[SHOWMAP]{NC} uploading app to phone")
    adb.execute_privileged_command(f"mkdir -p {REMOTE_FOLDER}/{app}", device_id=device_id)
    adb.push_privileged(os.path.join(TARGET_APK_PATH, app, "base.apk"), f"{REMOTE_FOLDER}/{app}", device_id=device_id)
    adb.push_privileged(os.path.join(TARGET_APK_PATH, app, "lib"), f"{REMOTE_FOLDER}/{app}", is_directory=True, device_id=device_id)
    if not adb.path_exists(os.path.join(REMOTE_FOLDER, "afl-showmap"), device_id=device_id):
        adb.push_privileged(os.path.join(BASE, "..", "afl", "afl-showmap"), REMOTE_FOLDER, device_id=device_id)
    if not adb.path_exists(os.path.join(REMOTE_FOLDER, "afl-frida-trace.so"), device_id=device_id):
        adb.push_privileged(os.path.join(BASE, "..", "afl", "afl-frida-trace.so"), REMOTE_FOLDER, device_id=device_id)
    own_libc = False
    for lib in os.listdir(os.path.join(TARGET_APK_PATH, app, "lib", "arm64-v8a")):
        if lib == "libc++_shared.so":
            own_libc = True
    ld_preload = ""
    if own_libc:
        # amend the LD_PRELOAD part of the command
        ld_preload = f'AFL_PRELOAD="{LD_PRELOAD} $(pwd)/{app}/lib/arm64-v8a/libc++_shared.so" '
    fuzzing_out = os.path.join(TARGET_APK_PATH, app, "fuzzing_output")
    os.system(f'mkdir -p {fuzzing_out}/cov_maps/')
    harness_path = os.path.join(app_path, "harnesses", fname)
    # copy harness.cpp and change it to parse the input from a file in argv[1]
    harness_cpp = os.path.join(harness_path, "harness.cpp")
    if not os.path.exists(harness_cpp):
        print(f'{RED}{harness_cpp} does not exists WTF{NC}')
        logging.errro(f'{harness_cpp} does not exists WTF')
        return
    info_json = os.path.join(harness_path, "info.json")
    if not os.path.exists(info_json):
        print(f'{RED}[ERROR]{NC} No info.json in harness folder! Please generate the harnesses again!')
        logging.errro(f'{info_json} does not exists WTF')
        return
    info_json = json.load(open(info_json))
    targetlibrary = info_json['targetlibrary']
    targetclassname = info_json['targetclassname']
    print(f'{PURPLE}[SHOWMAP]{NC} Creating showmap harness')
    create_showmap_afl_js(harness_path)
    create_showmap_harness(harness_path, partial_coverage=PARTIAL_COVERAGE) # now in the hanress_path there will be harness_showmap.cpp
    print(f'{PURPLE}[SHOWMAP]{NC} Compiling showmap harness')
    if os.path.exists(os.path.join(TARGET_APK_PATH, app, "harnesses", fname, "harness_showmap")):
        subprocess.run(f'rm {os.path.join(TARGET_APK_PATH, app, "harnesses", fname, "harness_showmap")}', shell=True)
    harness.compile_harness.compile_harness(fname, os.path.join(TARGET_APK_PATH, app, "harnesses"), REMOTE_FOLDER, showmap=True, device_id=device_id)
    # upload new harness
    adb.push_privileged(os.path.join(BASE, "..", "harness", "cpp", "libharness.so"), REMOTE_FOLDER+"/libharness.so", device_id=device_id) 
    adb.push_privileged(os.path.join(TARGET_APK_PATH, app, "harnesses", fname, "harness_showmap"), REMOTE_FOLDER+"/harness", device_id=device_id) 
    #adb.execute_privileged_command(f"cp {REMOTE_FOLDER}/harness_showmap {REMOTE_FOLDER}/harness", device_id=device_id)
    adb.execute_privileged_command(f"chmod +x {REMOTE_FOLDER}/harness", device_id=device_id)
    adb.push_privileged(os.path.join(harness_path, "afl_showmap.js"), f'{REMOTE_FOLDER}/afl.js', device_id=device_id)
    # setup the showmap specific stuff
    adb.execute_privileged_command(f"mkdir {REMOTE_FOLDER}/seeds", device_id=device_id)
    fuzz_output_path = os.path.join(TARGET_APK_PATH, app, "fuzzing_output", fname)
    only_seeds = False
    if not os.path.exists(fuzz_output_path):
        only_seeds = True
        print(f"{YELLOW}[SHOWMAP]{NC} no fuzzing output for {app}, {fname}, only uploading seeds")
        for seed in os.path.join(harness_path, "seeds"):
            adb.push_privileged(os.path.join(harness_path, "seeds", seed), f'{REMOTE_FOLDER}/seeds')
    else:
        print(f"{PURPLE}[SHOWMAP]{NC} uploading queue from {output_folder}")
        for instance in os.listdir(os.path.join(fuzz_output_path, output_folder)):
            #for crash in os.listdir(os.path.join(fuzz_output_path, output_folder, instance, "crashes")):
            #    adb.push_privileged(os.path.join(fuzz_output_path, output_folder, instance, "crashes", crash), f"{REMOTE_FOLDER}/seeds/{output_folder}_{instance}_{crash}", device_id=device_id)
            for seed in os.listdir(os.path.join(fuzz_output_path, output_folder, instance, "queue")):
                adb.push_privileged(os.path.join(fuzz_output_path, output_folder, instance, "queue", seed), f"{REMOTE_FOLDER}/seeds/{output_folder}_{instance}_{seed}", device_id=device_id)
    if not only_seeds:
        adb.execute_privileged_command(f'rm {REMOTE_FOLDER}/seeds/*seed*', device_id=device_id)
    # upload the queue + crashes, if those don't exist upload the 
    print(f'{PURPLE}[SHOWMAP]{NC} Running Showmap command')
    try:
        out, err = adb.execute_privileged_command(f"cd {REMOTE_FOLDER} && {ld_preload} AFL_FRIDA_INST_SEED=1 LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/{app}/lib/arm64-v8a:/system/lib64 ANDROLIB_APP_PATH={app} ANDROLIB_TARGET_LIBRARY={targetlibrary} ANDROLIB_CLASS0={targetclassname} ANDROLIB_MEMORY=memory ./afl-showmap -t 60000 -O -i seeds/ -C -o outputshow ./harness @@", timeout=3600, device_id=device_id)
    except adb.DeviceTimeoutException:
        logging.info(f"{app}-{fname} timeout over 3600")
        print(f"[SHOWMAP] timed out, {out}, {err}")
        adb.execute_privileged_command(f'rm -rf {REMOTE_FOLDER}/*', device_id=device_id)
        return
    adb.pull_privileged(f'{REMOTE_FOLDER}/outputshow', os.path.join(fuzzing_out, 'cov_maps', f'{fname}_covmap'), device_id=device_id)
    adb.execute_privileged_command(f'rm -rf {REMOTE_FOLDER}/*', device_id=device_id)


if __name__ == "__main__":
    logging.basicConfig(filename='showmap.log', encoding='utf-8', level=logging.DEBUG, format='%(asctime)s %(message)s', force=True)

    print("given a json with apps2harnesses and a description of the coverage, runs afl-showmap on the queue, retrieves, merges the data. The final coverage map is stored at fuzzing_output/{descrption}")
    """
    input json
    "app": {
        "harness" : ["output_emulator...", "output_emulator.."]

    }
    """
    if len(sys.argv) != 5:
        print("usage: python3 fuzzing/showmap.py app_harness.json device_id")
    app = sys.argv[1]
    fname = sys.argv[2]
    output_folder = sys.argv[3]
    device_id = sys.argv[4]
    do_showmap(app, fname, output_folder, device_id)
