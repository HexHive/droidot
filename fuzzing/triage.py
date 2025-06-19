"""
Script for triaging
setup triaging environment on phone (harness)
"""
import sys
import time
import os
import argparse
import json
import logging
import shutil
BASE_PATH = os.path.dirname(__file__)
sys.path.append(os.path.join(BASE_PATH, '..'))
import adb
import testing

RED='\033[0;31m'                                                   
YELLOW='\033[0;33m'                                                                                                                          
GREEN='\033[0;32m'                                                                                                                           
NC='\033[0m'                                                                                                                                 
BLUE='\033[0;34m'         # Blue                                      
PURPLE='\033[0;35m'       # Purple                                                                                                           
CYAN='\033[0;36m'         # Cyan 

TARGET_APK_PATH = os.path.join(BASE_PATH, "..", "target_APK")
REMOTE_FOLDER = "/data/local/tmp/triage/"
LD_PRELOAD = "/data/data/com.termux/files/usr/lib/libc++_shared.so"
NON_EXEC_CRASHES = "non_call_crashes"
REPRODUCED_CRASHES = "reproduced_crashes"
REPRODUCED_CRASHES_MIN = "reproduced_crashes_minimized"
REPRODUCED_CRASHES_DEDUP = "reproduced_crashes_minimized_deduplicated"

APP_SETUP = False

logging.basicConfig(filename='triage.log', encoding='utf-8', level=logging.DEBUG, format='%(asctime)s %(message)s', force=True)


def wait_for_device(device):
    while True:
        devices = adb.get_device_ids()
        if device.encode() not in devices:
            print(devices)
            print(f"waiting for {device} to reboot...")
            time.sleep(5)
        else:
            return

def clean(device_id=None):
    adb.execute_privileged_command(f"rm -r {REMOTE_FOLDER}", device_id=device_id)


def parse_bt(backtrace):
    """
    open backtrace file and get the function names
    """
    with open(backtrace, "r") as f:
        bt = f.read().splitlines()
    parsed_bt = []
    #0  0x0000007e88fd0980 in strchr_default () from /apex/com.android.runtime/lib64/bionic/libc.so
    #1  0x0000007bdbd84bac in decodeBytes () from /data/local/tmp/triage/com.trakm8.fleet/lib/arm64-v8a/libtbxml.so
    #2  0x0000007bdbd85104 in Java_za_co_twyst_tbxml_TBXML_jniParse () from /data/local/tmp/triage/com.trakm8.fleet/lib/arm64-v8a/libtbxml.so
    #3  0x00000059698c6c64 in main (argc=6, argv=0x7fe0b7e448) at harness_debug.cpp:250
    for l in bt:
        l = l[l.find("in")+3:]
        l = l[:l.find("(")]
        parsed_bt.append(l)
    return "\n".join(parsed_bt)


def deduplicate_crashes(app, function_name):
    """
    move duplicate crashes into a folder numbered 0,1 ... csv with the mapping from folder to crash name
    """
    fuzz_output_path = os.path.join(TARGET_APK_PATH, app, "fuzzing_output", function_name)
    repr_crashes_path = os.path.join(TARGET_APK_PATH, app, "fuzzing_output", function_name, REPRODUCED_CRASHES)
    min_crashes_path = os.path.join(TARGET_APK_PATH, app, "fuzzing_output", function_name, REPRODUCED_CRASHES_MIN) 
    min_done = os.path.exists(min_crashes_path)
    backtraces_path = os.path.join(TARGET_APK_PATH, app, "fuzzing_output", function_name, REPRODUCED_CRASHES, "backtraces")
    print(f"{PURPLE}[TRIAGE]{NC} grouping crashes by backtrace for {app}-{function_name}")
    if not os.path.exists(backtraces_path):
        print(f"{RED}[TRIAGE]{NC} no backtraces found, please run --rerun with --rerun_crashes_backtrace!!")
        exit(-1)
    mapping = {}
    for crash in os.listdir(backtraces_path):
        parsed_bt = parse_bt(os.path.join(backtraces_path, crash))
        if parsed_bt in mapping:
            mapping[parsed_bt].append(crash)
        else:
            mapping[parsed_bt] = [crash]
    mapping_txt = ""
    for i, parsed_bt in enumerate(mapping):
        bt_folder_path_repr = os.path.join(repr_crashes_path, "bt_"+str(i))
        if min_done:
            bt_folder_path_repr_min = os.path.join(min_crashes_path, "bt_"+str(i))
            os.makedirs(bt_folder_path_repr_min)
        os.makedirs(bt_folder_path_repr,exist_ok=True)
        for k, crash in enumerate(mapping[parsed_bt]):
            if os.path.exists(os.path.join(repr_crashes_path, crash)):
                if k == 0:
                    shutil.copy(os.path.join(repr_crashes_path, crash), os.path.join(bt_folder_path_repr, crash))
                else: 
                    shutil.move(os.path.join(repr_crashes_path, crash), os.path.join(bt_folder_path_repr, crash))
            if min_done and os.path.exists(os.path.join(min_crashes_path, crash)):
                if k == 0:
                    shutil.copy(os.path.join(min_crashes_path, crash), os.path.join(bt_folder_path_repr_min, crash))
                else:
                    shutil.move(os.path.join(min_crashes_path, crash), os.path.join(bt_folder_path_repr_min, crash))
        if min_done:
            with open(os.path.join(bt_folder_path_repr_min, "backtrace.txt"), "w") as f:
                f.write(parsed_bt)
        with open(os.path.join(bt_folder_path_repr, "backtrace.txt"), "w") as f:
            f.write(parsed_bt)
        mapping_txt += f"################ CRASH NR {i} ######################\n"
        mapping_txt += parsed_bt
        mapping_txt += "\n###################################################\n"
    with open(os.path.join(repr_crashes_path, "folder2backtraces.txt"), "w") as f:
        f.write(mapping_txt)
    if min_done:
        with open(os.path.join(min_crashes_path, "folder2backtraces.txt"), "w") as f:
            f.write(mapping_txt)
    print(f"{GREEN}[TRIAGE]{NC} finished grouping crashes")


def rerun_crashes(app, function_name, device_id, with_forking=True, with_unmapping=False, with_clean=True, with_bt=True):
    """
    try to reproduce each crash with the non instrumented library
    output is put into fuzzing_output/reproduced_crashes, fuzzing_output/non_call_crashes
    """
    clean(device_id=device_id)
    harness_path = os.path.join(TARGET_APK_PATH, app, "harnesses", function_name)
    if not os.path.exists(harness_path):
        print(f'{RED}[ERROR]{NC} Harness not found! please run harness generation!')
        exit(-1)
    print(f"{PURPLE}[TRIAGE]{NC} Setting up phone for {app}-{function_name}")
    info_json = os.path.join(harness_path, "info.json")
    if not os.path.exists(info_json):
        print(f'{RED}[ERROR]{NC} No info.json in harness folder! Please generate the harnesses again!')
        exit(-1)
    info_json = json.load(open(info_json))
    targetlibrary = info_json['targetlibrary']
    targetclassname = info_json['targetclassname']
    testing.setup(app, function_name, harness_path, UPLOAD_APP=True, INIT_COMPILE=True, COMPILE_HARNESS=True, remote_folder=REMOTE_FOLDER, device_id=device_id)
    global APP_SETUP
    APP_SETUP = True
    adb.execute_privileged_command(f"mkdir -p {REMOTE_FOLDER}/crashes", device_id=device_id)
    # upload the crashes 
    fuzz_output_path = os.path.join(TARGET_APK_PATH, app, "fuzzing_output", function_name)
    if not os.path.exists(fuzz_output_path):
        print(f"{RED}[TRIAGE]{NC} no fuzzing output for {app}, {function_name}, exiting")
        return 
    if with_clean:
        print(f"[TRIAGE] removing local folders")
        if os.path.exists(os.path.join(fuzz_output_path, NON_EXEC_CRASHES)):
            shutil.rmtree(os.path.join(fuzz_output_path, NON_EXEC_CRASHES))
        if os.path.exists(os.path.join(fuzz_output_path, REPRODUCED_CRASHES)):
            shutil.rmtree(os.path.join(fuzz_output_path, REPRODUCED_CRASHES))
    crashes = []
    print(f"{PURPLE}[TRIAGE]{NC} uploading crashes")
    for device in os.listdir(fuzz_output_path):
        if device == NON_EXEC_CRASHES or device == REPRODUCED_CRASHES or device == REPRODUCED_CRASHES_MIN:
                continue
        for instance in os.listdir(os.path.join(fuzz_output_path, device)):
            for crash in os.listdir(os.path.join(fuzz_output_path, device, instance, "crashes")):
                adb.push_privileged(os.path.join(fuzz_output_path, device, instance, "crashes", crash), f"{REMOTE_FOLDER}/crashes/{device}_{instance}_{crash}", device_id=device_id)
                crashes.append(f"{device}_{instance}_{crash}")
    print(f"{GREEN}[TRIAGE]{NC} done uploading crashes")
    own_libc = False
    for lib in os.listdir(os.path.join(TARGET_APK_PATH, app, "lib", "arm64-v8a")):
        if lib == "libc++_shared.so":
            own_libc = True
    ld_preload = ""
    if own_libc:
        # amend the LD_PRELOAD part of the command
        ld_preload = f'LD_PRELOAD="{LD_PRELOAD} $(pwd)/{app}/lib/arm64-v8a/libc++_shared.so" '
    print(f"{PURPLE}[TRIAGE]{NC} executing crashes")
    if with_forking:
        fork = "1"
    else:
        fork = "0"
    if with_unmapping:
        unmap = "1"
    else:
        unmap = "0"
    for crash in crashes:
        wait_for_device(device=device_id)
        time.sleep(1)
        dl_crash = False
        if "README.txt" in crash:
            continue
        try:
            out, err = adb.execute_privileged_command(f"cd {REMOTE_FOLDER} && ulimit -c unlimited && {ld_preload} LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/{app}/lib/arm64-v8a ANDROLIB_APP_PATH={app} ANDROLIB_TARGET_LIBRARY={targetlibrary} ANDROLIB_CLASS0={targetclassname} ANDROLIB_MEMORY=memory ./harness_debug ./crashes/{crash} {unmap} {fork}", timeout=60, device_id=device_id)
        except adb.DeviceTimeoutException:
            logging.info(f"{app}-{function_name} timeout over 60s")
            print(f"[TRIAGE]{crash} function timed out")
            continue
        if b"CALLING" in out:
            if b"EXITED DUE TO SIGNAL b" in out or b"EXITED DUE TO SIGNAL 11" in out:
                logging.info(f"{crash} function called, exited with SEGFAULT")
                print(f"[TRIAGE]{crash} function called, exited with SEGFAULT")
                dl_crash = True
            elif b"EXITED DUE TO SIGNAL 6" in out:
                logging.info(f"{crash} function called, exited with ABORT")
                print(f"[TRIAGE] {crash} function called, exited with ABORT")
                dl_crash = True
            elif b"EXITED NORMALLY:)" in out:
                logging.info(f"{crash} function called, exited normally!")
                print(f"[TRIAGE] {crash} function called, exited normally!")
            else:
                logging.info(f"{crash} function called, unknown exit code: {out.splitlines()[-4:]}, {err}")
                print(f"[TRIAGE] {crash} function called, unknown exit code: {out.splitlines()[-4:]}")
                dl_crash = True
        else:
            logging.info(f"{crash} function not called, stderr: {out.splitlines()[-4:]}, {err}")
            print(f"[TRIAGE]{crash} function not called, stderr: {out.splitlines()[-4:]}")
            os.makedirs(os.path.join(fuzz_output_path, NON_EXEC_CRASHES), exist_ok=True)
            adb.pull_privileged(f"{REMOTE_FOLDER}/crashes/{crash}", os.path.join(fuzz_output_path, NON_EXEC_CRASHES), device_id=device_id)
            adb.execute_privileged_command(f"mkdir -p {REMOTE_FOLDER}/non_exec_crashes", device_id=device_id)
            adb.execute_privileged_command(f"cp {REMOTE_FOLDER}/crashes/{crash} {REMOTE_FOLDER}/non_exec_crashes/{crash}", device_id=device_id)
        if dl_crash:
            os.makedirs(os.path.join(fuzz_output_path, REPRODUCED_CRASHES), exist_ok=True)
            adb.pull_privileged(f"{REMOTE_FOLDER}/crashes/{crash}", os.path.join(fuzz_output_path, REPRODUCED_CRASHES), device_id=device_id)
            adb.execute_privileged_command(f"mkdir -p {REMOTE_FOLDER}/reproduced_crashes", device_id=device_id)
            adb.execute_privileged_command(f"cp {REMOTE_FOLDER}/crashes/{crash} {REMOTE_FOLDER}/reproduced_crashes/{crash}", device_id=device_id)
            if with_bt:
                print(f"[TRIAGE] running crash {crash} for backtrace")
                out, err = adb.execute_privileged_command(f'PATH=//data/data/com.termux/files/usr/bin:$PATH && cd {REMOTE_FOLDER} && gdb --init-eval-command="set auto-load safe-path ." --init-eval-command="source ./dump_bt.py" --eval-command="dumpbt" --eval-command="q" --core=core ./harness_debug', device_id=device_id)
                os.makedirs(os.path.join(fuzz_output_path, REPRODUCED_CRASHES, "backtraces"), exist_ok=True)
                adb.pull_privileged(f"{REMOTE_FOLDER}/dumpbt.txt", os.path.join(fuzz_output_path, REPRODUCED_CRASHES, "backtraces", crash), device_id=device_id)
                adb.execute_privileged_command(f"rm {REMOTE_FOLDER}/dumpbt.txt", device_id=device_id)
                adb.execute_privileged_command(f"rm {REMOTE_FOLDER}/core", device_id=device_id)
    print(f"{GREEN}[TRIAGE]{NC} finished executing crashes")
    adb.execute_privileged_command("ulimit -c 0", device_id=device_id)
    if with_bt:
        deduplicate_crashes(app, function_name)


def setup_debug(app, function_name, device_id=None):
    """
    setup everything for debugging
    """
    global APP_SETUP
    if not APP_SETUP:
        clean(device_id=device_id)
    harness_path = os.path.join(TARGET_APK_PATH, app, "harnesses", function_name)
    if not os.path.exists(harness_path):
        print(f'{RED}[ERROR]{NC} Harness not found! please run harness generation!')
        exit(-1)
    print(f"{PURPLE}[TRIAGE]{NC} Setting up on the phone for debugging for {app}-{function_name}")
    info_json = os.path.join(harness_path, "info.json")
    if not os.path.exists(info_json):
        print(f'{RED}[ERROR]{NC} No info.json in harness folder! Please generate the harnesses again!')
        exit(-1)
    info_json = json.load(open(info_json))
    targetlibrary = info_json['targetlibrary']
    targetclassname = info_json['targetclassname']
    if not APP_SETUP:
        testing.setup(app, function_name, harness_path, UPLOAD_APP=True, COMPILE_HARNESS=True, remote_folder=REMOTE_FOLDER, device_id=device_id)
    print(f"{PURPLE}[TRIAGE]{NC} uploading crashes")
    repr_crashes_path = os.path.join(TARGET_APK_PATH, app, "fuzzing_output", function_name, REPRODUCED_CRASHES)
    min_crashes_path = os.path.join(TARGET_APK_PATH, app, "fuzzing_output", function_name, "reproduced_crashes_minimized") 
    if not os.path.exists(repr_crashes_path) and not os.path.exists(min_crashes_path):
        print(f"{RED}[TRIAGE]{NC} no reproduced_crashes folders found! please first run with --rerun")
        return 
    if os.path.exists(repr_crashes_path):
        adb.push_privileged(os.path.join(repr_crashes_path), f"{REMOTE_FOLDER}/", is_directory=True, device_id=device_id)
    if os.path.exists(min_crashes_path):
        adb.push_privileged(os.path.join(min_crashes_path), f"{REMOTE_FOLDER}/", is_directory=True, device_id=device_id)
    adb.push_privileged(os.path.join(TARGET_APK_PATH, app, "fuzzing_output", function_name), f"{REMOTE_FOLDER}/output", is_directory=True, device_id=device_id)
    own_libc = False
    for lib in os.listdir(os.path.join(TARGET_APK_PATH, app, "lib", "arm64-v8a")):
        if lib == "libc++_shared.so":
            own_libc = True
    ld_preload = ""
    if own_libc:
        # amend the LD_PRELOAD part of the command
        ld_preload = f'LD_PRELOAD="{LD_PRELOAD} $(pwd)/{app}/lib/arm64-v8a/libc++_shared.so" '
    print(f"{GREEN}[TRIAGE]{NC} finished setting up for triage")
    print(80*"=")
    print("debugging commands:")
    print(f"adb -s {device_id} shell; su; cd {REMOTE_FOLDER}")
    print("set PATH:")
    print("PATH=//data/data/com.termux/files/usr/bin:$PATH ")
    print(f"{ld_preload}LD_LIBRARY_PATH=/apex/com.android.art/lib64:$(pwd):$(pwd)/{app}/lib/arm64-v8a:/system/lib64 ANDROLIB_APP_PATH={app} ANDROLIB_TARGET_LIBRARY={targetlibrary} ANDROLIB_CLASS0={targetclassname} ANDROLIB_MEMORY=memory gdb -iex 'set auto-load safe-path .' --args ./harness_debug [crash_path] 0 0")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description=f'Help with triaging crashes, testing folder is currently: {REMOTE_FOLDER}')
    parser.add_argument("--target", type=str, required=True, help="The appname in target_APK")
    parser.add_argument("--target_function", type=str, required=True, help="The harness name of the native function")
    parser.add_argument("--device", type=str, required=True, help="specify a specific device on which to test")
    parser.add_argument("-c", "--clean", default=False, action="store_true", help="cleanup remote triage folder")
    parser.add_argument("-r", "--rerun", default=False, action="store_true", help="try reproducing the crashes on non-instrumented library, group by backtrace")
    parser.add_argument("-d", "--debug", default=False, action="store_true", help="setup debugging for crashes, install gef from termux with wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py")

    args = parser.parse_args()    

    if args.clean:
        clean(device_id=args.device)

    if args.rerun:
        rerun_crashes(args.target, args.target_function, device_id=args.device)

    if args.debug:
        setup_debug(args.target, args.target_function, device_id=args.device)
