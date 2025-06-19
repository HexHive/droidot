import os
import logging
import datetime
import re
import shutil
from statistics import mean
import time
import sys
import adb
import json
from defs import *
from utility import *
import harness.compile_harness as compile_harness

BASE = os.path.dirname(__file__)


def setup_fuzz(app, fname, device_id, print_color=NC):
    """
    Setup the folder structure and files needed to fuzz on the device
    This function requires that harnesses are already generated for the function!
    @app: the app identifier of the target app
    @fname: Java function name to fuzz + @identifier for harness type/multiple harnesses
    @device_id: device id on which to setup
    returns: output directory name on the device
    """
    logging.info(f'[{device_id.decode()}] setting up fuzzing for {app}:{fname}')  
    print(f'{print_color}[{device_id.decode()}] setting up fuzzing for {app}:{fname}{NC}')

    adb.execute_privileged_command("cd /sys/devices/system/cpu && echo performance | tee cpu*/cpufreq/scaling_governor", device_id=device_id)
    adb.execute_privileged_command("ulimit -c 0", device_id=device_id) # not setting this might lead to crashes hanging and not getting saved

    dt_string = datetime.datetime.now().strftime("%H:%M-%d-%m-%Y")
    harness_path = os.path.join(TARGET_APK_PATH, app, "harnesses", fname) # 
    fuzzing_path = os.path.join(FUZZING_DIRECTORY, f"{app}-{fname}") # path on phone

    # retrieve function offset for the function
    library, offset = get_library_offset4function(app, fname)
    if library == "" or offset == "":
        logging.error(f'[{device_id.decode()}] function offset not found')  
        print(f"{print_color}[{device_id.decode()}] function offset not found for {app}:{fname}{NC}")
        return -1

    # compile harness if it doesn't exist
    adb.execute_privileged_command(f"mkdir -p {FUZZING_DIRECTORY}", device_id=device_id)
    if not os.path.exists(os.path.join(harness_path, "harness")):
        logging.info(f'[{device_id.decode()}] compiling harness for {app}:{fname}')  
        #print(f"{print_color}[{device_id.decode()}] Compiling harness for {app}:{fname}{NC}")
        compile_harness.init_compilation(FUZZING_DIRECTORY, path=os.path.join(BASE, "..", "..", "harness"), device_id=device_id)
        compile_harness.compile_harness(fname, os.path.join(TARGET_APK_PATH, app, "harnesses"), FUZZING_DIRECTORY, device_id=device_id, delete=True)
    
    if not adb.path_exists(os.path.join(FUZZING_DIRECTORY, "afl-fuzz"), device_id=device_id):
        adb.push_privileged(os.path.join(BASE, "..","..", "afl", "afl-fuzz"), FUZZING_DIRECTORY, device_id=device_id)

    if not adb.path_exists(os.path.join(FUZZING_DIRECTORY, "afl-frida-trace.so"), device_id=device_id):
        adb.push_privileged(os.path.join(BASE, "..","..", "afl", "afl-frida-trace.so"), FUZZING_DIRECTORY, device_id=device_id)

    if not adb.path_exists(os.path.join(FUZZING_DIRECTORY, "libharness.so"), device_id=device_id):
        adb.push_privileged(os.path.join(BASE, "..","..", "harness", "cpp", "libharness.so"), FUZZING_DIRECTORY, device_id=device_id)

    # in case the directory already exists delete any remaining memory dumps
    adb.execute_privileged_command(f"rm -r -f {FUZZING_DIRECTORY}/*/memory*", device_id=device_id)

    # upload fuzzing working dir with seeds, output directory and harness
    logging.info(f'[{device_id.decode()}] setting up fuzzing directory structure')  
    #print(f"{print_color}[{device_id.decode()}] setting up fuzzing directory structure for {app}:{fname}")
    adb.execute_privileged_command(f"mkdir -p {shell_escape(fuzzing_path)}", device_id=device_id)
    adb.push_privileged(os.path.join(harness_path, "seeds"), shell_escape(fuzzing_path), is_directory=True, device_id=device_id)
 
    output_dir = f"output_{device_id.decode('utf-8')}_{dt_string}"
    adb.execute_privileged_command(f"mkdir {shell_escape(os.path.join(fuzzing_path, output_dir))}", device_id=device_id)
    adb.push_privileged(os.path.join(harness_path, "harness"), shell_escape(fuzzing_path), device_id=device_id)
    adb.execute_privileged_command(f"chmod +x {shell_escape(os.path.join(fuzzing_path, 'harness'))}", device_id=device_id)
    adb.push_privileged(os.path.join(harness_path, "afl.js"), shell_escape(fuzzing_path), device_id=device_id)

    # link afl-frida-trace to the uploaded so file
    adb.execute_privileged_command(f"ln -s {FUZZING_DIRECTORY}/afl-frida-trace.so {fuzzing_path}/afl-frida-trace.so", device_id=device_id)
    adb.execute_privileged_command(f"ln -s {FUZZING_DIRECTORY}/libharness.so {fuzzing_path}/libharness.so", device_id=device_id)

    # if apk is not present upload it to the fuzzing_dir/target_APK path
    adb.execute_privileged_command(f"mkdir -p {os.path.join(FUZZING_DIRECTORY, 'target_APK')}", device_id=device_id)
    device_app_path = os.path.join(FUZZING_DIRECTORY, "target_APK", app)
    if not adb.path_exists(device_app_path, device_id=device_id) or not adb.path_exists(device_app_path+"/base.apk", device_id=device_id) or not adb.path_exists(device_app_path+"/lib/arm64-v8a", device_id=device_id):
        logging.info(f'[{device_id}] uploading apk to device')
        #print((f'{print_color}[{device_id.decode()}] uploading apk {app}to device'))
        adb.execute_privileged_command(f"mkdir {device_app_path}", device_id=device_id)
        adb.push_privileged(os.path.join(TARGET_APK_PATH, app, "base.apk"), device_app_path, device_id=device_id)
        adb.push_privileged(os.path.join(TARGET_APK_PATH, app, "lib"), device_app_path, is_directory=True, device_id=device_id)

    # check if fuzzing_one.sh script is pressent
    if not adb.path_exists(os.path.join(FUZZING_DIRECTORY, "fuzzing_one.sh"), device_id=device_id):
        adb.push_privileged(os.path.join(BASE, "..", "fuzzing_one.sh"), FUZZING_DIRECTORY, device_id=device_id)
        adb.execute_privileged_command(f"chmod +x {os.path.join(FUZZING_DIRECTORY, 'fuzzing_one.sh')}", device_id=device_id)

    # sandbox
    adb.execute_privileged_command(f'chmod 755 -R {FUZZING_DIRECTORY}/target_APK/', device_id=device_id)
    adb.execute_privileged_command(f'chmod 755 {FUZZING_DIRECTORY}/', device_id=device_id)
    adb.execute_privileged_command(f'chmod 755 {FUZZING_DIRECTORY}/afl-frida-trace.so', device_id=device_id)
    adb.execute_privileged_command(f'chmod 755 {FUZZING_DIRECTORY}/afl-fuzz', device_id=device_id)
    adb.execute_privileged_command(f'chmod 755 {FUZZING_DIRECTORY}/fuzzing_one.sh', device_id=device_id)
    adb.execute_privileged_command(f'chmod 755 {FUZZING_DIRECTORY}/libharness.so', device_id=device_id)
    adb.execute_privileged_command(f'chown nobody {fuzzing_path}', device_id=device_id)
    adb.execute_privileged_command(f'/data/data/com.termux/files/usr/bin/chmod -R +r+x /data/data/com.termux', device_id=device_id)
    return output_dir
    

def setup_add_outfolder(app, fname, device_id, print_color=NC):
    """
    Add an additional output folder for another fuzzing campaign
    !!IMPORTANT!! only run after running setup_fuzz previously
    """
    dt_string = datetime.datetime.now().strftime("%H:%M-%d-%m-%Y")
    fuzzing_path = os.path.join(FUZZING_DIRECTORY, f"{app}-{fname}") # path on phone
    output_dir = f"output_{device_id.decode('utf-8')}_{dt_string}"
    adb.execute_privileged_command(f"mkdir {shell_escape(os.path.join(fuzzing_path, output_dir))}", device_id=device_id)
    adb.execute_privileged_command(f'chown nobody {shell_escape(os.path.join(fuzzing_path, output_dir))}', device_id=device_id)
    return output_dir


def remove_outdir(app, fname, output_dir, device_id, print_color=NC):
    fuzzing_path = os.path.join(FUZZING_DIRECTORY, f"{app}-{fname}") # path on phone
    adb.execute_privileged_command(f"rm -rf {shell_escape(os.path.join(fuzzing_path, output_dir))}", device_id=device_id)


def clean_harness_fuzz(app, fname, device_id, print_color=NC):
    fuzzing_path = os.path.join(FUZZING_DIRECTORY, f"{app}-{fname}") # path on phone
    adb.execute_privileged_command(f"rm -rf {shell_escape(fuzzing_path)}", device_id=device_id)

def start_fuzz(app, fname, output_dir, device_id, parallel=0, cmplog=0, check_started=False, print_color=NC):
    """
    Start fuzzing with the fuzzing_one.sh script (needed for env variables)
    Depends on setup_fuzz to be called beforehand with the same app and fname
    """
    # we check if the app ships it's own libc++, if it does we preload it for fuzzing
    #print(f"{print_color}[{device_id.decode()}] starting to fuzz {app}:{fname}")
    logging.info(f"starting to fuzz {app}:{fname}")
    ld_preload = ""
    for lib in os.listdir(os.path.join(TARGET_APK_PATH, app, "lib", "arm64-v8a")):
        if lib == "libc++_shared.so":
            ld_preload = f'$(pwd)/target_APK/{app}/lib/arm64-v8a/libc++_shared.so' 
    if not os.path.exists(os.path.join(TARGET_APK_PATH, app, "harnesses", fname, "info.json")):
        raise Exception('harness info.json does not exist!')
    harness_info = json.load(open(os.path.join(TARGET_APK_PATH, app, "harnesses", fname, "info.json")))
    targetlibrary = harness_info['targetlibrary']
    targetclassname = harness_info['targetclassname']
    adb.execute_nobody_command(f'cd {FUZZING_DIRECTORY} && ./fuzzing_one.sh ../target_APK/{app} {targetlibrary} {targetclassname} seeds {output_dir} {app}-{shell_escape(fname)} {parallel} {cmplog} {ld_preload}', wait_for_termination=False, device_id=device_id)
    if check_started:
        time.sleep(30+parallel*30)
        nr_afl = get_running_fuzzers(device_id)
        return nr_afl
    return -1


def get_running_fuzzers(device_id, print_color=NC):
    # check if fuzzer is still running
    ALL_PROC = adb.execute_privileged_command("ps -ef | grep afl-fuzz | grep -v grep | grep -v timeout", device_id=device_id)[0].decode('utf-8').split("\n")[:-1]
    NR_PROC = len(list(map(lambda x: re.sub("\s+", " ", x).split(" ")[1], ALL_PROC)))
    return NR_PROC


def stop_fuzz(device_id, print_color=NC):
    """
    kill all afl-fuzz processes
    """
    # kill AFL
    ALL_PROC = adb.execute_privileged_command("ps -ef | grep afl-fuzz | grep -v grep | grep -v timeout", device_id=device_id)[0].decode('utf-8').split("\n")[:-1]
    ALL_PROC = list(map(lambda x: re.sub("\s+", " ", x).split(" ")[1], ALL_PROC))
    for P in ALL_PROC:
        adb.execute_privileged_command("kill -9 " + P, device_id=device_id)
    # kill any running harnesses
    ALL_PROC = adb.execute_privileged_command("ps -ef | grep harness | grep -v grep | grep -v timeout | grep -v afl-fuzz", device_id=device_id)[0].decode('utf-8').split("\n")[:-1]
    ALL_PROC = list(map(lambda x: re.sub("\s+", " ", x).split(" ")[1], ALL_PROC))
    for P in ALL_PROC:
        adb.execute_privileged_command("kill -9 " + P, device_id=device_id)
    adb.execute_privileged_command(f"rm -r -f {FUZZING_DIRECTORY}/*/memory*", device_id=device_id)
    return len(ALL_PROC)


def fetch_fuzz_one(app, fname, fuzz_out_path, device_id, print_color=NC):
    """
    fetch the current fuzzer output from the phone
    TODO: what to do if it crashes right away
    """
    logging.info(f'[{device_id.decode()}] fetching fuzz output {fuzz_out_path} for {app} {fname}')
    print(f'{print_color}[{device_id.decode()}] fetching fuzz output {fuzz_out_path} for {app} {fname}{NC}')
    fuzzing_path = os.path.join(FUZZING_DIRECTORY, f"{app}-{fname}")
    # create the output directory if it doesn't already exist
    output_path = os.path.join(TARGET_APK_PATH, app, "fuzzing_output")
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    output_path = os.path.join(output_path, fname)
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    if os.path.exists(os.path.join(output_path, fuzz_out_path)):
        shutil.rmtree(os.path.join(output_path, fuzz_out_path))
    adb.pull_privileged(f"{fuzzing_path}/{fuzz_out_path}", output_path, is_directory=True, device_id=device_id)
    return fuzz_out_path


def fetch_fuzz_all(app, fname, device_id):
    fuzzing_path = os.path.join(FUZZING_DIRECTORY, f"{app}-{fname}")
    # create the output directory if it doesn't already exist
    output_path = os.path.join(TARGET_APK_PATH, app, "fuzzing_output")
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    output_path = os.path.join(output_path, fname)
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    fuzz_out_folders = adb.execute_privileged_command(f"cd {fuzzing_path} && ls . | grep output", device_id=device_id)[0]
    fuzz_out_folders = fuzz_out_folders.decode().splitlines()
    for folder in fuzz_out_folders:
        if folder == "":
            continue
        fetch_fuzz_one(app, fname, folder, device_id)


def clean_fuzz(device_id, print_color=NC):
    logging.info(f'[{device_id}] cleaning fuzzing directory {FUZZING_DIRECTORY}')
    #print(f'{print_color}[{device_id}] cleaning fuzzing directory {FUZZING_DIRECTORY}')
    adb.execute_privileged_command(f'rm -rf {FUZZING_DIRECTORY}/*', device_id=device_id)


def parse_out(app, fname, fuzz_out_folder, device_id, print_color=NC):
    """
    parse the fuzz output and return the parsed data as json
    """
    output_path = os.path.join(TARGET_APK_PATH, app, "fuzzing_output", fname)
    fuzz_stats = {}
    fuzz_out_path = os.path.join(output_path, fuzz_out_folder)
    if not os.path.exists(fuzz_out_path):
        logging.error(f'[{device_id}] {fuzz_out_path} does not exist, failed pulling data')
        return {}
    for core_output in os.listdir(fuzz_out_path):
        try:
            core_stats = {'fuzzer_instance' : core_output}
            # number execs per core
            if not os.path.exists(os.path.join(fuzz_out_path, core_output, "fuzzer_stats")):
                continue
            f = open(os.path.join(fuzz_out_path, core_output, "fuzzer_stats"))
            lines = f.readlines()
            for l in lines:
                if l == "":
                    continue
                l = l[:-1]
                key_v = l.split(":")[0].replace(" ", "")
                value_v = ''.join(l.split(":")[1:])[1:]
                core_stats[key_v] = value_v
            fuzz_stats[core_output] = core_stats
        except Exception as e:
            print(f'[{device_id}] failed to parse out: {e}')
            logging.error(f'[{device_id}] faile dto parse out {str(e)}')
            # maybe some borked fuzzing output, just continue
            continue
    return fuzz_stats


def wait_for_device(device, print_color=NC):
    while True:
        devices = adb.get_device_ids()
        if device not in devices:
            logging.info(f'[{device}] waiting for device to restart')
            print(f'{RED}[ERROR]{NC} {print_color}{device} is not booted, please boot it{NC} {RED}[!]{NC}')
            time.sleep(30)
            continue
        status = adb.check_device(device, check_space=True)
        if status != "OK":
            logging.info(f'[{device}] not funcitonal')
            print(f'{RED}[ERROR]{NC} {print_color}{device} is not functional {status}, please fix it{NC} {RED}[!]{NC}')
            time.sleep(30)
        else:
            return
