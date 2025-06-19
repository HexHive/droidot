import sys
import os
import json
import logging
import threading
import time
import shutil
import traceback
import warnings
from queue import Queue
import subprocess, re

BASE = os.path.dirname(__file__)

TARGET_APK_PATH = os.path.join(BASE, '..', 'target_APK')

sys.path.append(os.path.join(BASE, '..'))
sys.path.append(os.path.join(BASE, '../harness'))
sys.path.append(os.path.join(BASE, '../harness/lib'))
sys.path.append(os.path.join(BASE, '../fuzzing/lib'))

warnings.filterwarnings("ignore")


import emulator.emulator
import adb
import lib.interface as interface
import lib.apk_db as apk_db
from lib.utility import get_worker_color, CYAN, RED, GREEN, NC, package_for_triage, sort_fuzz_list, batch_fuzz_list, check_required_files, DL_TRIES

logging.basicConfig(filename='orchestrate.log', encoding='utf-8', level=logging.DEBUG, format='%(asctime)s %(levelname)s %(funcName)s %(message)s', force=True)

"""
more clean (pray) script to orchestrate for multiple apps and apks

Note that fname is usually the harness name

====config.json=====
fuzzable_test :             # for testing if a function is fuzzable, fuzz first for 
    enabled : true/false
    fuzzable_time_run_1: X[s]
    fuzzable_time_run_2: X[s]
    fuzzable_edge_diff: 5 
    cmplog : 0|1
fuzz : 
    fuzz_full : true/false     # run full fuzzing only for functions that are fuzzable
    parallel_instances: X               # how many instances on an emulator
    fuzz_time : X[s]                    # how long to fuzz fuzzable functions
    fuzz_db: "X"                        # path to sqlite db containing the apks/functions to 
    poll_time: X[s]                     # time between polling the instance 
    fuzz_only_fuzzable: true/false      # fuzz only functions that are fuzzable
    cmplog : 0|1

=====fuzz_list_path====
[{"apk": "", "functions": []}]  
"""


class DownloadFailed(Exception):
    pass

def clean():
    devices = adb.get_device_ids()
    for d in devices:
        interface.stop_fuzz(d)
        interface.clean_fuzz(d)
    
def kill():
    devices = adb.get_device_ids()
    for d in devices:
        emulator.emulator.stop_emulator(d.decode())


def test_fuzzable(db_cursor, app, fname, device_id, print_color=NC):
    """
    fuzz a function [fuzzable_time_run_1] if it didn't crash, 
    fuzz for [fuzzable_time_run_2]
    if there is an edge increase, mark the function as fuzzable
    return True if app:fname is fuzzable
    """
    cmplog = config["fuzzable_test"]["cmplog"]
    out_dir = interface.setup_fuzz(app, fname, device_id, print_color=print_color)
    running = interface.start_fuzz(app, fname, out_dir, device_id, cmplog=cmplog, check_started=True, print_color=print_color)
    if running < 1:
        print(f"{print_color}[{device_id.decode()}] {app}:{fname} crashed right away{NC}")
        logging.info(f"[{device_id.decode()}] {app}:{fname} crashed right away")
        interface.stop_fuzz(device_id, print_color=print_color) 
        return False, 0
    time.sleep(config["fuzzable_test"]["fuzzable_time_run_1"])
    interface.stop_fuzz(device_id, print_color=print_color)
    out_dir = interface.fetch_fuzz_one(app, fname, out_dir, device_id, print_color=print_color)
    run_1_result = interface.parse_out(app, fname, out_dir, device_id, print_color=print_color)
    if run_1_result == {}:
        print(f"{print_color}[{device_id.decode()}] {app}:{fname} no output on first run{NC}")
        logging.info(f"[{device_id.decode()}] {app}:{fname} no output on first run")
        running = interface.get_running_fuzzers(device_id=device_id, print_color=print_color)
        if running < 1:
            print(f"{print_color}[{device_id.decode()}] {app}:{fname} crashed after long startup{NC}")
            logging.info(f"[{device_id.decode()}] {app}:{fname} crashed after long startup")
            interface.stop_fuzz(device_id, print_color=print_color) 
            return False, 0
        else:
            print(f"{print_color}[{device_id.decode()}] {app}:{fname} waiting for longer startup{NC}")
            time.sleep(20)
            out_dir = interface.fetch_fuzz_one(app, fname, out_dir, device_id, print_color=print_color)
            run_1_result = interface.parse_out(app, fname, out_dir, device_id, print_color=print_color)
            if run_1_result == {}:
                print(f"{print_color}[{device_id.decode()}] {app}:{fname} ultra slow or fucked, running instances: {interface.get_running_fuzzers(device_id=device_id)} {NC}")
                interface.stop_fuzz(device_id, print_color=print_color) 
                return False,0
    apk_db.insert_fuzz_result(db_cursor, app, fname, run_1_result, lock)
    # fuck all you native libraries filling the disk
    interface.clean_harness_fuzz(app, fname, device_id)
    interface.wait_for_device(device_id, print_color=print_color) # make sure everyhting is ok
    out_dir_2 = interface.setup_fuzz(app, fname, device_id, print_color=print_color)
    running = interface.start_fuzz(app, fname, out_dir_2, device_id, cmplog=cmplog, check_started=True, print_color=print_color)
    if running < 1:
        print(f"{print_color}[{device_id.decode()}] {app}:{fname} crashed right away on second run{NC}")
        logging.info(f"[{device_id.decode()}] {app}:{fname} crashed right away on second run")
        interface.stop_fuzz(device_id, print_color=print_color) 
        return False, int(run_1_result['default']['saved_crashes'])
    time.sleep(config["fuzzable_test"]["fuzzable_time_run_2"])
    interface.stop_fuzz(device_id, print_color=print_color)
    out_dir_2 = interface.fetch_fuzz_one(app, fname, out_dir_2, device_id, print_color=print_color)
    run_2_result = interface.parse_out(app, fname, out_dir_2, device_id, print_color=print_color)
    apk_db.insert_fuzz_result(db_cursor, app, fname, run_2_result, lock)
    interface.clean_harness_fuzz(app, fname, device_id)
    if run_2_result == {}:
        return False, 0
    #TODO: compare the output
    if int(run_2_result['default']['edges_found']) - int(run_1_result['default']['edges_found']) > config['fuzzable_test']['fuzzable_edge_diff']:
        if int(run_1_result['default']['saved_crashes']) > 0 or int(run_2_result['default']['saved_crashes']) > 0:
            triage_path = package_for_triage(app, fname, TARGET_APK_PATH)
        return True, max(int(run_1_result['default']['saved_crashes']), int(run_2_result['default']['saved_crashes']))
    return False, max(int(run_1_result['default']['saved_crashes']), int(run_2_result['default']['saved_crashes']))


def fuzz_func(app, fname, device_id, print_color=NC):
    """
    fuzz a function for [fuzz_time] time
    """
    instances = config['fuzz']['parallel_instances']
    cmplog = config['fuzz']['cmplog']
    out_dir = interface.setup_fuzz(app, fname, device_id, print_color=print_color)
    running = interface.start_fuzz(app, fname, out_dir, device_id, parallel=instances, cmplog=cmplog,  check_started=True, print_color=print_color)
    if running == 0:
        print(f"{print_color}[{device_id.decode()}] {fname} crashed right away{NC}")
        logging.info(f"[{device_id.decode()}] {fname} crashed right away")
        interface.stop_fuzz(device_id, print_color=print_color) 
        return
    fuzz_time = config['fuzz']['fuzz_time']
    poll_time = config['fuzz']['poll_time']
    while fuzz_time > 0:
        time.sleep(poll_time)
        fuzz_time = fuzz_time - poll_time
        running = interface.get_running_fuzzers(device_id, print_color=print_color)
        if running == 0:
            print(f"{print_color}[{device_id.decode()}] {fname} {RED}fuzzing terminated prematurely{NC}")
            logging.info(f"[{device_id.decode()}] {fname} fuzzing terminated prematurely")
            out_dir = interface.fetch_fuzz_one(app, fname, out_dir, device_id, print_color=print_color)
            interface.stop_fuzz(device_id, print_color=print_color) 
            return
        print(f"{print_color}[{device_id.decode()}] {app} {fname} {GREEN}fuzzing with {running} instances {NC}")
        logging.info(f"[{device_id.decode()}] {app} {fname} {GREEN}fuzzing with {running} instances")
        out_dir = interface.fetch_fuzz_one(app, fname, out_dir, device_id, print_color=print_color)
    interface.stop_fuzz(device_id, print_color=print_color) 
    out_dir = interface.fetch_fuzz_one(app, fname, out_dir, device_id, print_color=print_color)
    out_data = interface.parse_out(app, fname, out_dir, device_id)
    apk_db.insert_fuzz_result(db_cursor, app, fname, out_data, lock)
    if any(int(out_data[k]['saved_crashes'])>0 for k in out_data):
        triage_path = package_for_triage(app, fname, TARGET_APK_PATH)
    interface.clean_harness_fuzz(app, fname, device_id)


def fuzz_worker(thread_nr, device_id):
    """
    in a infinite loop, consume apk_function dicts from the queue, check fuzzability and 
    """
    print_color = get_worker_color(thread_nr, len(devices))
    db_cursor = apk_db.open_db()
    while True:
        if apk_queue.empty():
            logging.info(f'[{device_id.decode()}] queue empty, exiting!')
            print(f'{print_color}[{device_id.decode()}] queue empty, exiting!{NC}')
            return
        apk_functions = apk_queue.get()
        to_fuzz = []
        app = apk_functions["apk"]
        try:
            interface.wait_for_device(device_id, print_color=print_color) # make sure everyhting is ok
            for harness in apk_functions["functions"]:
                try:
                    native_func = harness.harness
                    fuzzable = harness.fuzzable
                    all_present = check_required_files(app, native_func, target_APK=TARGET_APK_PATH)
                    if not all_present:
                        print(f'{print_color}[{device_id.decode()}] files missing for {app} {harness} {NC}')
                        logging.error(f'[{device_id.decode()}] files missing for {app} {harness}')
                        continue
                    if config["fuzzable_test"]["enabled"] and not fuzzable == 'unknown': # test for fuzzability and function wasn't yet tested
                        print(f'{print_color}[{device_id.decode()}] testing fuzzability of {app} {native_func}{NC}')
                        logging.info(f'[{device_id.decode()}] testing fuzzability of {app} {native_func}')
                        fuzzable, crashes = test_fuzzable(db_cursor, app, native_func, device_id, print_color=print_color)
                        if fuzzable:
                            logging.info(f'[{device_id.decode()}] FUZZABLE Function found: {app}:{native_func}')
                            print(f'{print_color}[{device_id.decode()}] FUZZABLE Function found: {app}:{native_func}{NC}')
                            apk_db.set_fuzzable(db_cursor, app, native_func, 'yes', crashes=crashes, lock=lock)
                        else:
                            apk_db.set_fuzzable(db_cursor, app, native_func, 'no', crashes=crashes, lock=lock)
                        interface.clean_harness_fuzz(app, native_func, device_id)
                    if config['fuzz']['fuzz_only_fuzzable']:
                        if fuzzable:
                            to_fuzz.append(harness)
                    else:
                        to_fuzz.append(harness)
                    interface.wait_for_device(device_id, print_color=print_color) # make sure everyhting is ok
                except Exception as e:
                    print(f'[{device_id.decode()}] ERROR in PROCESSING of {app}-{native_func}, {str(e)}, {traceback.format_exc()}')
                    logging.error(f'[{device_id.decode()}] ERROR in PROCESSING of {app}-{native_func}, {str(e)}, {traceback.format_exc()}')
                    interface.clean_harness_fuzz(app, native_func, device_id)
                    interface.wait_for_device(device_id, print_color=print_color) # make sure everyhting is ok
            if not config['fuzz']['fuzz_full']:
                print(f'{print_color}[{device_id.decode()}] done for {app}, cleaning device and local folders{NC}')
                logging.info(f'{print_color}[{device_id.decode()}] done for {app}, cleaning device and local folders{NC}')
                interface.clean_fuzz(device_id=device_id, print_color=print_color)
                continue
            for harness in to_fuzz:
                if harness.fuzzed == 'yes':
                    continue
                native_func = harness.harness
                print(f'{print_color}[{device_id.decode()}] fuzzing {app} {native_func}{NC}')
                fuzz_func(app, native_func, device_id, print_color=print_color)
                apk_db.set_fuzzed(db_cursor, app, native_func, lock)
                interface.wait_for_device(device_id) # make sure everyhting is ok
            print(f'{print_color}[{device_id.decode()}] completely finished fuzzing app {app}, locally deleting it!{NC}')
            interface.clean_fuzz(device_id=device_id, print_color=print_color)
        except Exception as e:
            print(f'[{device_id.decode()}] ERROR in PROCESSING of {app}, {str(e)}, {traceback.format_exc()}')
            logging.error(f'[{device_id.decode()}] ERROR in PROCESSING of {app}, {str(e)}, {traceback.format_exc()}')
            interface.clean_fuzz(device_id=device_id, print_color=print_color)
            continue    


lock = threading.Lock()

app2threadsinuse = {}

if len(sys.argv) == 2:
    cmd = sys.argv[1]
    if cmd == "clean":
        """
        stop all fuzzing and cleanup
        """
        clean()
        exit(0)
    if cmd == "kill":
        kill()
        exit(0)
    


if not os.path.exists(os.path.join(BASE, 'config.json')):
    print(f'{RED}[ORC]{NC} no config.json!, exiting')
    exit(-1)

config = json.load(open(os.path.join(BASE, 'config.json')))

print(f"{CYAN}[ORC]{NC} Setting up emulators...")
# nr_emulators = config["orchestrate"]["emulators"]

if "NREMULATORS" in os.environ:
    nr_emulators = int(os.environ["NREMULATORS"])
else:
    nr_emulators = config["nr_emulators"]
devices = adb.get_device_ids()
print(f"{CYAN}[ORC]{NC} {len(devices)} emulators already running, so starting {nr_emulators - len(devices)} new ones...")
for i in range(0, nr_emulators):
    emulator.emulator.start_emulator(f'emulator-{5554+i*2}')

time.sleep(4)
devices = adb.get_device_ids()
for d in devices:
    while True:
        out = adb.check_device(d, check_space=True)
        if out == "OK":
            break
        if out == "NOSPACE_DATA":
            adb.execute_privileged_command("rm -rf /data/local/tmp/*", device_id=d) #make space for memory dumping
        print(f'{RED}[ORC]{NC} {d} has issues: {out}')
        time.sleep(1)
    adb.execute_privileged_command("cd /sys/devices/system/cpu && echo performance | tee cpu*/cpufreq/scaling_governor", device_id=d)
    adb.execute_privileged_command("rm -rf /data/local/tmp/perf", device_id=d)
    interface.stop_fuzz(device_id=d)
    interface.clean_fuzz(device_id=d)

print(f'{GREEN}[ORC]{NC} devices: {b",".join(devices).decode()} are up')

# setup a queue of apks
db_cursor = apk_db.open_db()
fuzz_list = apk_db.get_fuzz_list(db_cursor) # apk: [(fname, fuzzed, fuzzable, crashes)] fuzzed = 0:no 1:yes, fuzzable = -1:not tested, 0:no, 1:yes

for app in fuzz_list:
    app2threadsinuse[app] = 0

fuzz_list_batched = batch_fuzz_list(fuzz_list) # sort the fuzz list such that the order in which items are returned from the queue are such that apps with the most harnesses are processed first

if not len(fuzz_list):
    print("Fuzz list empty!")
    exit(0)

print(f'{GREEN}[ORC]{NC} {len(fuzz_list)} items in the fuzz list!')

apk_queue = Queue()
threads = []
for i,d in enumerate(devices):
    t = threading.Thread(target=fuzz_worker, args=[i,d])
    threads.append(t)

for apk, fnames in fuzz_list_batched:
    apk_queue.put({"apk": apk, "functions": fnames})

for t in threads:
    t.start()
    time.sleep(15) # stagger the threads so in the beginning the rsyncs don't interfere

for t in threads:
    t.join()

