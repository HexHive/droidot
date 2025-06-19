import subprocess
import sys
import sqlite3
import json
import logging
import os
import shutil
import threading
import time
import shutil
from queue import Queue
import warnings
import subprocess, re

BASE = os.path.dirname(__file__)

sys.path.append(os.path.join(BASE, "fuzzing", "lib"))
import adb
from utility import get_worker_color, CYAN, RED, GREEN, NC
import tempfile
import emulator.emulator

"""
Does coverage map extraction in parallel
"""

TARGET_APK_PATH = os.path.join(BASE, "..", "./target_APK")


def showmap(apk, harness, output_folder, device_id, print_color=NC):
    print(f'{print_color}[{device_id.decode()}] python3 {BASE}/fuzzing/showmap.py {apk} {harness} {output_folder} {device_id.decode()}{NC}')
    try:
        subprocess.check_output(f"python3 {BASE}/fuzzing/showmap.py '{apk}' '{harness}' '{output_folder}' {device_id.decode()}", shell=True)
    except Exception as e:
        print(f'{print_color}[{device_id}] something went wrong...{e} {NC}')
        logging.error(f'[{device_id}] error running command {e}, {str(e)} ')


def showmap_worker(thread_nr, device_id):
    print_color = get_worker_color(thread_nr, len(devices))
    first = True
    while True:
        if apk_queue.empty():
            print(f'{print_color}[{device_id.decode()}] queue empty, exiting!{NC}')
            return
        apk, harness, output_dirs = apk_queue.get() # harnesses : {harness_name: [list of output folders]}
        if len(output_dirs) == 0:
            print(f"{print_color}[{device_id.decode()}] no harnesses for {apk} continuing{NC}")
            continue
        for output in output_dirs[:1]:
            showmap(apk, harness, output, device_id, print_color=print_color)
        print(f"{print_color}[{device_id.decode()}] done{NC}")


if len(sys.argv) != 2: 
    print("Please provide an argument")
    exit(1)
input_data = json.load(open(sys.argv[1])) # format {apk : {harness1: [outpufolders], harness2: ...}, apk2: ...}


print(f"{CYAN}[STATIC]{NC} Setting up emulators...")
# nr_emulators = config["orchestrate"]["emulators"]

if "NREMULATORS" in os.environ:
    nr_emulators = int(os.environ["NREMULATORS"])
else:
    nr_emulators = 8

devices = adb.get_device_ids()
print(f"{CYAN}[STATIC]{NC} {len(devices)} emulators already running, so starting {nr_emulators - len(devices)} new ones...")
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
        print(f'{RED}[STATIC]{NC} {d} has issues: {out}')
    adb.execute_privileged_command("cd /sys/devices/system/cpu && echo performance | tee cpu*/cpufreq/scaling_governor", device_id=d)
    adb.execute_privileged_command("rm -rf /data/local/tmp/perf", device_id=d)
print(f'{GREEN}[STATIC]{NC} devices: {b",".join(devices).decode()} are up')

apk_queue = Queue()
threads = []
for i,d in enumerate(devices):
    t = threading.Thread(target=showmap_worker, args=[i,d])
    threads.append(t)

for apk in input_data:
    for harness in input_data[apk]:
        apk_queue.put((apk, harness, input_data[apk][harness]))

for t in threads:
    t.start()
    time.sleep(30)

for t in threads:
    t.join()
