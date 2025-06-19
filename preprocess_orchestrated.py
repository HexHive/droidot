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

sys.path.append(os.path.join(BASE))
sys.path.append(os.path.join(BASE, 'harness'))
sys.path.append(os.path.join(BASE, 'harness/lib'))
sys.path.append(os.path.join(BASE, 'fuzzing/lib'))

warnings.filterwarnings("ignore")


import adb
from utility import get_worker_color, CYAN, RED, GREEN, NC
import emulator.emulator

"""
!!!ONLY RUN THIS ON A SETUP AWS MACHINE!!!
Does offset extraction in parallel
"""

TARGET_APK_PATH = os.path.join(BASE, "./target_APK")


def preprocess(apk, device_id, first=False, print_color=NC):
    print(f"{print_color}[{device_id.decode()}] processing {apk}{NC}")
    if first:
        init = "--init"
    else: 
        init = ""
    clean = "CLEAN" in os.environ
    if not os.path.exists(os.path.join(TARGET_APK_PATH, apk, "base.apk")):
        print(f"{print_color}NO APK for app {apk} ignoring!{NC}")
        return
    if clean:
        os.system(f'rm {os.path.join(TARGET_APK_PATH, apk, "signatures_pattern.txt")}')
        os.system(f'rm {os.path.join(TARGET_APK_PATH, apk, "signatures_libraries_offsets.txt")}')
        os.system(f'rm {os.path.join(TARGET_APK_PATH, apk, "static_analysis", "simple_argument_constraints.txt")}')
    if not os.path.exists(os.path.join(TARGET_APK_PATH, apk, "signatures_pattern.txt")):
        print(f'{print_color}extracting native sigs {apk} (signature extraction){NC}')
        subprocess.check_output(f'python3 static_analysis/preprocess.py {init} --target {apk} --signatures --device {device_id.decode()}', shell=True)
    if not os.path.exists(os.path.join(TARGET_APK_PATH, apk, "signatures_libraries_offsets.txt")):
        print(f"{print_color}Preprocessing {apk} (offset extraction){NC}")
        subprocess.check_output(f"python3 static_analysis/preprocess.py {init} --target {apk} --libraries --device {device_id.decode()}", shell=True)
    if not os.path.exists(os.path.join(TARGET_APK_PATH, apk, "static_analysis", "simple_argument_constraints.txt")):
        print(f"{print_color}Preprocessing {apk} (simple flowdroid){NC}")
        subprocess.check_output(f"python3 static_analysis/preprocess.py {init} --target {apk} -f --device {device_id.decode()}", shell=True)

def preproc_worker(thread_nr, device_id):
    print_color = get_worker_color(thread_nr, len(devices))
    first = True
    while True:
        if apk_queue.empty():
            print(f'{print_color}[{device_id.decode()}] queue empty, exiting!{NC}')
            return
        apk = apk_queue.get()
        preprocess(apk, device_id, first=first, print_color=print_color)
        first = False
        print(f"{print_color}[{device_id.decode()}] done{NC}")


if "APKS" not in os.environ:
    print("specify APKS env variable and point to file with apks")
    exit(1)

apk_list = open(os.environ["APKS"]).read().split("\n")

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
        print(f'{RED}[STATIC]{NC} {d.decode()} has issues: {out}')
    adb.execute_privileged_command("cd /sys/devices/system/cpu && echo performance | tee cpu*/cpufreq/scaling_governor", device_id=d)
    adb.execute_privileged_command("rm -rf /data/local/tmp/perf", device_id=d)
print(f'{GREEN}[STATIC]{NC} devices: {b",".join(devices).decode()} are up')

apk_queue = Queue()
threads = []
for i,d in enumerate(devices):
    t = threading.Thread(target=preproc_worker, args=[i,d])
    threads.append(t)

for apk in apk_list:
    if apk == '':
        continue
    apk_queue.put(apk)

for t in threads:
    t.start()

for t in threads:
    t.join()
