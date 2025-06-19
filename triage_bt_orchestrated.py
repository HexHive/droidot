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

sys.path.append(os.paht.join(BASE, "fuzzing", "lib")
import adb
from fuzzing.lib.utility import get_worker_color, CYAN, RED, GREEN, NC, package_for_triage

import emulator.emulator

"""
Does crash reproduction and backtrace grouping in parallel
"""

TARGET_APK_PATH = os.path.join(BASE, "target_APK")


def rerun_and_group(apk, harness, device_id, print_color=None):
    os.system(f'python3 {BASE}fuzzing/triage.py --target {apk} --target_function {harness} --device {device_id.decode()} -c -r')


def triage_worker(thread_nr, device_id):
    print_color = get_worker_color(thread_nr, len(devices))
    while True:
        if triage_queue.empty():
            print(f'{print_color}[{device_id.decode()}] queue empty, exiting!{NC}')
            return
        apk, harnesses = triage_queue.get()
        if len(harnesses) == 0:
            print(f"{print_color}[{device_id.decode()}] no harnesses for {apk} continuing{NC}")
            continue
        for harness in harnesses:
            if not os.path.exists(os.path.join(TARGET_APK_PATH, apk, "fuzzing_output", harness)):
                print(f"{print_color}[{device_id.decode()}] no fuzzing output for {apk} {harness}, skipping {NC}")
                continue
            if os.path.exists(os.path.join(TARGET_APK_PATH, apk, "fuzzing_output", harness, "reproduced_crashes")):
                print(f"{print_color}[{device_id.decode()}] reproduced crashes already present, skipping {NC}")
                continue
            print(f"{print_color}[{device_id.decode()}] rerunning crashes {NC}")
            rerun_and_group(apk, harness, device_id, print_color=print_color)
            adb.execute_privileged_command(f'rm -rf /data/local/tmp/triage/*', device_id=device_id)
        shutil.rmtree(os.path.join(TARGET_APK_PATH, apk))
        print(f"{print_color}[{device_id.decode()}] done{NC}")


from collections import defaultdict
triage_list = defaultdict(list)

if "FUZZ_DATA" not in os.environ:
    print("specif yFUZZ_DATA!")
    exit(-1)
    
fuzz_dir = os.environ["FUZZ_DATA"]


db = sqlite3.connect(os.path.join(fuzz_dir, "fuzz.db"))
db_cursor = db.cursor()
data = db_cursor.execute("select app,fname from fuzzresults where run_time > 200 and saved_crashes > 0;").fetchall()
fuzzable = db_cursor.execute("select app,fname from fuzzdata where fuzzable == 'yes';").fetchall()

print(fuzzable)
app2fuzzable = defaultdict(list)
for d in fuzzable:
    app2fuzzable[d[0]].append(d[1])

for d in data:
    app = d[0]
    harness = d[1]
    if app in app2fuzzable and harness in app2fuzzable[app]:
        triage_list[app].append(harness)
    print(f'[*.*] added {len(triage_list[app])} harnesses for {app}')

print(f"{CYAN}[STATIC]{NC} Setting up emulators...")
# nr_emulators = config["orchestrate"]["emulators"]
if "NREMULATORS" in os.environ:
    nr_emulators = os.environ["NREMULATORS"]
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
    adb.execute_privileged_command("rm -rf /data/local/tmp/*", device_id=d) #make space for memory dumping
print(f'{GREEN}[STATIC]{NC} devices: {b",".join(devices).decode()} are up')

triage_queue = Queue()
threads = []
for i,d in enumerate(devices):
    t = threading.Thread(target=triage_worker, args=[i,d])
    threads.append(t)

for apk, harnesses in triage_list.items():
    triage_queue.put((apk,harnesses))

for t in threads:
    t.start()
    time.sleep(20)

for t in threads:
    t.join()
