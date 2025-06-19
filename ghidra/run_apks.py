import os
import sys
import signal
import subprocess
import logging

logging.basicConfig(filename='ghidra.log', encoding='utf-8', level=logging.ERROR, format='%(asctime)s %(message)s')


if len(sys.argv) == 1:
    print("give me path to target_APK")
    exit(0)

target_APK = sys.argv[1]

for app in os.listdir(target_APK):
    libdir = os.path.join(target_APK, app, "lib", "arm64-v8a")
    if not os.path.exists(libdir):
        continue
    for lib in os.listdir(os.path.join(target_APK, app, "lib", "arm64-v8a")):
        libpath = os.path.join(target_APK, app, "lib", "arm64-v8a", lib)
        apppath = os.path.join(target_APK, app)
        try:
            code = subprocess.run(f'./run.sh {libpath} {apppath} output5', shell=True, timeout=60*5)
            logging.info(f'finished analyzeng {app} {lib}')
        except subprocess.TimeoutExpired:
            logging.info(f'timed out for {app} {lib}')
        
