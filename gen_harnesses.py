import os
import sys
import subprocess

BASE = os.path.dirname(__file__)

if "HARNESS_GEN_FLAGS" not in os.environ:
    print("HARNESS_GEN_FLAGS not set!");
    exit(-1)

HARNESS_GEN_FLAGS = os.environ["HARNESS_GEN_FLAGS"]

if "APKS" not in os.environ:
    print("specify APKS")
    exit(-11)

apks = open(os.environ["APKS"]).read().split("\n")

for apk in apks:
    if apk == '':
        continue
    subprocess.check_output(f'python3 harness/harness_generator.py {HARNESS_GEN_FLAGS} --target {apk}', shell=True)

