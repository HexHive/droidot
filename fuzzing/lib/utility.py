import os
import subprocess
from colorist import ColorRGB
import math
import time
import zipfile
import tempfile

from defs import *

RED='\033[0;31m'                                                   
YELLOW='\033[0;33m'                                                                                                                          
GREEN='\033[0;32m'                                                                                                                           
NC='\033[0m'                                                                                                                                 
BLUE='\033[0;34m'         # Blue                                      
PURPLE='\033[0;35m'       # Purple                                                                                                           
CYAN='\033[0;36m'         # Cyan 

DL_TRIES = 10

def get_library_offset4function(app, function):
    with open(os.path.join(TARGET_APK_PATH, app, "signatures_libraries_offsets.txt"), "r") as f:
        functions = f.readlines()
    library = ""
    offset = ""
    function = function.split("@")[0]
    for fn in functions:
        data = fn.split(" ")
        if data[0] == function:
            library = data[2]
            offset = data[3].strip("\n")
    return library, offset

def shell_escape(s):
    return s.replace('$', '\\$')


def thread_num2rgb(val, max_val):
    i = (val * 255 / max_val)
    r = round(math.sin(0.024 * i + 0) * 127 + 128)
    g = round(math.sin(0.024 * i + 2) * 127 + 128)
    b = round(math.sin(0.024 * i + 4) * 127 + 128)
    return (r,g,b)


def get_worker_color(worker_nr, nr_devices):
    r,g,b = thread_num2rgb(worker_nr, nr_devices)
    return ColorRGB(r,b,g)


def package_for_triage(app, fname, target_APK):
    temp_dir = tempfile.mkdtemp()
    out_name = f'{app}-{fname}-triage.tar.gz'
    out_path = os.path.join(temp_dir, out_name)
    subprocess.check_output(f'cd {target_APK} && tar -czvf {out_path} {app}/base.apk {app}/lib {app}/harnesses/{fname} {app}/fuzzing_output/{fname} {app}/signatures_libraries_offsets.txt {app}/signatures_pattern.txt', shell=True)
    return out_path


def sort_fuzz_list(fuzz_list):
    out = []
    app2harnessnum = {}
    for app in fuzz_list:
        app2harnessnum[app] = len(fuzz_list[app])
    sorted_dict = sorted(app2harnessnum.items(), key=lambda item: item[1])
    sorted_dict.reverse()
    for app, _ in sorted_dict:
        out.append((app, fuzz_list[app]))
    return out


def batch_fuzz_list(fuzz_list):
    out = []
    for app in fuzz_list:
        harnesses = fuzz_list[app]
        chunk_size = 2
        while harnesses:
            chunk, harnesses = harnesses[:chunk_size], harnesses[chunk_size:]
            out.append((app, chunk))
    print(out)
    return out


def check_required_files(app, harness, target_APK):
    harness_path = os.path.join(target_APK, app, "harnesses", harness)
    if not os.path.exists(harness_path):
        return False
    if not os.path.exists(os.path.join(harness_path, "harness.cpp")):
        return False
    if not os.path.exists(os.path.join(harness_path, "info.json")):
        return False
    if not os.path.exists(os.path.join(harness_path, "afl.js")):
        return False
    if not os.path.exists(os.path.join(target_APK, app, "base.apk")):
        return False
    if not os.path.exists(os.path.join(target_APK, app, "signatures_libraries_offsets.txt")):
        return False
    library, _ = get_library_offset4function(app, harness)
    if not os.path.exists(os.path.join(target_APK, app, "lib", "arm64-v8a", library)):
        return False
    return True
