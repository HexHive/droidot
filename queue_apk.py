import subprocess
import sys
import sqlite3
import json
import os
import shutil
import fuzzing.lib.apk_db as apk_db

BASE = os.path.dirname(__file__)

TARGET_APK_PATH = os.path.join(BASE, "./target_APK")
if "HARNESS_GEN_FLAGS" in os.environ:
    HARNESS_GEN_FLAGS = os.environ["HARNESS_GEN_FLAGS"]
else:
    HARNESS_GEN_FLAGS = "-jo_ok -cs_ph -cs_io -cs_ph_min_len 0 -ct_argval -fuzz" #this is super important so I put it on top (no unmapping to avoid contention)

os.system(f'rm {BASE}/harness/cpp/libharness.so') # delete old version of the library so it gets updated
os.system(f'rm {BASE}/harness/cpp/libharness_debug.so')
os.system(f'mv {BASE}/fuzzing/fuzz.db db_backups/fuzz_backupped.db')
os.system(f'rm {BASE}/fuzz.db')
apk_db.init_db()
con = apk_db.open_db()

#FNAME_WHITELIST = None
FNAME_WHITELIST = None
UNIQUE_FNAMES = False

def is_already_fuzzed(harness):
    cur = con.cursor()
    update_query = "SELECT * FROM fuzzdata WHERE fname == ?"
    cur.execute(update_query, (harness, ))
    rows = cur.fetchall()
    cur.close()
    return len(rows) > 0

def add_apk(apk, fname_allowlist=None):
    print(f'adding apk: {apk}')
    cur = con.cursor()
    if not os.path.exists(os.path.join(TARGET_APK_PATH, apk, "base.apk")):
        print("NO APK for app ignoring!")
        print(os.path.join(TARGET_APK_PATH, apk, "base.apk"))
        cur.close()
        return
    if not os.path.exists(os.path.join(TARGET_APK_PATH, apk, "signatures_pattern.txt")):
        print(f'extracting native sigs {apk} (signature extraction)')
        subprocess.check_output(f'python3 static_analysis/preprocess.py --target {apk} --signatures', shell=True)
    if not os.path.exists(os.path.join(TARGET_APK_PATH, apk, "signatures_libraries_offsets.txt")):
        print(f"Preprocessing {apk} (offset extraction)")
        subprocess.check_output(f"python3 static_analysis/preprocess.py --target {apk} --libraries", shell=True)
    
    harnesses = os.path.join(TARGET_APK_PATH, apk, "harnesses")
    #when queuing we assume it's a new fuzzing run so we just generate new harnesses
    #os.system(f'python3 harness/harness_generator.py --target {apk} --cleanup')
    #subprocess.check_output(f"python3 harness/harness_generator.py --target {apk} {HARNESS_GEN_FLAGS}", shell=True)

    if not os.path.exists(os.path.join(TARGET_APK_PATH, apk, "static_analysis", f"CS_{apk}.json")) \
        or len(open(os.path.join(TARGET_APK_PATH, apk, "static_analysis", f"CS_{apk}.json"),"r").read())< 4:
        print("FIXME PHENOMENON NOT PRESENT")

    if not os.path.exists(os.path.join(TARGET_APK_PATH, apk, "static_analysis", "simple_argument_constraints.txt")):
        print("FIXME simple_argument_constraints.txt NOT PRESENT")

    if not os.path.exists(os.path.join(TARGET_APK_PATH, apk, "harnesses", "meta_harness2nrfuzzargs.json")):
        print("FIXME meta_harness2nrfuzzargs.json NOT PRESENT")

    print(f"Ready {apk}")
    harnesses = os.listdir(harnesses)
    if "APP2FNAME" in os.environ:
        app2fname = json.load(open(os.environ["APP2FNAME"]))
    else:
        app2fname = None

    for harness in harnesses:
        if harness.endswith(".json"):
            continue
        if not os.path.exists(os.path.join(TARGET_APK_PATH, apk, "harnesses", harness)):
            continue
        if "Java_hl_productor_fxlib_HLRenderThread" in harness:
            continue # no more crashing my emulators

        if app2fname is not None:
            if apk not in app2fname:
                continue 
            if harness.split("@")[0] not in app2fname[apk]:
                continue
        try:
            if UNIQUE_FNAMES and is_already_fuzzed(harness):
                print(f"Harness already in db, skipping: {harness}")
                continue
            update_query = "INSERT INTO fuzzdata (app, fname) VALUES (?, ?)"
            cur.execute(update_query, (apk, harness, ))
            con.commit()
        except sqlite3.IntegrityError:
            print("integrity error") # dont care
            continue

    cur.close()

    app_path = os.path.join(TARGET_APK_PATH, apk)

if __name__ == "__main__":
    if "APKS" not in os.environ:
        print("specify APKS")
        exit(1)
    
    apks = open(os.environ["APKS"]).read().split("\n")
    for apk in apks:
        if apk == '':
            continue
        add_apk(apk)
    # sorry
    subprocess.check_output(f'cp {BASE}/fuzz.db {BASE}/fuzzing/fuzz.db', shell=True)
