import datetime,sqlite3, os, json
import sys

BASE = os.path.dirname(__file__)

sys.path.append(os.path.join(BASE, "../fuzzing/lib"))

from utility import get_library_offset4function

"""
Look through cs-io arg2-cs-io harnesses and get the unuique function namesf
"""

if "APKS" not in os.environ:
    print("specify APKS!")
    exit(-1)


apk_list = open(os.environ["APKS"]).read().split("\n")

TARGET_APK_PATH = os.path.join(BASE, "..", "target_APK")

def get_fnames(cs):
    unique_fs = list(set(k["name"] for k in cs))
    return unique_fs


app2fnames = {}
app2fnames2libraries = {}
for app in apk_list:
    if app == '':
        continue
    hp = os.path.join(TARGET_APK_PATH, app, "harnesses")
    if not os.path.exists(hp):
        print(f'NO HARNESS PATH {hp}')
        continue
    for harness in os.listdir(hp):
        if "cs-io" not in harness:
            continue
        harness_path = os.path.join(hp, harness)
        if not os.path.exists(harness_path):
            print(f'CS HARNESS PATH NOT PRESENT')
            continue
        info_json = json.load(open(os.path.join(harness_path, "info.json")))
        #print(info_json)
        app_cs = info_json["callsequence"]
        if app not in app2fnames:
            app2fnames[app] = []
        
        unique_fs = get_fnames(app_cs)
        for f in unique_fs:
            if f not in app2fnames[app]:
                app2fnames[app].append(f) 

for app in apk_list:
    if app == '':
        continue
    hp = os.path.join(TARGET_APK_PATH, app, "harnesses")
    if not os.path.exists(hp):
        print(f'NO HARNESS PATH {hp}')
        continue
    if app not in app2fnames2libraries:
        app2fnames2libraries[app] = {}

    for harness in os.listdir(hp):
        if harness.endswith(".json"):
            continue
        fname = harness.split("@")[0]
        app2fnames2libraries[app][fname] = {"library": get_library_offset4function(app, fname)[0]}

if "FUZZ_DATA" in os.environ:
    path = os.environ["FUZZ_DATA"]
else:
    path = BASE
open(os.path.join(path, "app2fnames.json"), "w+").write(json.dumps(app2fnames))
open(os.path.join(path, "app_fnames_libraries.json"), "w+").write(json.dumps(app2fnames2libraries))

