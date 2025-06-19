import datetime,sqlite3, os, json
import sys

BASE = os.path.dirname(__file__)
TARGET_APK_PATH = os.path.join(BASE, "..", "target_APK")

sys.path.append(os.path.join(BASE, "..", "harness", "lib"))
from utils import *

from collections import defaultdict
def get_partial_cses(cs):
    partial = set()
    unique_fs = []
    l = len(cs)
    for i in range(2,l):
        partial.add(tuple(k["name"] for k in cs[:i]))
    unique_fs = list(set(k["name"] for k in cs))
    return partial, unique_fs

if "FUZZ_DATA" in os.environ:
    fuzz_dir = os.environ["FUZZ_DATA"]
else:
    fuzz_dir = os.path.join(BASE, "fuzzing_data")

cursor = sqlite3.connect(os.path.join(fuzz_dir, 'fuzz.db')).cursor()

# a = cursor1.execute("select app, fname, saved_crashes from fuzzresults where fname LIKE '%@cs-io@%' and saved_crashes > 0;").fetchall()
# b = cursor2.execute("select app, fname, saved_crashes from fuzzresults where fname LIKE '%@cs-io@%' and saved_crashes > 0;").fetchall()

nt = cursor.execute("select app, fname  from fuzzdata where fname LIKE '%@@%';").fetchall()
ag = cursor.execute("select app, fname  from fuzzdata where fname LIKE '%@arg@%';").fetchall()
cs = cursor.execute("select app, fname  from fuzzdata where fname LIKE '%@cs-io@%';").fetchall()
al = cursor.execute("select app, fname  from fuzzdata where fname LIKE '%@arg-cs-io@%';").fetchall()

#fuzz_results_nothing = cursor_nothing.execute('select app,fname,run_time from fuzzresults where fname LIKE '%@@%' and run_time > 200')
cursor.close()

def get_fuzz_stats_runtime(fuzz_stats):
    if not os.path.exists(fuzz_stats):
        return {}
    f = open(fuzz_stats)
    lines = f.readlines()
    out = {}
    for l in lines:
        if l == "":
            continue
        l = l[:-1]
        key_v = l.split(":")[0].replace(" ", "")
        value_v = ''.join(l.split(":")[1:])[1:]
        out[key_v] = value_v
    if "run_time" not in out:
        return {}
    return out


def get_harnesses_like(app, fnames, identifier):
    harnesses = os.path.join(TARGET_APK_PATH, app, "harnesses")
    output = []
    for fname in fnames:
        found = False
        for harness in os.listdir(harnesses):
            if fname in harness and identifier in harness:
                output.append(harness)
                found = True
                break
        if not found:
            open("harness_not_found.txt", "a+").write(f'{app}-{fname}\n')
    return output


def get_output_folder(app, harnesses):
    ret = {}
    for harness in harnesses:
        fuzz_out = os.path.join(TARGET_APK_PATH, app, "fuzzing_output", harness)
        if not os.path.exists(fuzz_out):
            #ret[harness] = ["None"]
            continue
        output_folders = os.listdir(fuzz_out)
        chosen_out = ("", None, 0)
        for out in output_folders:
            stats = get_fuzz_stats_runtime(os.path.join(fuzz_out, out, 'default', 'fuzzer_stats'))
            if stats == {}:
                continue
            dt = datetime.datetime.strptime(out.split("_")[-1], "%H:%M-%d-%m-%Y")
            if chosen_out[0] == "":
                chosen_out = (out, dt, stats["run_time"])
            else:
                if dt > chosen_out[1]:
                    if int(stats["run_time"]) >= 180:
                        chosen_out = (out, dt, int(stats["run_time"]))
        if app == 'vidma.screenrecorder.videorecorder.videoeditor.pro':
            print(chosen_out, harness)
        ret[harness] = [chosen_out[0]]
    return ret

if "APP2FNAMES" not in os.environ:
    print("APP2FNAMES missing!")
    exit(-1)

app2fnames = json.load(open(os.environ["APP2FNAMES"]))

a2h_cs = defaultdict(list)
a2h_al = defaultdict(list)
a2h_nt = defaultdict(list)
a2h_ag = defaultdict(list)

for d in nt:
    if d[0] in app2fnames:
        if d[1].split("@")[0] in app2fnames[d[0]]:
            a2h_nt[d[0]].append(d[1])
for d in cs:
    if d[0] in app2fnames:
        if d[1].split("@")[0] in app2fnames[d[0]]:
            a2h_cs[d[0]].append(d[1])
for d in al:
    if d[0] in app2fnames:
        if d[1].split("@")[0] in app2fnames[d[0]]:
            a2h_al[d[0]].append(d[1])
for d in ag:
    if d[0] in app2fnames:
        if d[1].split("@")[0] in app2fnames[d[0]]:
            a2h_ag[d[0]].append(d[1]) 


# build the showmap json
out = {}
for app,harnesses in a2h_ag.items():
    if app not in out:
        out[app] = {}
    output_folders = get_output_folder(app, harnesses)
    out[app].update(output_folders)
for app,harnesses in a2h_cs.items():
    if app not in out:
        out[app] = {}
    output_folders = get_output_folder(app, harnesses)
    out[app].update(output_folders)
for app,harnesses in a2h_al.items():
    if app not in out:
        out[app] = {}
    output_folders = get_output_folder(app, harnesses)
    out[app].update(output_folders)

open(os.path.join(fuzz_dir, "showmap.json"),"w+").write(json.dumps(out))

