import os, json
import sqlite3
import numpy as np
import matplotlib.pyplot as plt
from showmap_helper import *
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict
from matplotlib.ticker import MaxNLocator

BASE = os.path.dirname(__file__)

TARGET_APK_PATH = os.path.join(BASE, "..", "target_APK")

# change to this directory

if "FUZZ_DATA" not in os.environ:
    print("FUZZ_DATA not in env!")
    exit(-1)

fuzz_dir = os.environ["FUZZ_DATA"]

def get_library_showmap_data(app2harness):
    lib2cov = {}
    fname2library = json.load(open(os.path.join(fuzz_dir, "apps_fnames_libraries.json")))
    print(app2harness)
    for app, harnesses in app2harness.items():
        tmp_lib2h = {}
        for harness in harnesses: 
            library = fname2library[app][harness.split("@")[0]]["library"]
            if library not in tmp_lib2h:
                tmp_lib2h[library] = []
            else:
                tmp_lib2h[library].append(harness)
        for library in tmp_lib2h:
            lib2cov[library] = merge_coverage_harnesses(app, tmp_lib2h[library])
    return lib2cov


def fname_in_harnesses(fname, harnesses):
    for harness in harnesses:
        if harness.split("@")[0] == fname:
            return harness
    return None


def get_partial_cses(app, harness):
    info = os.path.join(TARGET_APK_PATH, app, "harnesses", harness, "info.json")
    if not os.path.exists(info):
        print(info, "doesn't exist")
        exit(-1)
    cs = json.load(open(info))["callsequence"]
    partial = set()
    l = len(cs)
    for i in range(2,l):
        partial.add(tuple(k["name"] for k in cs[:i]))
    return list(partial), cs[0]["name"]

def do_plot(data, filename, annotation):
    # Example input: list of (x, y) tuples
    plt.gca().xaxis.set_major_locator(MaxNLocator(integer=True))
    data = [(i,d) for i,d in enumerate(data)]
    # Convert to numpy arrays
    x, y = zip(*data)
    x = np.array(x)
    y = np.array(y)
    print(x,y)

    # Plot the curve
    plt.plot(x, y, color='blue', linewidth=2)

    # Fill positive area (green)
    plt.fill_between(x, y, 0, where=(y >= 0), interpolate=True, color='green', alpha=0.5)

    # Fill negative area (red)
    plt.fill_between(x, y, 0, where=(y < 0), interpolate=True, color='red', alpha=0.5)

    # Axis line
    plt.axhline(0, color='gray', linewidth=1, linestyle='--')

    plt.xlabel("libraries")
    plt.ylabel("coverage difference")
    plt.title(annotation)
    plt.legend()
    plt.grid(False)
    plt.savefig(os.path.join(fuzz_dir, f"{filename}.pdf"))
    plt.clf()


def showmap():
    # cursor_ag  = sqlite3.connect("fuzzing_data/fuzz_argval_24_7_old.db").cursor()
    # cursor_cs  = sqlite3.connect("fuzzing_data/fuzz_cs_23_7_wrong_cov.db").cursor()
    cursor  = sqlite3.connect(os.path.join(fuzz_dir, 'fuzz.db')).cursor()

    all_fnames  = cursor.execute("select fname from fuzzdata").fetchall()
    all_fnames  = set(map(lambda x: x[0].split("@")[0], all_fnames))
    #showmap_harnesses = cursor_cs.execute("select app, fname  from fuzzdata where fname LIKE '%@cs-io@%';").fetchall()

    rows_callseq         = cursor.execute("select app, fname from fuzzdata where fname LIKE '%@cs-io@%';").fetchall()
    rows_baseline        = cursor.execute("select app, fname from fuzzdata where fname LIKE '%@@%';").fetchall()
    rows_argval          = cursor.execute("select app, fname from fuzzdata where fname LIKE '%@arg@%';").fetchall()
    rows_everything      = cursor.execute("select app, fname from fuzzdata where fname like '%@arg-cs-io@%';").fetchall()

    cursor.close()

    print(len(rows_baseline), len(rows_argval), len(rows_callseq), len(rows_everything))

    #app2fnames = json.load(open("app2fnames.json"))
    fname2library = json.load(open(os.path.join(fuzz_dir, "app_fnames_libraries.json")))

    app2h_cs, app2h_bs, app2h_av, app2h_al = defaultdict(list), defaultdict(list), defaultdict(list), defaultdict(list)
    for d in rows_callseq:
        app2h_cs[d[0]].append(d[1])
                    
    for d in rows_baseline:
        app2h_bs[d[0]].append(d[1])
                    
    for d in rows_argval:
        app2h_av[d[0]].append(d[1])

    for d in rows_everything:
        app2h_al[d[0]].append(d[1])
                    
    print("len bs", sum(len(app2h_bs[k]) for k in app2h_bs))

    for app, harnesses in app2h_al.items():
        assert(len(harnesses) == len(set(harnesses)))
    for app, harnesses in app2h_av.items():
        assert(len(harnesses) == len(set(harnesses)))
    for app, harnesses in app2h_bs.items():
        assert(len(harnesses) == len(set(harnesses)))
    for app, harnesses in app2h_cs.items():
        assert(len(harnesses) == len(set(harnesses)))

    tmp_lib2h_bs = defaultdict(list)
    applibs_bs = set()
    for app, harnesses in app2h_bs.items():
            for harness in harnesses: 
                library = fname2library[app][harness.split("@")[0]]["library"]
                applib = f'{app}-{library}'
                applibs_bs.add(applib)
                tmp_lib2h_bs[applib].append(harness)
    # merge
    lib2cov_bs = {}
    for applib in tmp_lib2h_bs:
        cov_bs = merge_coverage_harnesses(applib.split("-")[0], tmp_lib2h_bs[applib])
        lib2cov_bs[applib] = cov_bs
    print(len(lib2cov_bs))

    for applib, harnesses in tmp_lib2h_bs.items():
        assert(len(harnesses) == len(set(harnesses)))

    tmp_lib2h_cs = defaultdict(list)
    applibs_cs = set()
    for app, harnesses in app2h_cs.items():
        for harness in harnesses: 
            library = fname2library[app][harness.split("@")[0]]["library"]
            applib = f'{app}-{library}'
            applibs_cs.add(applib)
            _, first_function = get_partial_cses(app, harness)
            if not fname_in_harnesses(harness.split("@")[0], tmp_lib2h_cs[applib]):
                tmp_lib2h_cs[applib].append(harness)
            h2 = fname_in_harnesses(first_function, app2h_bs[app])
            if h2:
                if h2 not in tmp_lib2h_cs[applib]:
                    tmp_lib2h_cs[applib].append(h2) # we have the first function in argval
            else:
                print(app, first_function, harness, "not in baseline")
    # fill up if missing
    for applib, harnesses in tmp_lib2h_bs.items():
        if applib not in tmp_lib2h_cs:
            tmp_lib2h_cs[applib] = harnesses
    # merge
    lib2cov_cs = {}
    for applib in tmp_lib2h_cs:
        cov_cs = merge_coverage_harnesses(applib.split("-")[0], tmp_lib2h_cs[applib])
        lib2cov_cs[applib] = cov_cs
    print(len(lib2cov_cs))

    for applib, harnesses in tmp_lib2h_cs.items():
        assert(len(harnesses) == len(set(harnesses)))

    applibs_av = set()
    tmp_lib2h_av = defaultdict(list)
    for app, harnesses in app2h_av.items():
        for harness in harnesses: 
            library = fname2library[app][harness.split("@")[0]]["library"]
            applib = f'{app}-{library}'
            applibs_av.add(applib)
            if not fname_in_harnesses(harness.split("@")[0], tmp_lib2h_av[applib]):
                tmp_lib2h_av[applib].append(harness)
    # fill up if missing
    for applib, harnesses in tmp_lib2h_bs.items():
        if applib not in tmp_lib2h_av:
            tmp_lib2h_av[applib] = harnesses
            continue
        else:
            for harness in harnesses:
                if not fname_in_harnesses(harness.split("@")[0], tmp_lib2h_av[applib]):
                    tmp_lib2h_av[applib].append(harness) # fill up argv with nothing
    # merge
    lib2cov_av = {}
    for applib in tmp_lib2h_av:
        cov_av = merge_coverage_harnesses(applib.split("-")[0], tmp_lib2h_av[applib])
        lib2cov_av[applib] = cov_av
    print(len(lib2cov_av))

    for applib, harnesses in tmp_lib2h_av.items():
        assert(len(harnesses) == len(set(harnesses)))

    """
    aggregation to make comparison fair
    f1, f2, f3 -> f3@arg2-cs-io@ ok
    f2@arg2-cs-io@ does not exists => use f2@cs-io@
    f1@arg2@ ok use this, otherwise use f1@@
    """
    applibs_al = set()
    tmp_lib2h_al = defaultdict(list)
    for app, harnesses in app2h_al.items():
        for harness in harnesses: 
            library = fname2library[app][harness.split("@")[0]]["library"]
            applib = f'{app}-{library}'
            applibs_al.add(applib)
            if not fname_in_harnesses(harness.split("@")[0], tmp_lib2h_al[applib]):
                tmp_lib2h_al[applib].append(harness)
            partial_cses, first_function = get_partial_cses(app, harness)
            for partial in partial_cses: # iterate over partial cses with lenght >= 2
                if not fname_in_harnesses(partial[-1], app2h_al[app]):
                    # all run does not have a harness for this, let's take it from callsequnces
                    h = fname_in_harnesses(partial[-1], app2h_cs[app])
                    if h:
                        if h not in tmp_lib2h_al[applib]:
                            tmp_lib2h_al[applib].append(h) # we do have it so let's add it
                    else:
                        print(app, partial, harness)
                        #exit(-1)
                        pass # we don't have a harness for this partial callsequnce in either everything or cs, should not be the case
            h2 = fname_in_harnesses(first_function, app2h_av[app])
            if h2:
                if h2 not in tmp_lib2h_al[applib]:
                    tmp_lib2h_al[applib].append(h2) # we have the first function in argval
            else:
                h2 = fname_in_harnesses(first_function, app2h_bs[app])
                if h2:
                    if h2 not in tmp_lib2h_al[applib]:
                        tmp_lib2h_al[applib].append(h2) # add first function from baseline
                else:
                    print(app, first_function, harness, "not in baseline")
    
    # fill up if missing
    for applib, harnesses in tmp_lib2h_cs.items():
        if applib not in tmp_lib2h_al:
            tmp_lib2h_al[applib] = harnesses
        else:
            for harness in harnesses:
                if not fname_in_harnesses(harness.split("@")[0], tmp_lib2h_al[applib]):
                    tmp_lib2h_al[applib].append(harness)
            
    for applib, harnesses in tmp_lib2h_av.items():
        if applib not in tmp_lib2h_al:
            tmp_lib2h_al[applib] = harnesses
    for applib, harnesses in tmp_lib2h_bs.items():
        if applib not in tmp_lib2h_al:
            tmp_lib2h_al[applib] = harnesses

    lib2cov_al= {}    
    for applib in tmp_lib2h_al:
        cov_al = merge_coverage_harnesses(applib.split("-")[0], tmp_lib2h_al[applib])
        lib2cov_al[applib] = cov_al

    for applib, harnesses in tmp_lib2h_al.items():
        assert(len(harnesses) == len(set(harnesses)))

    open(os.path.join(fuzz_dir,"lib2cov_cs.json"), "w+").write(json.dumps(lib2cov_cs))
    open(os.path.join(fuzz_dir, "lib2cov_bs.json"), "w+").write(json.dumps(lib2cov_bs))
    open(os.path.join(fuzz_dir, "lib2cov_av.json"), "w+").write(json.dumps(lib2cov_av))
    open(os.path.join(fuzz_dir, "lib2cov_al.json"), "w+").write(json.dumps(lib2cov_al))
    libs_zero_cov = []
    for l in lib2cov_bs:
        if len(lib2cov_cs[l]) == 0 and len(lib2cov_bs[l]) == 0 and len(lib2cov_av[l]) == 0 and len(lib2cov_al[l]) == 0:
            libs_zero_cov.append(l)

    data_callseq = list(len(lib2cov_cs[a]) for a in lib2cov_cs if a not in libs_zero_cov)
    data_baseline = list(len(lib2cov_bs[a]) for a in lib2cov_bs if a not in libs_zero_cov)
    data_argval = list(len(lib2cov_av[a]) for a in lib2cov_av if a not in libs_zero_cov)
    data_everything = list(len(lib2cov_al[a]) for a in lib2cov_al if a not in libs_zero_cov)


    new_data_everything = []
    new_data_callseq = []

    libs_pvalue = applibs_al.intersection(applibs_cs)
    for lib in libs_pvalue:
        new_data_everything += [lib2cov_al[lib]]
        new_data_callseq += [lib2cov_cs[lib]]

    print(sorted(new_data_everything))
    print(sorted(new_data_callseq))

    # get the harnesses to compare argval2 with baseline non-zero diff
    av_bs_harnesses = {}
    for l in lib2cov_av:
        if lib2cov_bs[l] == 0 and lib2cov_av[l] == 0:
            continue
        assert(len(tmp_lib2h_av[l]) == len(set(tmp_lib2h_av[l])))
        for h in tmp_lib2h_av[l]:
            if h not in tmp_lib2h_bs[l]:
                app = l.split("-")[0]
                if app not in av_bs_harnesses:
                    av_bs_harnesses[app] = []
                if (h,fname_in_harnesses(h.split("@")[0], tmp_lib2h_bs[l]), len(lib2cov_av[l]) - len(lib2cov_bs[l])) in av_bs_harnesses[app]:
                    print("WTF WHY ALREADY IN THERE: ", (h,fname_in_harnesses(h.split("@")[0], tmp_lib2h_bs[l]), len(lib2cov_av[l]) - len(lib2cov_bs[l])))
                if not os.path.exists(f"{TARGET_APK_PATH}/{app}/fuzzing_output/cov_maps/{h}_covmap"):
                    continue
                av_bs_harnesses[app].append((h,fname_in_harnesses(h.split("@")[0], tmp_lib2h_bs[l]), len(lib2cov_av[l]) - len(lib2cov_bs[l])))

    for app, item in av_bs_harnesses.items():
        assert(len(item) == len(set(item)))
    #print("harnesses diff av-bs", av_bs_harnesses)
    open("av_bs_harnesses.json", "w").write(json.dumps(av_bs_harnesses))

    diff_sum = 0
    out = []
    for app, data in av_bs_harnesses.items():
        for d in data:
            #print(d)
            h_av = d[0]
            h_bs = d[1]
            diff = d[2]
            info_av = os.path.join(TARGET_APK_PATH, app, "harnesses", h_av, "info.json")
            if not os.path.exists(info_av):
                print("WTF no info.json")
            info_av = json.load(open(info_av))
            args = info_av["callsequence"][0]["signature"]["args"]
            f_constr = []
            diff_sum += diff
            for arg in args:
                if "constraints" in arg:
                    #print(arg["constraints"])
                    ct = list(arg["constraints"].keys())[0]
                    #constraints.append((list(arg["constraints"].keys())[0], diff))
                    f_constr.append(ct)
            out.append((app, h_av, len(args), f_constr, diff))
            if diff > 10000:
                pass
                print(app, h_av, len(args), f_constr, diff)
            if diff < 0:
                print(app, h_av, len(args), f_constr, diff)
    #for o in out:
        #print(o, o[4] / diff_sum)
    #print(constraints)

    libs_zero_cov = []
    for l in lib2cov_bs:
        if len(lib2cov_cs[l]) == 0 and len(lib2cov_bs[l]) == 0 and len(lib2cov_av[l]) == 0 and len(lib2cov_al[l]) == 0:
            libs_zero_cov.append(l)

    sort_everything = {k: v for k, v in sorted(lib2cov_al.items(), key=lambda item: len(item[1]), reverse=True)}


    data_callseq = list(len(lib2cov_cs[a]) for a in sort_everything if a not in libs_zero_cov)
    data_baseline = list(len(lib2cov_bs[a]) for a in sort_everything if a not in libs_zero_cov)
    data_argval = list(len(lib2cov_av[a]) for a in sort_everything if a not in libs_zero_cov)
    data_everything = list(len(lib2cov_al[a]) for a in sort_everything if a not in libs_zero_cov)

    means = list(map(np.mean, [data_baseline, data_callseq, data_argval, data_everything]))

    diff_everything_callseq = list(data_everything[i]-data_callseq[i] for i,_ in enumerate(data_everything))
    diff_everything_callseq = list(k for k in diff_everything_callseq if k != 0)
    diff_everything_callseq = list(sorted(diff_everything_callseq, reverse=True))

    diff_everything_argval = list(data_everything[i]-data_argval[i] for i,_ in enumerate(data_everything))
    diff_everything_argval = list(k for k in diff_everything_argval if k != 0)
    diff_everything_argval = list(sorted(diff_everything_argval, reverse=True))

    diff_everything_baseline = list(data_everything[i]-data_baseline[i] for i,_ in enumerate(data_everything))
    diff_everything_baseline = list(k for k in diff_everything_baseline if k != 0)
    diff_everything_baseline = list(sorted(diff_everything_baseline, reverse=True))

    diff_callsequence_baseline = list(data_callseq[i]-data_baseline[i] for i,_ in enumerate(data_callseq))
    diff_callsequence_baseline = list(k for k in diff_callsequence_baseline if k != 0)
    diff_callsequence_baseline = list(sorted(diff_callsequence_baseline, reverse=True))

    diff_argval_baseline = list(data_argval[i]-data_baseline[i] for i,_ in enumerate(data_callseq))
    diff_argval_baseline = list(k for k in diff_argval_baseline if k != 0)
    diff_argval_baseline = list(sorted(diff_argval_baseline, reverse=True))


    do_plot(diff_argval_baseline, "argval_naive", "difference argument analysis vs naive")
    do_plot(diff_callsequence_baseline, "cs_naive", "difference call sequence vs naive")
    do_plot(diff_everything_baseline, "compl_naive", "difference complete vs naive")
    do_plot(diff_everything_argval, "copml_argval", "difference copmlete vs argument analysis")
    do_plot(diff_everything_callseq, "compl_cs", "difference complete vs call sequence")
    #get_tikz_data(diff_argval_baseline)
    #get_tikz_data(data_baseline)
    #get_tikz_data(diff_everything_callseq)
    #get_tikz_data(diff_everything_argval)
    #get_tikz_data(diff_everything_baseline)
    #get_tikz_data(diff_callsequence_baseline)
    #get_tikz_data(diff_callsequence_baseline)

    means = list(map(np.mean, [data_baseline, data_callseq, data_argval, data_everything]))

    print(f"Total libraries considered: {list(map(len, [data_baseline, data_callseq, data_argval, data_everything]))}")
    print(f"Total std: {list(map(np.std, [data_baseline, data_callseq, data_argval, data_everything]))}")
    print(f"Average coverage (means): {means}, first is better by {(means[1] / means[0] - 1.0)*100:.2f}%, second is better by {(means[2] / means[0] - 1.0)*100:.2f}%, third is better by {(means[3] / means[0] - 1.0)*100:.2f}%")
    print(f'all vs bs {(means[3] / means[1] - 1.0)*100:.2f}')
    print(f'all vs av {(means[3] / means[2] - 1.0)*100:.2f}')




def get_tikz_data(data):
    out = ""
    for i,d in enumerate(data):
        out += f'({i}, {d})'
    print(f'xmax={len(data)},')
    print(f'ymax={max(data)},')
    print(out)


if __name__ == "__main__":
    showmap()
    
