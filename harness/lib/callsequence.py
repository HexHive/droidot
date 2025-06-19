import logging
import os
import json
from define import *
from utils import parse_sig_lib_offsets, parse_callsequence_function_phenomenon, \
    get_classname, check_in_cs, get_sequence_upto_function, build_cs_list, choose_better_to_fuzz_function, check_in_cs_fname, check_supported_args, \
        parse_phenom_callsequence, build_cs_lc_list, parse_gaps_cs_callsequence


def generate_empty_callsequence(app):
    """
    generates an empty callsequence
    """
    sig_lib_offsets_path = os.path.join(TARGET_APK_PATH, app, "signatures_libraries_offsets.txt")
    if not os.path.exists(sig_lib_offsets_path):
        print("[!] no signatures_libraries_offsets.txt file for app: ", app)
        return {}
    with open(sig_lib_offsets_path, "r") as f:
        sig_libs_offsets = f.read()
    fInfos = parse_sig_lib_offsets(sig_libs_offsets)
    callsequence = {}
    for fname in fInfos:
        callsequence[fname] = [{"sequence": [], "data_dependencies": {}}]
    logging.info(f"simple callsequence {callsequence}")
    return callsequence


def in_cs(exisitng_cses, new_cs):
    logging.debug(f"check in CS:{new_cs} EXISTING: {exisitng_cses}")
    new_cs_list = list(k['fname'] for k in new_cs["sequence"])
    for cs in exisitng_cses:
        existing_cs_list = list(k['fname'] for k in cs["sequence"])
        if new_cs_list == existing_cs_list and cs["args"] == new_cs["args"]:
            return True
    return False


def generate_callsequence_phenomenon(app, callsequence_input, fInfos, min_length=1, max_length=5):
    """
    add phenomeonen callsequence to existing callsequence
    """
    cs_file = os.path.join(TARGET_APK_PATH, app, "static_analysis", f"CS_{app}.json")
    if not os.path.exists(cs_file):
        print("no phenom callsequence file, skipping")
        logging.info("no phenom callsequence file, skipping")
        if min_length != 0:
            print("exiting due to min lenght set")
            exit(0)
        return callsequence_input
    if len(open(cs_file, "r").read()) == 0:
        print("no phenom callsequence file, skipping")
        logging.info("no phenom callsequence file, skipping")
        if min_length != 0:
            print("exiting due to min lenght set")
            exit(0)
        return callsequence_input
    with open(cs_file, "r") as f:
        fname2phenomcs = parse_phenom_callsequence(f.read(), fInfos)
    callsequence_output = {}
    for fname in callsequence_input:
        if fname not in fname2phenomcs:
            if min_length == 0:
                callsequence_output[fname] = [{"sequence": [], "caller": None, "data_dependencies": {}}]
            continue
        callsequence_output[fname] = []
        for ph_cs in fname2phenomcs[fname]:
            # TODO: check if functions are in fInfos!!!
            if len(ph_cs["seq"]) >= min_length and len(ph_cs["seq"]) <= max_length:
                print("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWw")
                logging.debug(f"adding phenomonen CS to {fname}, {ph_cs}")
                if not in_cs(callsequence_output[fname], {"sequence": ph_cs["seq"], "caller": ph_cs["caller"], "data_dependencies": {}, "args": ph_cs["args"]}):
                    callsequence_output[fname].append({"sequence": ph_cs["seq"], "caller": ph_cs["caller"], "data_dependencies": {}, "args": ph_cs["args"]})
            if len(callsequence_output[fname]) > MAX_NR_PHENOM_CS: 
                break
        if len(callsequence_output[fname]) == 0 and min_length == 0:
            callsequence_output[fname] = [{"sequence": [], "caller": None, "data_dependencies": {}}]
    logging.info(f"callsequence after phenomenon processing: {callsequence_output}")
    return callsequence_output


def generate_cs_io_GAPS(app, callsequence_input, fInfos, only_if_in_phenom=True):
    """
    Use the 
    """
    cs_file = os.path.join(TARGET_APK_PATH, app, "static_analysis", f"{app}-instr.json")
    if not os.path.exists(cs_file):
        print(f"no {app}-instr.json callsequence file, skipping")
        logging.info(f"no {app}-instr.json callsequence file, skipping")
        return callsequence_input
    if len(open(cs_file, "r").read()) == 0:
        print("no phenom callsequence file, skipping")
        logging.info("no phenom callsequence file, skipping")
        return callsequence_input
    print("ok")
    with open(cs_file, "r") as f:
        fname2gapsdata = parse_gaps_cs_callsequence(json.load(f), fInfos)
    """
    "Java_com_example_hellolibs_NativeCall_csfn1": [
    {
      "parent": "Java_com_example_hellolibs_NativeCall_bullshit",
      "native_fname": "Java_com_example_hellolibs_NativeCall_csfn0",
      "param_ind": 0
    }
  ],
    """
    # LIMITATIONS: only adding this for the final function of the callsequence
    for fname in fname2gapsdata:
        if fname not in callsequence_input and only_if_in_phenom:
            # don't do anything because we're not using GAPs data if no phenomenon callsequence is present
            continue 
        for f_seq in callsequence_input[fname]:
            idx = check_in_cs_fname(fname2gapsdata[fname]["native_fname"], f_seq["sequence"])
            if idx != -1:
                # Phenomenon found the dependency, add data dependency
                f_seq["data_dependencies"][str(fname2gapsdata[fname]["param_ind"])] = {"findex": str(idx), "reason": "GAPS"}
                logging.debug(f'{fname} adding GAPS data dependency to phenom cs: {f_seq}')
                #print(f'{fname} adding GAPS data dependency to phenom cs: {f_seq}')
            else:
                # need to add this function to the phenom cs
                f_seq["sequence"].insert(0, {"fname": fname2gapsdata[fname]["native_fname"], "caller": fname2gapsdata[fname]["parent"], "reason": "GAPS"})
                idx = check_in_cs_fname(fname2gapsdata[fname]["native_fname"], f_seq["sequence"])
                if idx == -1:
                    continue
                #print("?", f_seq["data_dependencies"])
                f_seq["data_dependencies"][str(fname2gapsdata[fname]["param_ind"])] = {"findex": str(idx), "reason": "GAPS"}
                logging.debug(f'{fname} inserted into cs and adding GAPS data dependency to phenom cs: {f_seq}')
                #print(f'{fname} adding GAPS data dependency {fname2gapsdata[fname]["native_fname"]} to phenom cs: {f_seq}')
    open("debug.json", "w").write(json.dumps(callsequence_input))
    return callsequence_input


def generate_callsequence_data_heuristic(app, callsequence, fInfos):
    """
    Uses some heuristics to add functions to the callsequence
    """
    # we are looking for the function that gives us the data dependency
    for targetFn in callsequence:
        for cs_entry in callsequence[targetFn]:
            targetFnInfo = fInfos[targetFn]
            # build list of functions in the same class
            FnSameClass = []
            for fn in fInfos:
                f = fInfos[fn]
                if f.classname == targetFnInfo.classname:
                    FnSameClass.append(f)
                if f.classname == targetFnInfo.outer_classname:
                    FnSameClass.append(f)
            for i, arg in enumerate(targetFnInfo.args_list):
                # look through function arguments and find any that are not supported or long (pointer)
                if arg not in TYPE_MAPPING_ARGS or arg == "long":
                    #TODO: some inconsistency when using data heuristics
                    # argument is not supported look though callsequence if any function already returns that object
                    found_in_list = False
                    for fn in cs_entry["sequence"]:
                        if fInfos[fn["fname"]].ret_type == arg:
                            found_in_list = True
                            break
                    if found_in_list:
                        continue
                    # now we look though the FnSameClass list and try to find a function that matches the return type
                    found_fn = None
                    for fn in FnSameClass:
                        if fn.ret_type == arg:
                            if found_fn is None:
                                if fn.fname != targetFn:
                                    found_fn = fn
                            else:
                                found_fn = choose_better_to_fuzz_function(found_fn, fn)
                    if found_fn is not None:
                        logging.debug(f"long heuristic found a function to add for targetfunction: {targetFn} for arg {arg}; {found_fn.fname}")
                        cs_entry["sequence"].append({"fname": found_fn.fname, "reason": "cs_heuristic"})
    logging.info(f"callsequence heuristic callsequence: {callsequence}")
    return callsequence
                
