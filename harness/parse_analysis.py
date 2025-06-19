"""
Philipp Mao, 20.10.2022: 
Parse the static analyis output from the UCI tools and generate the format for the harness generation
Sorry about this ...
"""
import sys
import argparse
import shutil
import logging
import os
import json
import copy
import random

random.seed(1234)

logging.basicConfig(filename='parse_static.log', encoding='utf-8', level=logging.DEBUG, format='%(asctime)s %(message)s')

from harness.lib.define import *
from harness.lib.constraints import generate_argument_constraints_basic, enrich_argument_constraints_simple_constant, get_top_signatures, \
    enrich_argument_constraints_simple_special, enrich_argument_constraints_phenomenon, enrich_argument_constraints_heuristic, enrich_argument_constraints_GAPS, try_find_corresponding_signature
from harness.lib.callsequence import generate_empty_callsequence, generate_callsequence_phenomenon, generate_callsequence_data_heuristic, generate_cs_io_GAPS
from harness.lib.utils import functionInfo, parse_sig_lib_offsets, get_fuzz_needed_type_2, add_cs


def io_matching(harness_gen_callsequence, unique=False, random_choice=True):
    """
    enrich the data dependency info with input output matching
    @aggressive: attempt to match every argument to an output
    @unique: for a function every argument can only be matched to at most another one
    @random: if true, one callsequence may become multiple if there are different ways of doing input output matching
    TODO: for types other than long, non-supported types: Allow non-aggressive matching and also add random option to not match
    """
    if random_choice:
        harness_gen_callsequence_out = {}
        for f in harness_gen_callsequence:
            f_ind_2_ret = {}
            # maps function -> arg indexes -> list of possible functions in callsequence returning the value in question
            data_dependency_possibilities = {}
            cs = harness_gen_callsequence[f]
            for i, f_cs in enumerate(cs):
                counter_fname = f_cs["name"]+"-"+str(i)
                data_dependency_possibilities[counter_fname] = {}
                for arg_ind, arg in enumerate(f_cs['signature']['args']):
                    data_dependency_possibilities[counter_fname][arg_ind] = []
                    if 'constraints' in arg:
                        # the argument has a constraint, no need for input output matching
                        continue
                    if AGGRESSIVE_IO_MATCHING:
                        # try to replace all types
                        for f_ind in reversed(range(len(f_ind_2_ret))):
                            if f_ind_2_ret[f_ind] == arg['type']:
                                data_dependency_possibilities[counter_fname][arg_ind].append(f_ind)
                                if f_ind >= i:
                                    print("WWWWWWWWWWTTTTTTTTTTTTTTTFFFFFFFFFFFFFFFFFFFFFFF")
                                    exit(0)
                    else:
                        # only try replacing types not supported by the harness
                        print(arg)
                        if arg["type"] in TYPE_MAPPING_ARGS and arg["type"] != 'long':
                            continue
                        # try to look for return types everywhere
                        for f_ind in reversed(range(len(f_ind_2_ret))):
                            if f_ind_2_ret[f_ind] == arg['type']:
                                data_dependency_possibilities[counter_fname][arg_ind].append(f_ind)
                                if f_ind >= i:
                                    print("WWWWWWWWWWTTTTTTTTTTTTTTTFFFFFFFFFFFFFFFFFFFFFFF")
                                    exit(0)
                f_ind_2_ret[i] = f_cs['signature']['ret_type']
            # now choose combinations of possible input output matching 
            logging.debug(f"input output possibilities {data_dependency_possibilities} for {cs}") 
            chosen_combos = []
            for _ in range(0, 100 * NR_IO_COMBINATIONS):
                # loop for a while, randomly sample callsequences, check if they already exist, else add new function _{cnt} to the callsequence
                generated_possibility = {}
                for f_poss in data_dependency_possibilities:
                    generated_possibility[f_poss] = {}
                    for ind in data_dependency_possibilities[f_poss]:
                        if len(data_dependency_possibilities[f_poss][ind]) > 0:
                            generated_possibility[f_poss][ind] = random.choice(data_dependency_possibilities[f_poss][ind])
                if generated_possibility not in chosen_combos:
                    chosen_combos.append(generated_possibility)
                if len(chosen_combos) > NR_IO_COMBINATIONS:
                    break
            logging.debug(f"generated random sequences: {chosen_combos}")
            added = 0
            for i, combo in enumerate(chosen_combos):
                cs_new = copy.deepcopy(cs)
                for k, f_cs in enumerate(cs_new):
                    counter_fname = f_cs["name"]+"-"+str(k)
                    dp_combo = combo[counter_fname]
                    for arg_ind in dp_combo:
                        if str(arg_ind) in f_cs['data_dependencies']:
                            logging.debug(f'{arg_ind} {f_cs} already in cs')
                            continue
                        f_cs['data_dependencies'][str(arg_ind)] = {"findex": str(dp_combo[arg_ind]), "reason": "io_matching"}
                        if dp_combo[arg_ind] >= k:
                            print(counter_fname, dp_combo, cs_new)
                            print("WWWWWWWWWWTTTTTTTTTTTTTTTFFFFFFFFFFFFFFFFFFFFFFF")
                            exit(0)
                if added >= NR_IO_COMBINATIONS:
                    break
                added += 1
                harness_gen_callsequence_out[f"{f}-{i}"] = cs_new
                print("IO MATCHING", f, i, chosen_combos)
                logging.debug(f"new io callsequence added: {harness_gen_callsequence_out[f'{f}-{i}']}")
        return harness_gen_callsequence_out
    else:
        for f in harness_gen_callsequence:
            # simpler datastructure to keep track of the indexes to return types in teh callsequence
            f_ind_2_ret = {}
            cs = harness_gen_callsequence[f]
            for i, f_cs in enumerate(cs):
                already_chosen_functions = set()
                for arg_ind, arg in enumerate(f_cs['signature']['args']):
                    if 'constraints' in arg:
                        # the argument has a constraint, no need for input output matching
                        continue
                    if AGGRESSIVE_IO_MATCHING:
                        # try to replace all types
                        for f_ind in reversed(range(len(f_ind_2_ret))):
                            if f_ind_2_ret[f_ind] == arg['type']:
                                if unique and f_ind in already_chosen_functions:
                                    continue
                                already_chosen_functions.add(f_ind)
                                f_cs['data_dependencies'][str(arg_ind)] = {"findex": str(f_ind), "reason": "io_matching"}
                                break
                    else:
                        # only try replacing types not supported by the harness
                        if arg in TYPE_MAPPING_ARGS and arg != 'long':
                            continue
                        # try to look for return types everywhere
                        for f_ind in reversed(range(len(f_ind_2_ret))):
                            if f_ind_2_ret[f_ind] == arg['type']:
                                if unique and f_ind in already_chosen_functions:
                                    continue
                                already_chosen_functions.add(f_ind)
                                f_cs['data_dependencies'][str(arg_ind)] = {"findex": str(f_ind), "reason": "io_matching"}
                                break
                f_ind_2_ret[i] = f_cs['signature']['ret_type']
            harness_gen_callsequence[f] = cs
        return harness_gen_callsequence


def clean_and_purge(harness_gen_callsequence, with_generic_jobject=False, only_fuzzable=False, only_constrained=False):
    """
    remove sequences/functions with non-supported arguments
    replace the arguments wth the jni name
    @remove_all: determines if we will remove the entire callsequence or only the specific function, currently entire callsequence is removed
    """
    harness_generation_callsequence_out = {}
    for f in harness_gen_callsequence:
        cs = copy.deepcopy(harness_gen_callsequence[f])
        unsup_arg = False
        fuzzable_arg_present = False
        constraint_present = False
        for cs_f in cs:
            # set return value to jni c type
            if cs_f['signature']['ret_type'] in TYPE_MAPPING_ARGS:
                cs_f['signature']['ret_type'] = TYPE_MAPPING_ARGS[cs_f['signature']['ret_type']]
            else:
                cs_f['signature']['ret_type'] = 'jobject'
            # check args if supported
            for i, arg in enumerate(cs_f['signature']['args']):
                if 'constraints' in arg:
                    constraint_present = True
                if arg['type'] not in TYPE_MAPPING_ARGS:
                    # check if argument comes from data dependency
                    if str(i) in cs_f["data_dependencies"]:
                        # luckily the argument is from a dependency, change type to object
                        arg['type'] = "Object"
                    elif 'constraints' in arg and 'equals' in arg['constraints'] and arg['constraints']['equals'] == 'null':
                        logging.debug(f"callsequence {f} using jobject with null constraint for {arg['type']}")
                        arg['type'] = "jobject"
                    elif with_generic_jobject:
                        logging.debug(f"callsequence {f} using jobject for {arg['type']}")
                        arg['type'] = "jobject"
                    else:
                        # no dice
                        logging.debug(f"unsupported arg in cs: {arg}, {cs_f['signature']['args']}, {cs_f}")
                        unsup_arg = True
                        break
                else:
                    tofuzz, tofuzz_type = get_fuzz_needed_type_2(arg)
                    if tofuzz_type in FUZZABLE_TYPES and tofuzz:
                        logging.debug(f"fuzzable argument present cs: {arg}, {cs_f['signature']['args']}, {cs_f}")
                        fuzzable_arg_present = True
                    arg['type'] = TYPE_MAPPING_ARGS[arg['type']]
            if unsup_arg:
                break
        if unsup_arg: 
            logging.debug(f"deleted cs: {cs}")
        else:
            if add_cs(only_fuzzable, fuzzable_arg_present, only_constrained, constraint_present):
                harness_generation_callsequence_out[f] = cs
            else:
                logging.debug(f'deleted cs {cs} {only_fuzzable, fuzzable_arg_present, only_constrained, constraint_present}')
    print(f"[!] callsequences removed due to unsupported argument: {len(harness_gen_callsequence) - len(harness_generation_callsequence_out)}")
    return harness_generation_callsequence_out


def merge_callsequence_signature(callsequence, fname2signature, with_phenomenon_cs_constraints=True):
    """
    merge both callsequence and signature
    """
    harness_generation_callsequence = {}
    # TODO: add some callerinfo (if available) to better merge callsequence and fname2signature (currently we just pick the fist entry ::/) => kinda solved when using the phenom callsequences
    # TODO: current function naming scheme is a counter for the function FNMAE@ind
    for fname in callsequence:
        f_counter = 0
        f_callsequences = callsequence[fname]
        for cs in f_callsequences:
            if len(cs["sequence"])>0:
                harness_generation_callsequence_f = []
                for cs_entry in cs["sequence"]:
                    reason = cs_entry["reason"]
                    f = cs_entry["fname"]
                    if "phenom_j" == reason and with_phenomenon_cs_constraints:
                        # use the constraints from the phenomenon constraints
                        #sig = copy.deepcopy(fname2signature[f][0])
                        sig = copy.deepcopy(try_find_corresponding_signature(cs_entry, fname2signature[f]))
                        if "args" in cs_entry:
                            logging.debug(f"adding phenom cs constraint {sig}, {cs_entry}")
                            for i, cs_arg in enumerate(cs_entry["args"]):
                                if "constraints" in cs_arg:
                                    if "constraints" not in sig["args"][i]:
                                        sig["args"][i]["constraints"] = cs_arg["constraints"]
                                    else:
                                        sig["args"][i]["constraints"].update(cs_arg["constraints"])
                        harness_generation_callsequence_f.append({"name": f, "reason": reason, "signature": sig, "data_dependencies": {}})
                    else:
                        harness_generation_callsequence_f.append({"name": f, "reason": reason, "signature": copy.deepcopy(fname2signature[f][0]), "data_dependencies": {}})
                sig = copy.deepcopy(try_find_corresponding_signature(cs, fname2signature[fname]))
                if WITH_PHENOM_CONSTRAINTS and "args" in cs:
                    logging.debug(f"adding phenom cs constraint {sig}, {cs}")
                    if "args" in cs:
                        for i, cs_arg in enumerate(cs["args"]):
                            if "constraints" in cs_arg:
                                if "constraints" not in sig["args"][i]:
                                    sig["args"][i]["constraints"] = cs_arg["constraints"]
                                else:
                                    sig["args"][i]["constraints"].update(cs_arg["constraints"])
                harness_generation_callsequence_f.append({"name": fname, "reason": "final_function", "signature": sig, "data_dependencies": cs["data_dependencies"]})
                logging.debug(f'adding cs to hgcs {fname}: {harness_generation_callsequence_f}')
                harness_generation_callsequence[f"{fname}@{f_counter}"] = copy.deepcopy(harness_generation_callsequence_f)
                f_counter += 1
            else:
                # no callsequence so instead just look for the 
                logging.info(f'MERGING single function getting top X signatures')
                logging.debug(f'getting top signatures: {fname} {fname2signature[fname]}')
                sigs = get_top_signatures(fname2signature[fname])
                for sig in sigs:
                    harness_generation_callsequence_f = []
                    sig = copy.deepcopy(sig)
                    harness_generation_callsequence_f.append({"name": fname, "reason": "final_function", "signature": sig, "data_dependencies": {}})
                    harness_generation_callsequence[f"{fname}@{f_counter}"] = copy.deepcopy(harness_generation_callsequence_f)
                    f_counter += 1
                    logging.debug(f'adding cs to hgcs {fname}: {harness_generation_callsequence_f}')
    logging.info(f"merged harness generation callsequence: {harness_generation_callsequence}")
    return harness_generation_callsequence


def parse_static(app, with_arg_value_constraints, with_arg_value_constraints_gaps, with_phenomenon_callsequence, phenom_cs_min_length,
 with_cs_io_gaps, with_callsequence_heuristic, with_constraints_heuristic, with_io_matching, with_generic_jobject, only_constrained, only_fuzzable):
    # generate the fname2signature dictionary
    sig_lib_offsets_path = os.path.join(TARGET_APK_PATH, app, "signatures_libraries_offsets.txt")
    with open(sig_lib_offsets_path, "r") as f:
        fInfos = parse_sig_lib_offsets(f.read())
    fname2signature = generate_argument_constraints_basic(app)
    if len(fname2signature) == 0:
        print("[!] no functions in fname2signature, exiting")
        exit(0)
    if with_arg_value_constraints:
        print("[..] generating argument list for arg value constraints")
        fname2signature = enrich_argument_constraints_simple_constant(app, fname2signature, fInfos)
        fname2signature = enrich_argument_constraints_simple_special(app, fname2signature, fInfos)
    if with_arg_value_constraints_gaps:
        print("[..] argument value constraints with GAPS")
        fname2signature = enrich_argument_constraints_GAPS(app, fname2signature, fInfos)
    if with_constraints_heuristic:
        print("[..] arg constraint heuristics baby!!")
        fname2signature = enrich_argument_constraints_heuristic(fname2signature)
    # generate the callsequence dictionary 
    callsequence = generate_empty_callsequence(app)
    if with_phenomenon_callsequence:
        print("[..] generating phenomenon callsequence")
        callsequence = generate_callsequence_phenomenon(app, callsequence, fInfos, min_length=phenom_cs_min_length)
    if with_cs_io_gaps:
        print(f'[..] generating cs_io constraints with GAPS')
        callsequence = generate_cs_io_GAPS(app, callsequence, fInfos)
    if with_callsequence_heuristic:
        print("[..] callsequence heuristics baby!!")
        callsequence = generate_callsequence_data_heuristic(app, callsequence, fInfos)
    harness_generation_callsequences = merge_callsequence_signature(callsequence, fname2signature, with_phenomenon_cs_constraints=with_arg_value_constraints)
    # do input output matching 
    if with_io_matching:
        print("[..] doing io matching")
        harness_generation_callsequences = io_matching(harness_generation_callsequences)
    # delete callsequences with unsupported arguments
    harness_generation_callsequences = clean_and_purge(harness_generation_callsequences, with_generic_jobject, only_fuzzable, only_constrained)
    with open(os.path.join(TARGET_APK_PATH, app, "harness_generation_callsequences.json"), "w+") as f:
        f.write(json.dumps(harness_generation_callsequences))
    return harness_generation_callsequences
