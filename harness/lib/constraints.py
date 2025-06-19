import logging
import os
import json
import copy
from define import *
from utils import parse_sig_lib_offsets, parse_simple_argument_constraints, get_constant_cpp_string, get_short_functionname, \
 parse_simple_argument_constraints_special, parse_argument_constraints_GAPS, get_constant_cpp_string_GAPS


def z3_to_constraints(z3_file):
    """
    parse z3 file and obtain constraints TODO
    """
    return 42


def generate_argument_constraints_basic(app):
    sig_lib_offsets_path = os.path.join(TARGET_APK_PATH, app, "signatures_libraries_offsets.txt")
    if not os.path.exists(sig_lib_offsets_path):
        print("[!] no signatures_libraries_offsets.txt file for app: ", app)
        return {}
    with open(sig_lib_offsets_path, "r") as f:
        sig_libs_offsets = f.read()
    fInfos = parse_sig_lib_offsets(sig_libs_offsets)
    signatures = {}
    for fname in fInfos:
        f  = fInfos[fname]
        sig = f.get_basic_signature_for_function()
        signatures[f.fname] = [sig]
    return signatures


def get_signature_score(signature):
    """
    give a score to a signature
    +1 constant constraint
    -1 unconstrained not-fuzzable
    +2 filepath
    +2 lenof
    +2 empty with size
    +1 empty (no size)
    +2 equal
    +1 array with size
    """
    score = 0
    fuzzable_present = False
    for arg in signature["args"]:
        if 'constraints' not in arg:
            if arg not in FUZZABLE_TYPES:
                score -=1
            else:
                fuzzable_present = True
            continue
        arg_constr = arg["constraints"]
        if "equals" in arg_constr:
            score += 1
        elif "lenof" in arg_constr:
            score += 2
        elif "filepath" in arg_constr:
            score += 2
        elif "empty_array" in arg_constr:
            if 'len' in arg_constr["empty_array"]:
                score += 0
            else:
                score += 0
        elif "max_array_length" in arg_constr:
            score += 1
        elif "same_var" in arg_constr:
            score += 2
    if fuzzable_present:
        score += 2
    logging.debug(f'score for {signature}: {score}')
    return score


def try_find_corresponding_signature(cs_seq, signatures):
    """
    try to associate the caller to the signature, if this fails return the "best constraint"
    """
    #return signatures[0]
    potential_signatures = []
    if "caller" in cs_seq:
        caller = cs_seq["caller"]
        for signature in signatures:
            print(caller, signature)
            if 'parent' in signature and caller == signature["parent"]:
                potential_signatures.append(signature)
    if len(potential_signatures) == 1:
        # we found only one matching constraint with the same caller, so return this
        logging.debug(f'found one matching signature for callsequence caller {caller}, {potential_signatures[0]}')
        return potential_signatures[0]
    if len(potential_signatures) == 0:
        potential_signatures = signatures
    # now we iterate over all potential signatures and choose the best one
    score = get_signature_score(potential_signatures[0])
    found = potential_signatures[0]
    for signature in potential_signatures[1:]:
        temp_score = get_signature_score(signature)
        if temp_score > score:
            found = signature
    return found


def check_sig_in_signatures(sig, signatures):
    ret_type = sig['ret_type']
    args = sig['args']
    lib = sig['library']
    offset = sig['offset']
    for sig2 in signatures:
        if sig2['ret_type'] == ret_type and sig2['args'] == args and sig2['library'] == lib and sig2['offset'] == offset:
            print(f'BBBBBBBBBBBBBBB', sig2, sig)
            return True
    return False


def get_top_signatures(signatures, deduplicate=True):
    sig_score = []
    if deduplicate:
        dedup_list = list(x for i,x in enumerate(signatures) if not check_sig_in_signatures(x, signatures[:i]))
        signatures = dedup_list
    for sig in signatures:
        sig_score.append((sig, get_signature_score(sig)))
    sig_score = sorted(sig_score, key=lambda x: x[1])
    sig_score.reverse()
    sig_out = list(k[0] for k in sig_score[:MAX_NR_GAPS_CT])
    logging.debug(f'sig list top {MAX_NR_GAPS_CT}: {sig_out}')
    print("AAAAAAAAAAAAAAAAAAAAAAAA", signatures, sig_score[:MAX_NR_GAPS_CT])
    return sig_out


def enrich_argument_constraints_simple_constant(app, fname2signatures, fInfos):
    """
    parse the simple_argument_constraints.txt and generate the corresponding dictionary fname2signature for the json to the generate_harness function
    the output is inserted into {"name": f, "signature": fname2signature[f], "data_dependencies": {}}
    returns a fname2signature dictionary
    if we have multiple values, we will create a new signature netry for it
    """
    txt_path = os.path.join(TARGET_APK_PATH, app, "static_analysis", "simple_argument_constraints.txt")
    if not os.path.exists(txt_path):
        print("[!] no simple argument constraints, will just return the normal functions, returning")
        return fname2signatures
    with open(txt_path, "r") as f:
        simple_argument_constraints = f.read()
    # {fname: [{0: "asdf", 1: 2.2}, {0: "ABC"}], fname2: [...]}
    simple_argument_constraints = parse_simple_argument_constraints(simple_argument_constraints)
    fname2signatures_out = {}
    # add the constraints to fname2signatures
    for fname in fInfos:
        if fname in simple_argument_constraints:
            fname2signatures_out[fname] = []
            for simple_constraints in simple_argument_constraints[fname]:
                for signature in fname2signatures[fname]:
                    #should only be one
                    signature_copy = copy.deepcopy(signature)
                    if len(simple_constraints) != len(signature_copy['args']):
                        logging.debug(f"{fname} {signature_copy}, {simple_constraints}, overloaded function not correct? skipping")
                        fname2signatures_out[fname].append(signature_copy)
                        continue
                    for ind in simple_constraints:
                        value = simple_constraints[ind]
                        arg = signature_copy['args'][ind]
                        arg['constraints'] = {'equals': {'value': get_constant_cpp_string(value, arg['type']), 'reason': 'simple_flowdroid'}}
                    fname2signatures_out[fname].append(signature_copy)
        else:
            fname2signatures_out[fname]  = copy.deepcopy(fname2signatures[fname])   
    logging.info(f"fname2signatures after enriching with simple constraints: {fname2signatures_out}")
    return fname2signatures_out


def enrich_argument_constraints_simple_special(app, fname2signatures, fInfos):
    """
    parse the simple_argument_constraints.txt and generate the corresponding dictionary fname2signature for the json to the generate_harness function
    looks for special constraints such as filepath/length dependencies
    the output is inserted into {"name": f, "signature": fname2signature[f], "data_dependencies": {}}
    returns a fname2signature dictionary
    """
    txt_path = os.path.join(TARGET_APK_PATH, app, "static_analysis", "simple_argument_constraints.txt")
    if not os.path.exists(txt_path):
        print("[!] no simple argument constraints, will just return the normal functions, returning")
        return fname2signatures
    with open(txt_path, "r") as f:
        simple_argument_constraints_special = f.read()
    # {fname: [{0: "asdf", 1: 2.2}, {0: "ABC"}], fname2: [...]}
    simple_argument_constraints_special = parse_simple_argument_constraints_special(simple_argument_constraints_special)
    fname2signatures_out = {}
    # add the constraints to fname2signatures
    for fname in fInfos:
        if fname in simple_argument_constraints_special:
            fname2signatures_out[fname] = []
            for signature in fname2signatures[fname]:
                signature_copy = copy.deepcopy(signature)
                for special_constraint in simple_argument_constraints_special[fname]:
                    #should only be one
                    if special_constraint["type"] == "len": 
                        byte_arg_ind = special_constraint["byte_arg_ind"]
                        len_arg_ind = special_constraint["len_arg_ind"]
                        if len_arg_ind > len(signature_copy['args'])-1 or byte_arg_ind > len(signature_copy['args'])-1:
                            # indices outside of argument range skip
                            logging.debug(f"{fname} {signature_copy} {special_constraint} indexes out of range!")
                            continue
                        if signature_copy['args'][len_arg_ind]["type"] != "int":
                            logging.debug(f"{fname} {signature_copy} {special_constraint} not integer at index!")
                            continue
                        if signature_copy['args'][byte_arg_ind]["type"] != "byte[]":
                            logging.debug(f"{fname} {signature_copy} {special_constraint} not byte[] at index!")
                            continue
                        arg = signature_copy['args'][len_arg_ind]
                        arg['constraints'] = {'lengthof': {'bytearr_arg': str(byte_arg_ind), 'reason': 'simple_special'}}
                        logging.debug(f"{fname} {signature_copy} after lenght ind arg")
                    if special_constraint["type"] == "filepath":
                        filepath_arg_ind = special_constraint["file_path_arg_ind"]
                        if filepath_arg_ind > len(signature_copy['args'])-1:
                            # indices outside of argument range skip
                            logging.debug(f"{fname} {signature_copy} {special_constraint} indexes out of range!")
                            continue
                        if signature_copy['args'][filepath_arg_ind]['type'] != "String":
                            logging.debug(f"{fname} {signature_copy} {special_constraint} not String at index!")
                            continue
                        arg = signature_copy['args'][filepath_arg_ind]
                        arg['constraints'] = {'filepath': {'reason': 'simple_special'}}
                        logging.debug(f"{fname} {signature_copy} after filepath ind arg")
                fname2signatures_out[fname].append(signature_copy)
        else:
            fname2signatures_out[fname]  = copy.deepcopy(fname2signatures[fname])   
    logging.info(f"fname2signatures after enriching with simple special constraints: {fname2signatures_out}")
    return fname2signatures_out


def enrich_argument_constraints_GAPS(app, fname2signatures, fInfos):
    """
    Parse the base-instr.json and add the constraints to the fname2signatures file
    """
    data_path = os.path.join(TARGET_APK_PATH, app, "static_analysis", f"{app}-instr.json")
    if not os.path.exists(data_path):
        print("[!] no GAPS json, returning input")
        return fname2signatures
    with open(data_path, "r") as f:
        gaps_argument_constraints = parse_argument_constraints_GAPS(json.load(f), fInfos)
    # {fname: [{0: "asdf", 1: 2.2, "parent": "parent1"}, {0: "ABC", "parent": "parent2"}], fname2: [...]}
    fname2signatures_out = {}
    for fname in fInfos:
        if fname not in gaps_argument_constraints:
            # no change and skip
            fname2signatures_out[fname] = copy.deepcopy(fname2signatures[fname]) 
            continue
        if len(gaps_argument_constraints[fname]) == 0:
            # no constraints.. skip
            fname2signatures_out[fname] = copy.deepcopy(fname2signatures[fname]) 
            continue
        fname2signatures_out[fname] = []    
        for signature in fname2signatures[fname]:
            # iterate over the gaps constraints and integrate them 
            gaps_parents_added = 0
            for constraints in gaps_argument_constraints[fname]:
                signature_copy = copy.deepcopy(signature)
                logging.debug(f'ADDRESSOF SIGNATURE {id(signature_copy)} {fname}')
                parent = constraints['parent']
                constr_added = 0 # this counter tracks if any of the GAPS constraints were actually added
                for constr in constraints['constraints']:
                    ct_type = constr['type']
                    param_ind = constr['param_ind']
                    if param_ind > len(signature_copy['args'])-1:
                        print(f'WTFFF lenght index of constrainted param greater than signature???? {constr}, {signature_copy}')
                        exit(-1)
                    if 'constraints' in signature_copy['args'][param_ind] and len(signature_copy['args'][param_ind]['constraints']) > 0:
                        print(f'[GAPSCT] another constraint for the same aprameter {param_ind} {constr} {signature_copy}')
                        exit(-1)
                    if ct_type == 'lenof':
                        len_arg_ind = constr["len_arg_ind"]
                        if len_arg_ind > len(signature_copy['args'])-1:
                            # indices outside of argument range skip
                            #print(f'[GAPSCONSTR] arg out of range?? {signature_copy}, {constr}')
                            logging.debug(f"{fname} {signature_copy} {constr} indexes out of range!")
                            continue
                        if signature_copy['args'][param_ind]["type"] != "int":
                            # length not int @TODO add support for other types such as a
                            #print(f'[GAPSCONSTR] lenght not int??? {fname} {signature_copy}, {constr}')
                            logging.debug(f"{fname} {signature_copy} {constr} not integer at index!")
                            continue
                        if signature_copy['args'][len_arg_ind]["type"] != "byte[]":
                            #print(f'[GAPSCONSTR] lenghtof is not bytearray {fname} {signature_copy}, {constr}')
                            logging.debug(f"{fname} {signature_copy} {constr} not byte[] at index!")
                            continue
                        constr_added += 1
                        arg = signature_copy['args'][param_ind]
                        arg['constraints'] = {'lengthof': {'bytearr_arg': str(len_arg_ind), 'reason': 'GAPS'}}
                        logging.debug(f'adding lengthof bytearray constraint')
                    elif ct_type == 'constant':
                        if signature_copy['args'][param_ind]["type"] == "byte[]":
                            print("not supported constant bytearray")
                            continue
                        arg = signature_copy['args'][param_ind]
                        value = constr["value"]
                        if signature_copy['args'][param_ind]["type"] in NUMERIC_TYPES_1:
                            try:
                                int(get_constant_cpp_string_GAPS(value, arg['type']))
                            except Exception as e:
                                logging.debug(f'{fname} INVALID constant for numeric type {arg} {constr} {str(e)}')
                                continue 
                        if signature_copy['args'][param_ind]["type"] in NUMERIC_TYPES_2:
                            try:
                                float(get_constant_cpp_string_GAPS(value, arg['type']))
                            except Exception as e:
                                logging.debug(f'{fname} INVALID constant for numeric type {arg} {constr} {str(e)}')
                                continue 
                        constr_added += 1
                        logging.debug(f'ADRESS OF ARG constant {fname}, {id(arg)}')
                        arg['constraints'] = {'equals': {'value': get_constant_cpp_string_GAPS(value, arg['type']), 'reason': 'GAPS'}}
                    elif ct_type == 'filepath':
                        constr_added += 1
                        if signature_copy['args'][param_ind]['type'] != "String":
                            #print(f"{fname} {signature_copy} {constr} not String at index!")
                            logging.debug(f"{fname} {signature_copy} {constr} not String at index!")
                            continue
                        arg = signature_copy['args'][param_ind]
                        arg['constraints'] = {'filepath': {'reason': 'GAPS'}}
                        logging.debug(f'ADRESS OF ARG filepath {fname}, {id(arg)}')
                        logging.debug(f"{fname} {signature_copy} after filepath ind arg")
                    elif ct_type == 'stdlib':
                        continue
                        constr_added += 1
                        java_func = constr["java_func"]
                        arg = signature_copy['args'][param_ind]
                        arg['constraints'] = {'stdlib': {'java_func': java_func, 'reason': 'GAPS'}}
                        logging.debug(f"{fname} {signature_copy} after stdlib GAPS constr")
                    elif ct_type == 'empty_array':
                        constr_added += 1
                        arg = signature_copy['args'][param_ind]
                        logging.debug(f'ADRESS OF ARG empty array {fname}, {id(arg)}')
                        arg['constraints'] = {'empty_array': {'reason': 'GAPS'}}
                        #print("EEEEEEEEEEEMTPYT", constr, 'empty array')
                        if 'len' in constr and int(constr['len'])!= 0:
                            arg['constraints']['empty_array']['len'] = constr['len']
                        logging.debug(f"{fname} {signature_copy} after empty_array GAPS constr")
                    elif ct_type == 'max_array_length':
                        continue
                        constr_added += 1
                        arg = signature_copy['args'][param_ind]
                        arg['constraints'] = {'max_array_length': {'len': constr['len'], 'reason': 'GAPS'}}
                        logging.debug(f"{fname} {signature_copy} after max_array_length GAPS constr")
                    elif ct_type == 'byte_buffer_lenght':
                        continue
                        constr_added += 1
                        arg = signature_copy['args'][param_ind]
                        arg['constraints'] = {'byte_buffer_max_lenght': {'len': constr['len'], 'reason': 'GAPS'}}
                        logging.debug(f"{fname} {signature_copy} after byte_buffer_max_lenght GAPS constr")
                    elif ct_type == 'other_invoke':
                        constr_added += 1
                        arg = signature_copy['args'][param_ind]
                        if constr['func'] == 'Ljava/nio/ByteBuffer;->position()I': #we set the position of any bytebuffer to be passed to 0
                            arg['constraints'] = {'equals': {'value': '0', 'reason': 'GAPS'}}
                    elif ct_type == 'same_var':
                        constr_added += 1
                        arg = signature_copy['args'][param_ind]
                        logging.debug(f'ADRESS OF ARG same_var {fname}, {id(arg)}')
                        arg['constraints'] = {'same_var': {'var': constr['var'], 'reason': 'GAPS'}}
                        logging.debug(f"{fname} {signature_copy} after same_var GAPS constr")
                    else:
                        # constraint is not relevant to argval so skip it
                        continue
                if constr_added > 0:
                    logging.debug(f'ALREADY IN {fname} {signature_copy } {fname2signatures_out[fname]}')
                    if signature_copy in fname2signatures_out[fname]:
                        continue
                    logging.debug(f'ADDING TO {fname} {signature_copy } {fname2signatures_out[fname]}')
                    gaps_parents_added += 1
                    signature_copy['parent'] = parent
                    fname2signatures_out[fname].append(signature_copy)
                    logging.debug(f'ADDED TO {fname} {fname2signatures_out[fname]}')
            if gaps_parents_added == 0:
                # no GAPS enriched signatures were added at all so need to append original signature
                logging.debug(f'adding original one {fname}, {signature}')
                fname2signatures_out[fname].append(copy.deepcopy(signature)) # just keep the old data
        logging.debug(f'DONE FOR ITERATION GAPS PARSING {fname}: {fname2signatures_out[fname]}')
    logging.info(f"fname2signatures after enriching with GAPS constraints: {fname2signatures_out}")
    #print(fname2signatures_out)
    open("debug.json", "w").write(json.dumps(fname2signatures_out))
    return fname2signatures_out


def enrich_argument_constraints_phenomenon(target, functionName, args):
    """
    TODO: not implemented at all currently!
    enrichtes the json fed into the harness generator with constraints
    @functionName: the full java functionname with underscores
    @args: list of arguments, in the format expected by the harness generator
    @line_number (NOT IMPLEMENTED CURRENTLY): TODO: have some logic to choose the line number
    """
    analysis_path = os.path.join(TARGET_APK_PATH, target, "static_analysis")
    # open BASE_FILENAME, look for the function with the corresponding line number
    with open(os.path.join(analysis_path, BASE_FILENAME)) as f:
        base_file = json.loads(f.read())
    with open(os.path.join(analysis_path, PHENOMENON_FILENAME)) as f:
        phenomenon_file = json.loads(f.read())
    base_fn_info = {}
    for fn in base_file:
        if fn["nativeName"] == get_short_functionname(functionName):
            base_fn_info = fn
            break
    if base_fn_info == {}:
        print("[!] native function not found in base output, returning")
        return args
    # iterate over the arguments
    for i, java_param_type in enumerate(base_fn_info["params"]):
        argument = args[i]
        if TYPE_MAPPING_ARGS[java_param_type] != argument["type"]:
            # Sanity check
            print(f"[!] type from harness json: {argument['type']} is different to type in analysis file: {java_param_type}, returning!")
            return args
        # find the argument in the PHENOMENON_FILENAME
        ph_info = {}
        for ph in phenomenon_file:
            if ph["name"] == base_fn_info["name"]:
                ph_info = ph
                break
        if ph_info == {}:
            print(f"[-] argument {argument} not found in phenomen output, no constraints added")
            continue
        # check if a z3 file exists, TODO: is it always z3_path_cond0
        if os.path.exists(os.path.join(analysis_path, f"{ph_info['name']}_z3_path_cond0")):
            with open(os.path.join(analysis_path, f"{ph_info['name']}_z3_path_cond0"), "r") as f:
                z3_file = json.loads(f.read())
        else:
            print(f"[-] no constraints added for argument {argument}, no constraints added")
            continue    
        # evaluate the z3 constraints for the value and generate an equals constraint
        # argument['constraints'] = z3_to_constraints(z3_file)
        args[i] = argument
    
    return args


def enrich_argument_constraints_heuristic(fname2signatures, level=0):
    """
    add some standalone constraints based on heuristics (type, funcitonname and so on)
    TODO: can have duplicates sometimes (openFIle("tmp/tes"), openFile("tmp/asdf")) -> will both be with filepath and same harness...
    """
    if level==0:
        for fname in fname2signatures:
            for sig in fname2signatures[fname]:
                for arg in sig["args"]:
                    if arg["type"] == "String":
                        if "file" in get_short_functionname(fname).lower() or "path" in get_short_functionname(fname).lower() or "open" in get_short_functionname(fname).lower():
                            if "constraints" in arg:
                                arg["constraints"]["filepath"] = {'reason': 'arg_fname_heuristic'}
                            else:
                                arg["constraints"] = {"filepath": {'reason': 'arg_fname_heuristic'}}
                            print(f"[:)] added filepath constraint for {fname}, {arg}")
                            logging.debug(f"added filepath constraint for {fname}, {arg}")
                            break
                    if arg["type"] == "int":
                        if "file" in get_short_functionname(fname).lower():
                            if "constraints" in arg:
                                arg["constraints"]["filedescriptor"] = {'reason': 'arg_fname_heuristic'}
                            else:
                                arg["constraints"] = {"filedescriptor": {'reason': 'arg_fname_heuristic'}}
                            print(f"[:)] added filedescriptor constraint for {fname}, {arg}")
                            logging.debug(f"added filedescriptor constraint for {fname}, {arg}")
                            break
    logging.info(f"data enrichment heuristics: {fname2signatures}")
    return fname2signatures