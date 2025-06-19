from define import *
import json
import logging
import re
import subprocess
import struct

reg = re.compile(r"Shared library: \[(.*)\]")


def add_cs(only_fuzzable, fuzzable_arg_present, only_constrained, constraint_present):
    if only_fuzzable and only_constrained:
        if fuzzable_arg_present and constraint_present:
            return True
    elif only_fuzzable and not only_constrained:
        if fuzzable_arg_present:
            return True
    elif not only_fuzzable and only_constrained:
        if constraint_present:
            return True
    elif not only_fuzzable and not only_constrained:
        return True
    return False


def is_param_ind(json_key):
    found = re.findall(r'param-(\d+)', json_key)
    if not found:
        return None
    return int(found[0])


def float_conversion(gaps_data, arg_type):
    print("conversion float", gaps_data, arg_type)
    if arg_type == "double":
        return str(struct.unpack("d", (int(gaps_data)).to_bytes(8, "little", signed=True))[0])
    if arg_type == "float":
        return str(struct.unpack("f", (int(gaps_data)).to_bytes(4, "little", signed=True))[0])
    else:
        return gaps_data


def get_shared_libs(lib_path):
    app_specific_libraries = []
    out = subprocess.check_output(['readelf', '-d', lib_path]).decode().split("\n")
    for line in out: 
        match = reg.findall(line)
        if match:
            library = match[0]
            if library in LIBS_TO_EXCLUDE or library in LIBS_LIB64:
                continue
            else:
                app_specific_libraries.append(library)
    return app_specific_libraries


def get_fuzz_needed_type_2(arg):
    # version where the type is still the original java type
    if "constraints" in arg and ("equals" in arg["constraints"] or "lengthof" in arg["constraints"] or "same_var" in arg["constraints"]):
        return False, None
    elif arg["type"] in EMPTY_ARRAY_TYPES_2:
        return False, None
    elif "constraints" in arg and arg["type"] == "byte[]":
        if "equals" in arg["constraints"]:
            return False, None
        elif "empty_array" in arg["constraints"]:
            if "len" in arg["constraints"]["empty_array"]:
                return False,None
            else:
                return True, 'int'
    elif "constraints" in arg and arg["type"] == "int":
        if "filedescriptor" in arg:
            return True, 'byte[]'
    elif "constraints" in arg and arg["type"] == "String":
        if "filepath" in arg["constraints"]:
            return True, arg['type'] 
    elif arg['type'] not in TYPE_MAPPING_ARGS:
        return False, None
    return True, arg['type']


def get_fuzz_needed_type(arg):
    if "constraints" in arg and ("equals" in arg["constraints"] or "lengthof" in arg["constraints"] or "same_var" in arg["constraints"]):
        return False, None
    elif arg["type"] in EMPTY_ARRAY_TYPES:
        return False, None
    elif "constraints" in arg and arg["type"] == "jbyteArray":
        if "equals" in arg["constraints"]:
            return False, None
        elif "empty_array" in arg["constraints"]:
            if "len" in arg["constraints"]["empty_array"]:
                return False,None
            else:
                return True, 'jint'
    elif "constraints" in arg and arg["type"] == "jint":
        if "filedescriptor" in arg:
            return True, 'jbyteArray'
    elif "constraints" in arg and arg["type"] == "jstring":
        if "filepath" in arg["constraints"]:
            return True, 'jbyteArray' 
    elif arg['type'] == "jobject":
        return False, None
    return True, arg['type']


def get_outer_classname(mangled_name):
    # from the mangled java name get the outer classname
    innerclass = get_classname(mangled_name)
    return innerclass[:innerclass.rfind("$")]


def get_short_functionname(mangled_name):
    # from the mangeld java name get only the function name
    mangled_name = mangled_name.replace("_1", "#")
    mangled_name = mangled_name[mangled_name.rfind("_")+1:]
    mangled_name = mangled_name.replace("#", "_1")
    return mangled_name


def get_classname(mangled_name):
    # from the mangled java name get the classname
    mangled_name = mangled_name.replace("_1", "#")
    if "__" in mangled_name:
        # handle overloaded functions
        mangled_name = mangled_name[:mangled_name.find("__")]
    return mangled_name[:mangled_name.rfind("_")]



class functionInfo:
    def __init__(self, args_list, ret_type, offset, library, fname):
        self.args_list = []
        for arg in args_list:
            if arg != '':
                self.args_list.append(arg)
        self.all_args_supported = all(arg in TYPE_MAPPING_ARGS for arg in self.args_list)
        self.ret_type = ret_type
        self.offset = offset
        self.library = library
        self.fname = fname    
        self.classname = get_classname(fname)
        # for nested classes
        self.outer_classname = None
        if "$" in self.classname:
            self.outer_classname = get_outer_classname(fname)
    def get_basic_signature_for_function(self):
        """
        for the app and function
        {'name': 'Java_com_example_hellolibs_MainActivity_byteArrayFunction', 'signature': {'args': [{'type': 'jbyteArray'}], 'ret_type': 'void', 'library': 'libhello-libs.so', 'offset': 392268}}
        """
        signature = {}
        signature['ret_type'] = self.ret_type
        args = []
        for arg in self.args_list:
            if arg == '':
                continue
            args.append({"type": arg})
        signature['args'] = args
        signature['library'] = self.library
        signature['offset'] = self.offset
        return signature


def parse_sig_lib_offsets(content):
    """
    parse the content of the signatures_libraries_offsets.txt file
    returns a list of functionInfo objects
    """
    output_list = {}
    sigs_libs_offsets = content.split("\n")
    for line in sigs_libs_offsets:
        if line == '':
            continue
        split = line.split(" ")
        fname = split[0]
        sig = split[1]
        ret_type = sig.split(":")[0]
        arg_list = sig.split(":")[1].split(",")
        library = split[2]
        offset = split[3]
        output_list[fname] = functionInfo(arg_list, ret_type, offset, library, fname)
    return output_list


def get_mangled_signature(args):
    # https://docs.oracle.com/en/java/javase/11/docs/specs/jni/design.html
    type_mapping = {"boolean": "Z", "byte": "B", "char": "C", "short": "S", "int":"I", "long": "J", "float":"F", "double":"D", "String": "Ljava_lang_String_2", "rest": "Ljava_lang_Object_2"}
    mangled_arg_sig = ""
    for arg in args:
        if arg == '':
            continue
        if arg in type_mapping:
            mangled_arg_sig += type_mapping[arg]
        elif arg[-2:] == "[]":
            if arg[:-2] in type_mapping:
                mangled_arg_sig += "_3" + type_mapping[arg[:-2]]
            else:
                mangled_arg_sig += "_3" + type_mapping["rest"]
        else:
            mangled_arg_sig += type_mapping["rest"]
    return mangled_arg_sig


def check_supported_args(cs, fInfos):
    """
    check if all arguments in the funciton list are in TYPE_MAPPING_ARGS
    """
    for f in cs:
        fname = f["fname"]
        if not fInfos[fname].all_args_supported:
            return False
    return True


def fixup_overload(fname_orig, args_orig, fInfos):
    """
    fname_orig is suspected to be an overloaded function
    """
    args = ",".join(a["type"] for a in args_orig)
    fname_fixed = fname_orig + "__" + get_mangled_signature(args)
    logging.debug(f"fixing overload: {fname_fixed}, {fname_orig}, {args}")
    if fname_fixed in fInfos:
        return fname_fixed
    else:
        return None


def get_partial(cs):
    out = []
    for i in range(1, len(cs)):
        out.append(cs[:i])
    return out


def parse_androguard_fcall(fcall):
    if type(fcall) == list:
        fcall = fcall[0]
    #parse the androguard fucntino naming
    classname = fcall[1:fcall.find(";->")]
    classname = classname.replace("_", "#")
    classname = classname.replace("/", "_")
    classname = classname.replace("#", "__")
    fname = fcall[fcall.find(";->")+3:fcall.find("(")]
    return "Java_" + classname + "_" + fname

def parse_phenom_callsequence(content, fInfos):
    """
    go from phenomonen callsequence json to a dict
    {fname: [cs1, cs2, cs3 ]}, where csx = [{fname: ..., caller: }]
    TODO: use fInfos to try and resolve overloaded function names
    """
    cs_json = json.loads(content)
    output = {}
    UCI_cache = {}
    for data in cs_json:
        if data["callerName"] not in UCI_cache:
            callername, callerargs = parse_callsequence_function_phenomenon(data["callerName"])
            UCI_cache[data["callerName"]] = (callername, callerargs)
        else:
            callername, callerargs = UCI_cache[data["callerName"]]
        callsequences = data["callSequences"]
        for cs in callsequences:
            if cs[-1] not in UCI_cache:
                final_function, final_args = parse_callsequence_function_phenomenon(cs[-1])
                if final_function not in fInfos:
                # function is not in fInfos, try to fixup the overloaded function
                    final_function = fixup_overload(final_function, final_args, fInfos)
                    if final_function is None:
                        # doesn't exist, ignore it
                        continue
                UCI_cache[cs[-1]] = (final_function, final_args)
            else:
                final_function, final_args = UCI_cache[cs[-1]]
            
            # for some reason the instruction is not always equal to the last function int he callsequnece
            # this checks for this and adjusts the callername accordingly
            # TODO: resolve this with Yu-jye
            # TODO: add function constraint parsing, simply extract this additional informatoin from the callsequences
            #class_final_function = get_classname(final_function)
            cs_parsed = []
            for fn in list(cs[:-1]):
                if fn not in UCI_cache:
                    fn, args = parse_callsequence_function_phenomenon(fn)
                    if fn not in fInfos:
                    # function is not in fInfos, try to fixup the overloaded function
                        fn = fixup_overload(final_function, args, fInfos)
                        if fn is None:
                            # doesn't exist, ignore it
                            continue
                    UCI_cache[fn] = (fn, args)
                else:
                    fn, args = UCI_cache[fn]
                #logging.debug(f"class comparison {class_final_function}, {get_classname(fn)}")
                #if get_classname(fn) == class_final_function:
                cs_parsed.append({"fname": fn, "caller": callername, "reason": "phenom_j", "args": args})
            if final_function in output:
                if not {"seq":cs_parsed, "args": final_args} in output[final_function]:
                    output[final_function].append({"seq":cs_parsed, "args": final_args, "caller": callername})
                else:
                    logging.debug(f"{cs_parsed} already in {output[final_function]}")
            else:
                output[final_function] = [{"seq":cs_parsed, "args": final_args, "caller": callername}]
        
    return output


def parse_simple_argument_constraints(content):
    """
    parse the contents of the simple arguments file
    {"fname": [{0:"asdf}, {1}}]}
    native_function_constant: <com.example.hellolibs.MainActivity: void IntStringLongBool(int,java.lang.String,long,boolean)>:1:"asdf"
    native_function_constant: <com.example.hellolibs.MainActivity: void IntStringLongBool(int,java.lang.String,long,boolean)>:2:2342L
    """
    output = {}
    if NO_CONSTANT_CONSTRAINTS:
        return output
    lines = content.split("\n")
    for l in lines:
        if l == '':
            continue
        isConstant = False
        if not "native_function_constant" in l:
            # TODO: handle the more fine grained object detection (probably not to be done in this file)
            continue
        l = l.split(":")
        if len(l) > 5:
            # maybe happens if there is a : in the string, just ignore
            continue
        index = int(l[3])
        value = l[4]
        # should be a regex...
        className = l[1][l[1].find("<")+1:]
        className = className.replace(".", "_")
        className = "Java_" + className
        fname = l[2][l[2].rfind(" ")+1: l[2].rfind("(")]
        fname = fname.replace("_", "_1")
        mangled_name = f"{className}_{fname}"
        # no support for choices, if a native function is called multiple times with the same parameter and different constant values, we choose 
        # the last value, will need to support a choices constraint TODO 
        if mangled_name not in output:
            output[mangled_name] = [{index: value}]
        else:
            if index in output[mangled_name][-1]:
                # the constraints are collected in order, once we hit a duplicate index we need to add another entry
                output[mangled_name].append({index: value})
            else:
                output[mangled_name][-1][index] = value
    return output


def parse_simple_argument_constraints_special(content):
    """
    parse the contents of the simple arguments file
    {"fname": [{0:"asdf}, {1}}]}
    native_function_constant: <com.example.hellolibs.MainActivity: void IntStringLongBool(int,java.lang.String,long,boolean)>:1:"asdf"
    native_function_constant: <com.example.hellolibs.MainActivity: void IntStringLongBool(int,java.lang.String,long,boolean)>:2:2342L
    """
    output = {}
    lines = content.split("\n")
    for l in lines:
        if l == '':
            continue
        if "[!] length dependency" in l:
            # [!] length dependency<com.yysdk.mobile.vpsdk.VPSDKNativeLibrary: int imPushVideo(int,long,int,int,int,byte[],int)>found a length dependency between: args[6] = len(args[5] 
            UCI_name = l[len("[!] length dependency"):l.find("found a length dependency between:")]
            className = UCI_name[1:UCI_name.find(":")]
            className = className.replace(".", "_")
            className = "Java_" + className
            fname = UCI_name[UCI_name.rfind(" ")+1: UCI_name.rfind("(")]
            fname = fname.replace("_", "_1")
            mangled_name = f"{className}_{fname}"
            out = re.findall(r"args\[(\d+)\] = len\(args\[(\d+)\]", l)
            byte_arg_ind = int(out[0][1])
            len_arg_ind = int(out[0][0])
            if byte_arg_ind > len_arg_ind:
                logging.debug(f"{mangled_name} {byte_arg_ind} > {len_arg_ind} skipping")
                continue
            if mangled_name in output:
                output[mangled_name].append({"type": "len", "byte_arg_ind": byte_arg_ind, "len_arg_ind": len_arg_ind})
            else:
                output[mangled_name] = [{"type": "len", "byte_arg_ind": byte_arg_ind, "len_arg_ind": len_arg_ind}]
        if "[!] filepath constraint" in l:
            # [!] filepath constraint<org.telegram.ui.Components.RLottieDrawable: long create(java.lang.String,java.lang.String,int,int,int[],boolean,int[],boolean,int)>found a filepath constraint for arg at index: 0
            UCI_name = l[len("[!] filepath constraint"):l.find("found a filepath constraint")]
            className = UCI_name[1:UCI_name.find(":")]
            className = className.replace(".", "_")
            className = "Java_" + className
            fname = UCI_name[UCI_name.rfind(" ")+1: UCI_name.rfind("(")]
            fname = fname.replace("_", "_1")
            mangled_name = f"{className}_{fname}"
            out = re.findall(r"found a filepath constraint for arg at index: (\d+)", l)
            filepath_ind = int(out[0][0])
            if mangled_name in output:
                output[mangled_name].append({"type": "filepath", "file_path_arg_ind": filepath_ind})
            else:
                output[mangled_name] = [{"type": "filepath", "file_path_arg_ind": filepath_ind}]
    return output


def parse_argument_constraints_GAPS(instr_json, fInfos):
    """
    parse the GAPS output to the used intermediate format
    """
    out = {}
    for fname in instr_json:
        if fname not in fInfos:
            logging.error(f'{fname} not in fInfos, was signatures_pattern extraction done with overlaoding')
            continue
        out[fname] = []
        print(fname)
        print(instr_json[fname])
        for constraint in instr_json[fname]:
            constr_out = {}
            parent = constraint["parent"]
            constr_out["parent"] = parse_androguard_fcall(parent)
            constr_out["constraints"] = []
            for key in constraint:
                print(key)
                param_ind = is_param_ind(key)
                print(param_ind)
                if param_ind is None:
                    continue
                if param_ind > len(fInfos[fname].args_list) -1 :
                    print(f'WTF {key} {param_ind} out of bounds for {fname} {fInfos[fname].args_list}')
                    exit(-1)
                constr = constraint[key]['constraint']
                ct_type = constr['type']
                print(f'parsing constraint: {constr}')
                logging.debug(f'parsing constraint: {constr} for param: {param_ind}')
                if ct_type == 'array length':
                    len_arg_ind = is_param_ind(constr["value"])
                    if len_arg_ind is None:
                        print(f'failed parsing param of array length arugment: {len_arg_ind} {constr}')
                        continue
                    constr_out["constraints"].append({'param_ind': param_ind, 'type': 'lenof', 'len_arg_ind': len_arg_ind})
                elif ct_type == 'constant':
                    if NO_CONSTANT_CONSTRAINTS:
                        continue
                    constr_out["constraints"].append({'param_ind': param_ind, 'type': 'constant', 'value': constr["value"]})
                elif ct_type == 'file path':
                    constr_out["constraints"].append({'param_ind': param_ind, 'type': 'filepath'})
                elif ct_type == 'java stdlib' or ct_type == 'current time millis':
                    constr_out["constraints"].append({'param_ind': param_ind, 'type': 'stdlib', 'java_func': constr["value"]})
                elif constr["type"] == "empty array":
                    if constr["value"] != "":
                        constr_out["constraints"].append({'param_ind': param_ind, 'type': 'empty_array', 'len': int(constr["value"])})
                    else:
                        constr_out["constraints"].append({'param_ind': param_ind, 'type': 'empty_array'})
                elif constr["type"] == "array":
                    print(constr["value"])
                    if constr["value"] == "":
                        print("skipping")
                        continue
                    constr_out["constraints"].append({'param_ind': param_ind, 'type': 'max_array_length', 'len': int(constr["value"])})
                #elif ct_type == 'byte buffer length': #@TODO not currently implemented
                #    if constr["value"] == "":
                #        continue
                #    constr_out["constraints"].append({'param_ind': param_ind, 'type': 'byte_buffer_lenght', 'len': int(constr["value"])})
                elif ct_type == 'equal arguments':
                    other_var_ind = is_param_ind(constr['value'])
                    if other_var_ind is None:
                        print(f'failed parsing param of equal arugment: {other_var_ind} {constr}')
                        exit(-1)
                    if param_ind > other_var_ind:
                        constr_out["constraints"].append({'param_ind': param_ind, 'type': 'same_var', 'var': other_var_ind})
                    else:
                        constr_out["constraints"].append({'param_ind': other_var_ind, 'type': 'same_var', 'var': param_ind})
                elif ct_type == 'other invoke':
                    constr_out["constraints"].append({'param_ind': param_ind, 'type': 'other_invoke', 'func': constr['value']})
                else:
                    continue
            if len(constr_out["constraints"]) == 0:
                continue
            if constr_out in out[fname]:
                continue
            out[fname].append(constr_out)
            logging.debug(f'appending {constr_out} as constraint for {fname}')
    return out
                

def parse_gaps_cs_callsequence(instr_json, fInfos):
    """
    parse the gaps constraints, look for the constraint 
    """
    out = {}
    for fname in instr_json:
        if fname not in fInfos:
            print(f'{fname} not in fInfos')
            logging.error(f'{fname} not in fInfos, was signatures_pattern extraction done with overlaoding')
            continue
        for constraint in instr_json[fname]:
            print(constraint)
            parent = constraint["parent"]
            for key in constraint:
                param_ind = is_param_ind(key)
                if param_ind is None:
                    continue
                if param_ind > len(fInfos[fname].args_list) -1 :
                    print(f'WTF {key} {param_ind} out of bounds for {fname} {fInfos[fname].args_list}')
                    exit(-1)
                constr = constraint[key]['constraint']
                ct_type = constr['type']
                logging.debug(f'parsing constraint: {constr} for param: {param_ind}')
                if ct_type == 'native call':
                    print("NATIVE CALL", constr)
                    native_fname = parse_androguard_fcall(constr["value"])
                    if native_fname not in fInfos:
                        print(f'native call dependency is not : {native_fname} {constr}')
                        continue
                    new_dep = {"parent" : parse_androguard_fcall(parent), 'native_fname': native_fname, 'param_ind': param_ind}
                    out[fname] = new_dep #right now we only use one value dependency cosntraint, who cares
                    print("AAAAAAAAAAAAAAAAAA", out[fname])
                    logging.debug(f'appending {out[fname]} as cs_io for {fname}')
    return out


                
def parse_callsequence_function_phenomenon(UCI_functionName):
    """
    goes from '$i0 = virtualinvoke $r8.<com.example.hellolibs.MainActivity: int addJNI(int)>($i0)' to com_example_hellolibs_MainAcitivty_addJNI
    also extracts the args as a list (smae as in fname2arguments)
    """
    rel_part = UCI_functionName[UCI_functionName.find("<")+1:UCI_functionName.rfind(">")]
    signature = rel_part[rel_part.find("(")+1:rel_part.find(")")]
    sig_types = signature.split(",")
    args = []
    if len(sig_types) == 1 and sig_types[0] == '':
        pass
    else:      
        for arg in sig_types:
            args.append({"type": arg.split(".")[-1]})
    logging.debug(f"parsing phenom constraint, args: {args}")
    fun_args = UCI_functionName[UCI_functionName.find(">")+1:]
    fun_args = fun_args[fun_args.find("(")+1:fun_args.find(")")]
    fun_args = fun_args.split(",")
    if fun_args == ['']:
        fun_args = []
    if len(fun_args) != len(args):
        logging.debug(f"FAILURE in parse phenom cs!!! , {fun_args}, {args}, {UCI_functionName}")
    else:
        if WITH_PHENOM_CONSTRAINTS:
            for i, arg_value in enumerate(fun_args):
                if args[i]["type"] == "String" and len(re.findall(r"\".*\"", arg_value)) == 1:
                    args[i]["constraints"] = {"equals": {"reason": "phenom_cs", "value": arg_value}}
                elif args[i]["type"] != "String" and len(re.findall(r"[a-z]\d+",arg_value)) == 0:
                    args[i]["constraints"] = {"equals": {"reason": "phenom_cs", "value": arg_value}}
                else:
                    continue
    logging.debug(f"parsing phenom constant values after contant values: {args}")
    className = rel_part.split(":")[0]
    className = className.replace(".", "_")
    fname = rel_part.split(":")[1]
    fname = fname[fname.rfind(" ")+1:fname.find("(")]
    fname = fname.replace("_", "_1")
    return "Java_" + className + "_" + fname, args


def get_sequence_upto_function(sequence, fname):
    # get the sequence up to a function 
    # the idea is that we don't want callsequences with repeating functions
    seq = []
    for entry in sequence:
        if fname == entry["fname"]:
            return seq
        else:
            seq.append(entry)
    return seq


def build_cs_list(f, cs_temp):
    cs = []
    for entry in cs_temp:
        nativeFunc = entry["fname"]
        if nativeFunc == f.fname:
            break
        if f.classname == get_classname(nativeFunc):
            cs.append(entry)
        if f.outer_classname == get_classname(nativeFunc):
            cs.append(entry)
    return cs


def build_cs_lc_list(f, native_lifecycle, fInfos):
    # buld a callsequence of native functions using the classname of f
    cs_lc = []
    for lcc in ["android.app.Activity", "android.app.Fragment", "android.app.Service", "android.content.ContentProvider"]:
        for act in native_lifecycle[lcc]:
            for lifecycleFn in ["onCreate", "onStart", "onResume", "onActivityCreated","onViewCreated", "onBind", "onStartCommand"]:
                if lifecycleFn in native_lifecycle[lcc][act]:
                    # iterate over the functions in the lifecycle and check the classname
                    for lc_f in native_lifecycle[lcc][act][lifecycleFn]:
                        if f.classname == get_classname(lc_f["fname"]) and lc_f["fname"] in fInfos:
                            cs_lc.append(lc_f)
    return cs_lc  


def check_in_cs(cs_1, cs_2):
    # check if any of the callers/functions in cs_1 are in cs_2
    # this is mainly used to check if the simple callsequences are interfering with the phenomenon ones
    for e1 in cs_1:
        for e2 in cs_2:
            if e1["caller"] == e2["caller"]:
                return True
            if e1["fname"] == e2["fname"]:
                return True
    return False


def check_in_cs_fname(fname, callsequnce):
    # check if funciton is in callsequnce, return index, return -1 if not found
    ind = -1
    for i, entry in enumerate(callsequnce):
        if fname == entry["fname"]:
            ind = i
            return ind
    return -1

def sublist(lst1, lst2):
    fnames1 = []
    fnames2 = []
    for f in lst1:
        fnames1.append(f["fname"])
    for f in lst2:
        fnames2.append(f["fname"]) 
    return set(fnames2) <= set(fnames1)


def merge_cs(cs_new, cs_ext):
    # merge two callsequences, such that [a,b,c,d], [c,d,e,f] becomes [a,b,c,d,e,f]
    f_slice = []
    for i1, f1 in enumerate(cs_new):
        if -1 ==  check_in_cs(f1["fname"], cs_ext):
            f_slice.append(f1)
        else:
            if sublist(cs_new[i1:], cs_ext):
                return f_slice + cs_ext
            else:
                f_slice.append(f1)
    return f_slice + cs_ext


def choose_better_to_fuzz_function(f1, f2):
    """
    Return the functionInfo of the function that is likely easier to fuzz
    Easier: byte[], byteBuffer, String argument
    Easier: less arguments
    """
    score_f1 = 0
    score_f2 = 0
    if "byte[]" in f1.args_list:
        score_f1 += 5
    if "ByteBuffer" in f1.args_list:
        score_f1 += 5
    if "String" in f1.args_list:
        score_f1 += 3
    if "byte[]" in f2.args_list:
        score_f2 += 5
    if "ByteBuffer" in f2.args_list:
        score_f2 += 5
    if "String" in f2.args_list:
        score_f2 += 3
    # subtract the nr of arguments from the score
    score_f1 -= len(f1.args_list)
    score_f2 -= len(f2.args_list)
    # if a long is in the argument list, deduct points
    if "long" in f1.args_list:
        score_f1 -= 4
    if "long" in f2.args_list:
        score_f2 -= 4
    # deduct point for generic object
    if "Object" in f1.args_list:
        score_f1 -= 10
    if "Object" in f2.args_list:
        score_f2 -= 10
    if score_f1 < score_f2:
        return f2
    if score_f2 > score_f1:
        return f1
    return f1


def get_constant_cpp_string(value, type):
    """
    from the value and type, creates the value that is inserted into the c++ code
    Since it is only used with the simple constraints and we only extract strings and numeric values this is only a stub, may be extended in the future
    """
    return value

def get_constant_cpp_string_GAPS(value, arg_type):
    if arg_type == 'float' or arg_type == 'double':
        return float_conversion(value, arg_type)
    if arg_type == "String" or arg_type == "string":
        return "\"" + value[2:-2] + "\""
    return value