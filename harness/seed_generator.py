"""
Automatic seed generation based on output of static dalvik app analysis
v0.1: function signature
v0.2: function signature + constraints on arguments
v0.3: function with a callsequence
"""

import os
import random
import string
from lib.define import *
from lib.utils import get_fuzz_needed_type


random.seed(1234)


def random_bytes_length(length):
    """
    generate random bytes of a certain length
    """

    return random.randbytes(length)


def random_bytes_length_LV():
    """
    generate random bytes with LV encoding
    """
    #len_bytes = random.randbytes(GENERIC_SIZE_BYTES)
    #length = int.from_bytes(len_bytes, 'little')
    length = random.randrange(0, 2**(8*GENERIC_SIZE_BYTES))
    len_bytes = length.to_bytes(NR_LV_SIZE_BYTES, 'little')
    data_bytes = random.randbytes(length)
    return len_bytes + data_bytes


def random_bytes_printable_LV():
    """
    generate random printable bytes with LV encoding
    """
    #len_bytes = random.randbytes(GENERIC_SIZE_BYTES)
    #length = int.from_bytes(len_bytes, 'little')
    length = random.randrange(0, 2**(8*GENERIC_SIZE_BYTES))
    len_bytes = length.to_bytes(NR_LV_SIZE_BYTES, 'little')
    data_bytes = b""
    for i in range(0, length):
        data_bytes += bytes([random.randrange(32, 127)])
    return len_bytes + data_bytes


def gen_seed_generic(seed_gen_list, LV=True):
    """
    given a list of arguments {"type:": "..", [constraints]}
    generates some seeds that adhere to the input structure
    """
    seed = b""
    for i, arg in enumerate(seed_gen_list):
        arg_type = arg["type"]
        LV_needed = arg["LV"]
        if arg_type in TYPE2SIZE:
            seed += random_bytes_length(TYPE2SIZE[arg_type]) 
        else:
            # handle case for variable-length types
            if LV_needed:
                seed += random_bytes_length_LV()  
            else:
                # if we have to generate random bytes don't make them too large
                seed += random_bytes_length(random.randrange(0, 2**(8*GENERIC_SIZE_BYTES)))
    return seed


def gen_seed_file(seed_gen_list, f_bytes):
    """
    given a list of arguments {"type:": "..", [constraints]}
    generates some seeds that adhere to the input structure
    use the f_bytes to fill byte[] or bytebuffer arguments
    TODO: also use file bytes if constraint is filepath or filedescriptor
    """
    seed = b""
    #TODO: Constraints
    bytes_found = False
    for i, arg in enumerate(seed_gen_list):
        arg_type = arg["type"]
        LV_needed = arg["LV"]
        if arg_type == 'jlong':
            # not fuzzing jlong
            seed += 8 * b"\x00"
            continue
        if arg_type in TYPE2SIZE:
            seed += random_bytes_length(TYPE2SIZE[arg_type])
        elif arg_type == 'jbyteArray' or arg_type == 'ByteBuffer':
            bytes_found = True
            #if input some bytes, 
            if LV_needed:
                seed += len(f_bytes).to_bytes(NR_LV_SIZE_BYTES, 'little') 
                seed += f_bytes
            else:
                seed += f_bytes             
        else:
            # handle case for variable-length types
            if LV_needed:
                seed += random_bytes_length_LV() 
            else:
                seed += random_bytes_length(random.randrange(0, 2**(8*GENERIC_SIZE_BYTES)))
    if bytes_found:
        return seed
    else:
        return None


def gen_file_seeds(seed_gen_list):
    """
    given a list of arguments, generates some seeds that adhere to the structure, filling byte types with the data from well-formed file types 
    """
    output = []
    for file_type in os.listdir("./file_seeds"):
        for f in os.listdir(f"./file_seeds/{file_type}"):
            f_bytes = open(f"./file_seeds/{file_type}/{f}", "rb").read()
            seed = gen_seed_file(seed_gen_list, f_bytes)
            if seed is not None:
                output.append((file_type, seed))
    return output


def gen_seeds(arguments):
    """
    generates a bunch of seeds
    for bytearrays/bytebuffer types, will use some common file types to seed it
    """
    output_seeds = []
    overall_args, LV_args, seed_gen_list = get_nr_arguments_to_fuzz(arguments)
    for i in range(NR_SEEDS):
        output_seeds.append(("generic", gen_seed_generic(seed_gen_list)))
    if FILE_SEEDS:
        file_seeds = gen_file_seeds(seed_gen_list)
        output_seeds += file_seeds
    return output_seeds, {"overall": overall_args, "LV": LV_args}, seed_gen_list
    

def get_nr_arguments_to_fuzz(arguments):
    # count the number of arguments that need to be fuzzed, (overall, LV-args)
    overall_args = 0
    LV_args = 0
    seed_gen_list = []
    for i, arg in enumerate(arguments):
        tofuzz, arg_type = get_fuzz_needed_type(arg)
        if not tofuzz:
            continue
        if arg_type == "jobject":
            continue
        if arg_type in TYPE2SIZE:
            overall_args += 1
            seed_gen_list.append({"type": arg_type, "LV": False})
        else:
            # handle case for variable-length types
            if i == len(arguments)-1:
                # if we have to generate random bytes don't make them too large
                overall_args += 1
                seed_gen_list.append({"type": arg_type, "LV": False})
            else:
                LV_args += 1
                overall_args += 1
                seed_gen_list.append({"type": arg_type, "LV": False})
    return overall_args, LV_args, seed_gen_list
