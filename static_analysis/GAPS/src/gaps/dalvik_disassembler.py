import subprocess
import logging
from androguard.core.analysis.analysis import MethodClassAnalysis
import os
import sys

###############################################################################
# LOGGING
###############################################################################

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)
# logging.basicConfig(level=logging.DEBUG)

###############################################################################
# CODE
###############################################################################


def _escape_backslash(x: str) -> str:
    return x.replace("\\", "\\\\")


def _escape_double_quote(x: str) -> str:
    return x.replace('"', '\\"')


def _process_instr_output(instr_output: str) -> str:
    instructions = instr_output.split(", ")
    # escape backslash
    instructions = list(map(_escape_backslash, instructions))
    # escape double quotes
    instructions = list(map(_escape_double_quote, instructions))
    return ", ".join(instructions)


def disassemble(gaps):
    incremental_offset = 0

    method: MethodClassAnalysis
    for method in gaps.dx.get_methods():
        if method.is_external():
            continue

        m = method.get_method()
        method_name = str(m)
        if "[access" in method_name:
            method_name = method_name.split("[access")[0].replace(" ", "")

        offset_method = incremental_offset
        for bb in method.get_basic_blocks():
            last_native_addr = -1
            offset_inst = bb.get_start() + offset_method
            if offset_inst > incremental_offset:
                incremental_offset = offset_inst
            instructions = list(bb.get_instructions())
            for inst in instructions[:-1]:
                gaps.instr_to_parent_method[offset_inst] = method_name
                inst_out = _process_instr_output(inst.get_output())
                if "(" in inst_out:
                    inst_out = inst_out.replace(" ", "").replace(",", ", ")
                str_inst = "{} {}".format(inst.get_name(), inst_out)
                # str_inst = resolve_access_methods(
                #    str_inst, gaps)
                next_inst_offset = offset_inst + inst.get_length()
                if next_inst_offset > incremental_offset:
                    incremental_offset = next_inst_offset
                # nodes
                gaps.addr_to_instr[offset_inst] = str_inst
                if "put" in str_inst.split()[0] and "->" in str_inst:
                    gaps.instructions_to_address[str_inst.split()[-2]].add(
                        offset_inst
                    )
                # pre-fetch starting point's addresses
                if "," in inst_out:
                    key = inst_out.split(",")[-1][1:]
                    if (
                        key in gaps.starting_points
                        and offset_inst > last_native_addr
                    ):
                        last_native_addr = offset_inst
                    else:
                        gaps.instructions_to_address[key].add(offset_inst)
                # edges
                # set for destination -> sources
                gaps.instr_cfg[next_inst_offset].add(offset_inst)
                offset_inst = next_inst_offset
            # multiple destinations ?
            last_inst = instructions[-1]
            # node
            inst_out = _process_instr_output(last_inst.get_output())
            if "(" in inst_out:
                inst_out = inst_out.replace(" ", "").replace(",", ", ")
            str_inst = "{} {}".format(last_inst.get_name(), inst_out)
            # str_inst = resolve_access_methods(str_inst, gaps)
            gaps.addr_to_instr[offset_inst] = str_inst
            gaps.instr_to_parent_method[offset_inst] = method_name
            # edges
            for child in bb.childs:
                child_offset = child[1] + offset_method
                if child_offset > incremental_offset:
                    incremental_offset = child_offset
                # set for destination -> sources
                gaps.instr_cfg[child_offset].add(offset_inst)
                gaps.instr_to_parent_method[child_offset] = method_name
            if last_native_addr != -1:
                gaps.native_addrs.add(last_native_addr)
            incremental_offset += 1


def run_apktool(gaps):
    LOG.debug(f"[+] STARTING APK DISASSEMBLY IN {gaps.tmp_path}")
    cmd = f"apktool d -f --no-assets {gaps.dalvik_path} -o {gaps.tmp_path}"
    if gaps.per_dex_analysis:
        cmd += " -s"
    subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if not os.path.exists(gaps.tmp_path):
        LOG.error("[-] ERROR IN DISASSEMBLY")
        sys.exit(0)
    LOG.debug(f"[+] DISASSEMBLED IN {gaps.tmp_path}")


def run_baksmali(gaps):
    LOG.debug(f"[+] STARTING DEX DISASSEMBLY IN {gaps.tmp_path}")
    subprocess.run(
        f"baksmali d {gaps.dalvik_path} -o {gaps.tmp_path}",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if not os.path.exists(gaps.tmp_path):
        LOG.error("[-] ERROR IN DISASSEMBLY")
        sys.exit(0)
    LOG.debug(f"[+] DISASSEMBLED IN {gaps.tmp_path}")
