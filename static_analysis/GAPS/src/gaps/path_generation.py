import logging
import re
import sys

from . import method_utils

###############################################################################
# LOGGING
###############################################################################

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)
logging.basicConfig(level=logging.INFO)

###############################################################################
# CODE
###############################################################################


def find_path_smali_native(
    target_method: str,
    gaps,
    target_class: str = None,
    target_instruction: str = None,
    starting_points: list = None,
) -> list:
    if len(target_method) == 0:
        return []

    # find starting points
    found = False
    if starting_points:
        found = True
    else:
        starting_points = set()
        if not target_instruction:
            for offset, instr in gaps.addr_to_instr.items():
                if target_method in instr:
                    (
                        class_name,
                        method_name,
                    ) = method_utils.get_class_and_method(instr, True)
                    if (
                        not target_class
                        or (target_class and class_name == target_class)
                    ) and method_name == target_method:
                        found = True
                        starting_points.add(offset)
        else:
            if target_instruction in gaps.instructions_to_address:
                starting_points = gaps.instructions_to_address[
                    target_instruction
                ]
                if len(starting_points) > 0:
                    found = True
    if not found:
        return []

    return _breadth_first_search_graph(gaps, starting_points)


def find_path_smali(
    target_method: str,
    gaps,
    target_class: str = None,
    target_instruction: str = None,
) -> list:
    search = ""
    if target_instruction:
        search = target_instruction
    elif target_class:
        search = f"{target_class};->{target_method}"
    else:
        search = f";->{target_method}"

    if "(" in search and search in gaps.search_list:
        return gaps.search_list[search]

    if search in gaps.requested:
        return []

    # find starting points
    found = False
    starting_points = set()
    if not target_instruction:
        for offset, instr in gaps.addr_to_instr.items():
            if target_method in instr:
                class_name, method_name = method_utils.get_class_and_method(
                    instr, True
                )
                # check if search needs to be performed in specific classes
                if (
                    not target_class
                    or (target_class and class_name == target_class)
                ) and method_name == target_method:
                    found = True
                    starting_points.add(offset)
    else:
        if target_instruction in gaps.instructions_to_address:
            starting_points = gaps.instructions_to_address[target_instruction]
            if len(starting_points) > 0:
                found = True

    if not found:
        return []

    return _breadth_first_search_graph(gaps, starting_points, search)


def _breadth_first_search_graph(
    gaps,
    starting_points: list,
    search: str = None,
) -> list:
    # set containing all the final paths
    dict_paths = {}

    max_path_len = gaps.path_len
    max_alternative_paths = gaps.tot_alt_paths
    for starting_point in starting_points:
        paths = []
        code_paths = []
        destination = starting_point
        # new path created
        paths.append([destination])
        code_paths.append([gaps.addr_to_instr[destination]])
        complete = False
        while not complete:
            main_path = False
            while destination in gaps.instr_cfg:
                list_destinations = list(gaps.instr_cfg[destination])
                # look for alternative paths
                main_path = False
                main_path_copy = paths[0].copy()
                code_path_copy = code_paths[0].copy()
                for i in range(len(list_destinations)):
                    if list_destinations[i] in paths[0]:
                        continue
                    if not main_path:
                        destination = list_destinations[0]
                        paths[0].append(destination)
                        instr = gaps.addr_to_instr[destination]
                        code_paths[0].append(instr)
                        main_path = True
                    elif max_alternative_paths > 0:
                        max_alternative_paths -= 1
                        new_path = main_path_copy.copy()
                        new_path.append(list_destinations[i])
                        paths.append(new_path)
                        new_code_paths = code_path_copy.copy()
                        instr = gaps.addr_to_instr[list_destinations[i]]
                        new_code_paths.append(instr)
                        code_paths.append(new_code_paths)
                if len(code_paths[0]) > max_path_len or not main_path:
                    break
            code_paths[0].append(gaps.instr_to_parent_method[starting_point])
            if destination not in dict_paths:
                dict_paths[destination] = set()
            dict_paths[destination].add(tuple(code_paths[0]))
            code_paths.pop(0)
            paths.pop(0)
            # if there are other copied paths to explore
            if len(paths) > 0:
                destination = paths[0][len(paths[0]) - 1]
            else:
                complete = True
    deepest = sys.maxsize
    for distance in dict_paths:
        if deepest > distance:
            deepest = distance
    if deepest == sys.maxsize:
        return []
    list_paths = list(dict_paths[deepest])
    if search:
        gaps.requested.add(search)
        if "(" in search:
            gaps.search_list[search] = list_paths
    return list_paths


def print_paths(paths: list, down: bool = False):
    """print paths"""
    if paths:
        print(f"[+] PATHS FOUND: {len(paths)}")
        atm = 0
        for path in paths:
            print(f"[+] PATH {atm}")
            i = len(path) - 1
            for j in range(len(path)):
                print(f"{i}| {path[j]}")
                if j != len(path) - 1:
                    if not down:
                        print("\t↑")
                    else:
                        print("\t↓")
                i -= 1
            print()
            atm += 1


def generate_instructions(partial_paths: list, gaps):
    json_data = {}
    native_call_params_seen = []
    return_values_seen = []
    gaps.search_list = {}
    partial_paths.sort(key=len)
    for partial_path in partial_paths:
        for index, node in enumerate(partial_path):
            if (
                "invoke" in node.split()[0]
                and node.split()[-1] in gaps.starting_points
            ):
                jni_mangled = _get_jni_mangled_name(node, gaps)
                if jni_mangled not in json_data:
                    json_data[jni_mangled] = []
                method_args = node.split("(")[1].split(")")[0]
                out_params = {}
                gaps.parent_method = partial_path[len(partial_path) - 1]
                out_params["parent"] = gaps.parent_method
                if len(method_args) != 0:
                    regs_list = _get_registers(node, ignore_caller=True)
                    args_list = method_utils.extract_arguments(method_args)
                    reg_args_map = _generate_reg_args_map(regs_list, args_list)
                    native_call_params = _find_register_parameter_assignment(
                        partial_path, index, ignore_caller=True
                    )
                    missing_regs = []
                    for reg in regs_list:
                        if reg not in native_call_params or (
                            reg in native_call_params
                            and "instruction" not in native_call_params[reg]
                        ):
                            missing_regs.append(reg)
                    if len(missing_regs) > 0 and gaps.inter_procedural:
                        result = {}
                        gaps.layers = 0
                        _find_interprocedural(
                            result,
                            gaps,
                            gaps.parent_method,
                            missing_regs,
                        )
                        for reg in result:
                            if reg not in native_call_params:
                                native_call_params[reg] = result[reg][0]
                                if len(result[reg]) > 1:
                                    for new_result in range(
                                        1, len(result[reg])
                                    ):
                                        copy_native_call_params = (
                                            native_call_params.copy()
                                        )
                                        copy_native_call_params[reg] = result[
                                            reg
                                        ][new_result]
                                        if (
                                            copy_native_call_params
                                            not in native_call_params_seen
                                        ):
                                            gaps.requested = set()
                                            native_call_params_seen.append(
                                                copy_native_call_params
                                            )
                                            _analyse_native_call_params(
                                                gaps,
                                                copy_native_call_params,
                                                regs_list,
                                                reg_args_map,
                                                out_params,
                                                partial_path,
                                                json_data,
                                                jni_mangled,
                                            )
                        gaps.requested = set()
                        native_call_params_seen.append(native_call_params)
                        _analyse_native_call_params(
                            gaps,
                            native_call_params,
                            regs_list,
                            reg_args_map,
                            out_params,
                            partial_path,
                            json_data,
                            jni_mangled,
                        )
                    elif native_call_params not in native_call_params_seen:
                        gaps.requested = set()
                        native_call_params_seen.append(native_call_params)
                        _analyse_native_call_params(
                            gaps,
                            native_call_params,
                            regs_list,
                            reg_args_map,
                            out_params,
                            partial_path,
                            json_data,
                            jni_mangled,
                        )
                return_values = None
                if (
                    node[len(node) - 1] != "V"
                    and index - 1 > 0
                    and "move-result" in partial_path[index - 1].split()[0]
                ):
                    return_paths = partial_path[:index][::-1]
                    return_values = _find_return_value_assignment(
                        return_paths, 0
                    )
                if return_values and return_values not in return_values_seen:
                    return_values_seen.append(return_values)
                    for return_value in return_values:
                        if (
                            "invoke" in return_value.split()[0]
                            and return_value.split()[-1]
                            in gaps.starting_points
                        ):
                            out_params["return-value"] = return_value.split()[
                                -1
                            ]
                if len(out_params) > 1:
                    json_data[jni_mangled].append(out_params)
                elif len(json_data[jni_mangled]) == 0:
                    json_data.pop(jni_mangled)
    _save_json_data(gaps, json_data)


def _find_interprocedural(result: dict, gaps, parent: str, missing_regs: list):
    parents_seen = []
    (
        parent_class,
        parent_method,
    ) = method_utils.get_class_and_method(parent, True)
    parent_calls = find_path_smali(
        parent_method,
        gaps,
        target_class=parent_class,
        target_instruction=parent,
    )
    if len(parent_calls) > 0:
        for parent_call in parent_calls:
            parent_regs_list = _get_registers(
                parent_call[0],
                ignore_caller=True,
            )
            analyze = False
            for reg in parent_regs_list:
                if reg in missing_regs:
                    analyze = True
                    break
            if analyze:
                parent_call_params = _find_register_parameter_assignment(
                    parent_call, 0, ignore_caller=True
                )
                for reg in parent_call_params:
                    if reg in missing_regs:
                        if reg not in result:
                            result[reg] = []
                        result[reg].append(parent_call_params[reg])
                new_parent = parent_call[len(parent_call) - 1]
                if gaps.layers < 3 and new_parent not in parents_seen:
                    parents_seen.append(new_parent)
                    (
                        new_parent_class,
                        new_parent_method,
                    ) = method_utils.get_class_and_method(new_parent, True)
                    new_parent_calls = find_path_smali(
                        new_parent_method,
                        gaps,
                        target_class=new_parent_class,
                        target_instruction=new_parent,
                    )
                    parent_calls += new_parent_calls
                    gaps.layers += 1


def _generate_reg_args_map(regs_list: list, args_list: list) -> dict:
    reg_args_map = {}
    i = 0
    j = 0
    while i < len(regs_list):
        reg = regs_list[i]
        if j > len(args_list) - 1:
            # amount of registers > number of parameters
            reg_args_map[reg] = "?"
        else:
            reg_args_map[reg] = args_list[j]
            if args_list[j] == "long" or args_list[j] == "double":
                next_reg = regs_list[i + 1]
                reg_args_map[next_reg] = reg
                regs_list.remove(next_reg)

            j += 1
        i += 1
    return reg_args_map


def _get_jni_mangled_name(node: str, gaps) -> str:
    jni_mangled = (
        node.split()[-1][1:]
        .replace("_", "_1")
        .replace("/", "_")
        .replace(";->", "_")
        .split("(")[0]
    )
    jni_mangled = "Java_" + jni_mangled
    node_class, node_method = method_utils.get_class_and_method(node)
    node_method_args = node.split("(")[1].split(")")[0]
    overload = False
    for native_call in gaps.starting_points:
        native_class, native_method = method_utils.get_class_and_method(
            native_call
        )
        native_method_args = native_call.split("(")[1].split(")")[0]
        if (
            node_class == native_class
            and native_method == node_method
            and node_method_args != native_method_args
        ):
            overload = True
            break

    if overload:
        mangled_args_list = method_utils.extract_jni_mangled_arguments(
            node_method_args
        )
        jni_mangled = jni_mangled + mangled_args_list
    return jni_mangled


def _analyse_native_call_params(
    gaps,
    native_call_params: list,
    regs_list: list,
    reg_args_map: dict,
    out_params: dict,
    partial_path: list,
    json_data: dict,
    jni_mangled: str,
) -> bool:
    for i, reg in enumerate(native_call_params):
        original_reg = reg
        if reg not in regs_list and reg in reg_args_map:
            if reg_args_map[reg] in reg_args_map:
                reg = reg_args_map[reg]
        if reg in regs_list:
            if "instruction" in native_call_params[reg]:
                native_call_param = native_call_params[reg]["instruction"]
                if native_call_param in gaps.search_list:
                    _get_results_search_list(
                        gaps,
                        native_call_param,
                        native_call_params,
                        regs_list,
                        reg_args_map,
                        out_params,
                        partial_path,
                        json_data,
                        jni_mangled,
                        original_reg,
                        reg,
                    )
                    continue
                elif (
                    "get" in native_call_param.split()[0]
                    and "->" in native_call_param.split()[-2]
                ):
                    result = {}
                    _resolve_var_assignment(native_call_param, gaps, result)
                    if len(result) > 0:
                        gaps.search_list[native_call_param] = result
                        _get_results_search_list(
                            gaps,
                            native_call_param,
                            native_call_params,
                            regs_list,
                            reg_args_map,
                            out_params,
                            partial_path,
                            json_data,
                            jni_mangled,
                            original_reg,
                            reg,
                        )
                        continue
                else:
                    _classify_constraint(
                        gaps,
                        native_call_param,
                        native_call_params,
                        original_reg,
                        reg,
                        regs_list,
                        reg_args_map,
                        out_params,
                        partial_path,
                    )


def _get_results_search_list(
    gaps,
    native_call_param: str,
    native_call_params: list,
    regs_list: list,
    reg_args_map: dict,
    out_params: dict,
    partial_path: list,
    json_data: dict,
    jni_mangled: str,
    original_reg: str,
    reg: str,
) -> bool:
    if gaps.parent_method in gaps.search_list[native_call_param]:
        res = gaps.search_list[native_call_param][gaps.parent_method]
    else:
        res = list(gaps.search_list[native_call_param].values())
    for i, instruction in enumerate(res):
        if type(instruction) is list:
            instruction = instruction[0]
        if i == 0:
            _classify_constraint(
                gaps,
                instruction,
                native_call_params,
                original_reg,
                reg,
                regs_list,
                reg_args_map,
                out_params,
                partial_path,
            )
        else:
            copy_out_params = out_params.copy()
            _classify_constraint(
                gaps,
                instruction,
                native_call_params,
                original_reg,
                reg,
                regs_list,
                reg_args_map,
                copy_out_params,
                partial_path,
            )
            if len(copy_out_params) > 1:
                json_data[jni_mangled].append(copy_out_params)
                _save_json_data(gaps, json_data)
                json_data[jni_mangled] = []


def _classify_constraint(
    gaps,
    instruction: str,
    native_call_params: list,
    original_reg: str,
    reg: str,
    regs_list: list,
    reg_args_map: dict,
    out_params: dict,
    partial_path: list,
) -> bool:
    file_path_signatures = [
        "Ljava/io/File;->getAbsolutePath()Ljava/lang/String;",
        "Ljava/io/File;->getPath()Ljava/lang/String;",
        "Ljava/io/File;->getCanonicalpath()Ljava/lang/String;",
    ]
    byte_buffer_length = [
        "Ljava/nio/ByteBuffer;->capacity()I",
        "Ljava/nio/ByteBuffer;->remaining()I",
    ]
    current_time_millis = "Ljava/lang/System;->currentTimeMillis()J"
    if "const" in instruction.split()[0]:
        value = _get_const_value(instruction)
        if '\\"' in instruction:
            string_start = instruction.index('\\"')
            value = instruction[string_start:]
        type_ = "constant"
        if "array" in reg_args_map[original_reg]:
            empty = True
            if "additional_instructions" in native_call_params[original_reg]:
                for additional_instruction in native_call_params[original_reg][
                    "additional_instructions"
                ]:
                    if "invoke" in additional_instruction.split()[0]:
                        empty = False
            if empty:
                type_ = "empty array"
                _add_type_value_json(
                    out_params,
                    _find_indices(regs_list, reg),
                    type_,
                    value,
                )
        else:
            _add_type_value_json(
                out_params,
                _find_indices(regs_list, reg),
                type_,
                value,
            )
    elif "invoke" in instruction.split()[0]:
        method_signature = instruction.split()[-1]
        if method_signature in file_path_signatures:
            _add_type_value_json(
                out_params,
                _find_indices(regs_list, reg),
                "file path",
                method_signature,
            )

        elif method_signature in byte_buffer_length:
            _add_type_value_json(
                out_params,
                _find_indices(regs_list, reg),
                "byte buffer length",
                method_signature,
            )

        elif method_signature == current_time_millis:
            _add_type_value_json(
                out_params,
                _find_indices(regs_list, reg),
                "current time millis",
                method_signature,
            )

        elif method_signature.startswith("Ljava/lang"):
            _add_type_value_json(
                out_params,
                _find_indices(regs_list, reg),
                "java stdlib",
                method_signature,
            )

        elif method_signature in gaps.starting_points:
            _add_type_value_json(
                out_params,
                _find_indices(regs_list, reg),
                "native call",
                method_signature,
            )

        else:
            _add_type_value_json(
                out_params,
                _find_indices(regs_list, reg),
                "other invoke",
                method_signature,
            )

    elif "array-length" in instruction.split()[0]:
        array_reg = instruction.split()[-1]
        if array_reg in regs_list:
            array_param = reg_args_map[array_reg]
            if array_param[0] == "v":
                array_reg = array_param
                array_param = reg_args_map[array_reg]
            param_index = regs_list.index(array_reg)
            _add_type_value_json(
                out_params,
                _find_indices(regs_list, reg),
                "array length",
                f"param-{param_index}",
            )

        else:
            _add_type_value_json(
                out_params,
                _find_indices(regs_list, reg),
                "array length",
                "",
            )

    elif "new-array" in instruction.split()[0]:
        empty = True
        value = "unknown"
        if "additional_instructions" in native_call_params[original_reg]:
            for additional_instruction in native_call_params[original_reg][
                "additional_instructions"
            ]:
                if (
                    "invoke" in additional_instruction.split()[0]
                    or "put" in additional_instruction.split()[0]
                    or "fill-array-data" in additional_instruction.split()[0]
                ):
                    empty = False
        if empty:
            type_array = "empty array"
        else:
            type_array = "array"
        length_infos = _find_register_parameter_assignment(
            partial_path,
            native_call_params[original_reg]["instruction_index"],
        )
        regs = _get_registers(instruction)
        if len(regs) > 1:
            reg_len = regs[1]
            if reg_len in length_infos:
                if "instruction" in length_infos[reg_len]:
                    length_info = length_infos[reg_len]["instruction"]
                    if "const" in length_info.split()[0] and re.search(
                        "\d+", length_info.split()[-1]
                    ):
                        value = _get_const_value(length_info)
                        _add_type_value_json(
                            out_params,
                            _find_indices(regs_list, reg),
                            type_array,
                            value,
                        )

                    elif (
                        "get" in length_info.split()[0]
                        and "->" in length_info.split()[-2]
                    ):
                        result = {}
                        _resolve_var_assignment(length_info, gaps, result)
                        gaps.search_list[instruction] = result
                        if gaps.parent_method in result:
                            values = result[gaps.parent_method]
                        else:
                            values = list(result.values())
                        for res in values:
                            if type(res) is list:
                                res = res[0]
                            if "const" in res.split()[0] and re.search(
                                "\d+", res.split()[-1]
                            ):
                                value = _get_const_value(res)
                                _add_type_value_json(
                                    out_params,
                                    _find_indices(regs_list, reg),
                                    type_array,
                                    value,
                                )
                    else:
                        _add_type_value_json(
                            out_params,
                            _find_indices(regs_list, reg),
                            type_array,
                            "",
                        )


def _get_const_value(instruction):
    split_instructions = instruction.split()
    return " ".join(split_instructions[2:])


def _add_type_value_json(
    out_params: dict, params_index: list, type_constraint: str, value: str
):
    out_params[f"param-{params_index[0]}"] = {}
    out_params[f"param-{params_index[0]}"]["constraint"] = {}
    out_params[f"param-{params_index[0]}"]["constraint"][
        "type"
    ] = type_constraint
    out_params[f"param-{params_index[0]}"]["constraint"]["value"] = value
    if len(params_index) > 1:
        for i in range(1, len(params_index)):
            out_params[f"param-{params_index[i]}"] = {}
            out_params[f"param-{params_index[i]}"]["constraint"] = {}
            out_params[f"param-{params_index[i]}"]["constraint"][
                "type"
            ] = "equal constraint"
            out_params[f"param-{params_index[i]}"]["constraint"][
                "value"
            ] = f"param-{params_index[0]}"


def _save_json_data(gaps, json_data: dict):
    for call in json_data:
        for arg_value in json_data[call]:
            if call not in gaps.json_output:
                gaps.json_output[call] = []
            if arg_value not in gaps.json_output[call]:
                gaps.stats_row[4] += 1
                gaps.json_output[call].append(arg_value)


def _resolve_var_assignment(var_instr: str, gaps, result: list):
    class_name, var_name = method_utils.get_class_and_method(var_instr, True)
    var_paths = find_path_smali(
        var_name,
        gaps,
        target_class=class_name,
        target_instruction=var_instr.split()[-2],
    )
    for var_path in var_paths:
        value_from = _find_register_parameter_assignment(
            var_path, 0, only_caller=True
        )
        if len(value_from) > 0:
            for reg in value_from:
                if "instruction" in value_from[reg]:
                    instruction = value_from[reg]["instruction"]
                    if (
                        "get" in instruction.split()[0]
                    ) and "->" in instruction.split()[-2]:
                        _resolve_var_assignment(instruction, gaps, result)
                    elif (
                        "const" in instruction.split()[0]
                        or "array-length" in instruction.split()[0]
                        or "invoke" in instruction.split()[0]
                    ) and instruction not in result:
                        if var_path[len(var_path) - 1] not in result:
                            result[var_path[len(var_path) - 1]] = []
                        result[var_path[len(var_path) - 1]].append(instruction)


def _find_register_parameter_assignment(
    path: list,
    start_from: int,
    ignore_caller: bool = False,
    only_caller: bool = False,
    no_return: bool = False,
) -> dict:
    if ignore_caller and only_caller:
        LOG.error("bad call - either keep or remove the caller")
        return {}
    const_instr, instr_index = None, -1
    res = {}
    if start_from < 0 or start_from > len(path) - 1:
        return res
    instr = path[start_from]
    registers = list(
        set(_get_registers(instr, ignore_caller, only_caller, no_return))
    )
    path_as_string = ""
    for i in range(start_from + 1, len(path)):
        path_as_string += path[i] + " "
    for reg in registers:
        if path_as_string.find(reg) == -1:
            registers.remove(reg)
    if len(registers) == 0:
        return res
    original_registers = registers.copy()
    to_translate = {}
    for i in range(start_from + 1, len(path)):
        if len(path[i].split()) > 0:
            instr = path[i].split()[0]
        else:
            instr = path[i]
        to_remove = None
        instr_reg = _get_registers(path[i])
        for register in instr_reg:
            if register in registers:
                to_remove = None
                const_instr = None
                if "move-result" in instr:
                    if (
                        "get" in path[i + 1].split()[0]
                        or "invoke" in path[i + 1].split()[0]
                    ) and "this$" not in path[i + 1]:
                        const_instr = path[i + 1]
                        instr_index = i + 1
                        to_remove = register
                elif (
                    "move" in instr or "-to-" in instr
                ) and register == instr_reg[0]:
                    if register != instr_reg[len(instr_reg) - 1]:
                        registers.append(instr_reg[len(instr_reg) - 1])
                        to_remove = register
                        if register not in to_translate:
                            to_translate[
                                instr_reg[len(instr_reg) - 1]
                            ] = instr_reg[0]
                        else:
                            old_reg = to_translate[register]
                            to_translate[
                                instr_reg[len(instr_reg) - 1]
                            ] = old_reg
                            to_translate.pop(register)
                elif (
                    (
                        "const" in instr
                        or "get" in instr
                        or "new" in instr
                        or "array-length" in instr
                        or "mul" in instr
                        or "add" in instr
                        or "sub" in instr
                        or "div" in instr
                        or "rem" in instr
                        or "and" in instr
                        or "or" in instr
                        or "xor" in instr
                        or "shl" in instr
                        or "shr" in instr
                    )
                    and register == instr_reg[0]
                ) and "this$" not in path[i]:
                    const_instr = path[i]
                    instr_index = i
                    to_remove = register
                    if "array-length" in instr:
                        if (
                            instr_reg[len(instr_reg) - 1]
                            not in original_registers
                            and instr_reg[len(instr_reg) - 1] in to_translate
                        ):
                            const_instr = const_instr.replace(
                                instr_reg[len(instr_reg) - 1],
                                to_translate[instr_reg[len(instr_reg) - 1]],
                            )
                elif "return" in instr:
                    const_instr = path[i]
                    instr_index = i
                    to_remove = register
                elif (
                    register == instr_reg[0]
                    and "put" not in instr
                    and "monitor-enter" not in instr
                    and "check-cast" not in instr
                    and "instance-of" not in instr
                    and "fill" not in instr
                    and "throw" not in instr
                    and "switch" not in instr
                    and "cmp" not in instr
                    and "if" not in instr
                    and "invoke" not in instr
                ):
                    const_instr = path[i]
                    instr_index = i
                    to_remove = register
                else:
                    const_instr = path[i]
                if const_instr:
                    reg = register
                    if reg in to_translate:
                        reg = to_translate[reg]
                    if reg not in res:
                        res[reg] = {}
                    if to_remove:
                        res[reg]["instruction"] = const_instr
                        res[reg]["instruction_index"] = instr_index
                    else:
                        if "additional_instructions" not in res[reg]:
                            res[reg]["additional_instructions"] = []
                        res[reg]["additional_instructions"].append(const_instr)
                if to_remove and to_remove in registers:
                    registers.remove(to_remove)

            if len(registers) == 0:
                break
    return res


def _find_return_value_assignment(path: list, start_from: int) -> dict:
    const_instr = None
    res = []
    instr = path[start_from]
    registers = _get_registers(instr)
    if len(registers) == 0:
        return {}, -1
    to_translate = {}
    for i in range(start_from + 1, len(path)):
        if len(path[i].split()) > 0:
            instr = path[i].split()[0]
        else:
            instr = path[i]
        if "return-void" == instr:
            return res, -1
        to_remove = None
        instr_reg = _get_registers(path[i])
        for register in instr_reg:
            if register in registers:
                const_instr = None
                if "move-result" in instr:
                    if i - 1 > 0:
                        const_instr = path[i - 1]
                        to_remove = register
                elif "move" in instr and register == instr_reg[0]:
                    if register != instr_reg[len(instr_reg) - 1]:
                        registers.append(instr_reg[len(instr_reg) - 1])
                        to_remove = register
                        to_translate[
                            instr_reg[len(instr_reg) - 1]
                        ] = instr_reg[0]
                elif (
                    (
                        "const" in instr
                        or "get" in instr
                        or "new" in instr
                        or "array-length" in instr
                    )
                    and register == instr_reg[0]
                ) and "this$" not in path[i]:
                    const_instr = path[i]
                    to_remove = register
                elif "return" in instr:
                    const_instr = path[i]
                    to_remove = register
                elif "invoke" in instr:
                    const_instr = path[i]
                if to_remove and to_remove in registers:
                    registers.remove(to_remove)
                if const_instr and const_instr not in res:
                    res.append(const_instr)
            if len(registers) == 0:
                break
    return res


def _get_registers(
    instr: str,
    ignore_caller: bool = False,
    only_caller: bool = False,
    no_return: bool = False,
) -> list:
    if "->" in instr:
        class_name, variable_name = method_utils.get_class_and_method(instr)
        if class_name.strip():
            splits = instr.split(class_name)[0].split()
        else:
            splits = []
    elif "," not in instr:
        splits = instr.split()
        if len(splits) > 1:
            res = []
            res.append(splits[-1])
            return res
    else:
        splits = instr.split()
    registers = []
    for split in splits:
        if "," in split:
            register = split.split(",")[0]
            if "p" in register:
                register = register.replace("p", "v")
            if "..." in register:
                first_reg_val = register.split("...")[0].replace("v", "")
                last_reg_val = register.split("...")[1].replace("v", "")
                if len(first_reg_val) > 0 and len(last_reg_val) > 0:
                    for i in range(int(first_reg_val), int(last_reg_val) + 1):
                        registers.append("v" + str(i))
            else:
                registers.append(register)
        elif "v" == split[0]:
            registers.append(split)
    if ")" in instr and "(" in instr and len(registers) > 0 and no_return:
        method_arg = instr.split("(")[1].split(")")[0]
        args_list = method_utils.extract_arguments(method_arg)
        method_ret_type = instr.split(")")[1].split("\n")[0]
        if method_ret_type != "V" and len(registers) > len(args_list):
            registers.pop(len(registers) - 1)
    if ignore_caller and "invoke-static" not in instr.split()[0]:
        registers = registers[1:]
    if not only_caller:
        return registers
    return [registers[0]]


def _find_indices(list_to_check, item_to_find):
    indices = []
    for idx, value in enumerate(list_to_check):
        if value == item_to_find:
            indices.append(idx)
    return indices
