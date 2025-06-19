import re


from typing import Tuple


def get_class_and_method(
    instruction: str, subclass: bool = False
) -> Tuple[str, str]:
    """parse an instruction to extract class name and method name"""
    class_name = ""
    method_name = ""
    if instruction and "const" not in instruction.split()[0]:
        if "->" in instruction:
            class_name = (
                instruction.split("->")[0].replace(";", "").split()[-1]
            )
            if "$" in class_name and not subclass:
                class_name = class_name.split("$")[0]
            method_name = instruction.split("->")[1].replace(";", "")
            if "(" in method_name:
                method_name = method_name.split("(")[0]
            else:
                method_name = method_name.split()[0]
    return class_name, method_name


def is_method(instr: str) -> re.Match:
    return re.search("L[\w/$]+;->[\w]+\((.*)\)", instr)


def extract_arguments(method_arg: str) -> list:
    i = 0
    args = []
    isArray = False
    while i < len(method_arg):
        # class or interface
        if method_arg[i] == "L":
            if method_arg[i - 1] == "[":
                isArray = True

            # check array
            if isArray:
                args.append(
                    "[L" + method_arg[i + 1 : method_arg.find(";")] + ";"
                )
                isArray = False
            else:
                args.append(method_arg[i + 1 : method_arg.find(";")])

            i = method_arg.find(";") + 1
            method_arg = method_arg.replace(";", " ", 1)

            continue

        # Int
        if method_arg[i] == "I":
            if method_arg[i - 1] == "[":
                isArray = True

            if isArray:
                args.append("int array")
                isArray = False
            else:
                args.append("int")

        # Boolean
        if method_arg[i] == "Z":
            if method_arg[i - 1] == "[":
                isArray = True

            if isArray:
                args.append("boolean array")
                isArray = False
            else:
                args.append("boolean")

        # Float
        if method_arg[i] == "F":
            if method_arg[i - 1] == "[":
                isArray = True

            if isArray:
                args.append("float array")
                isArray = False
            else:
                args.append("float")

        # Long
        if method_arg[i] == "J":
            if method_arg[i - 1] == "[":
                isArray = True

            if isArray:
                args.append("long array")
                isArray = False
            else:
                args.append("long")

        # Double
        if method_arg[i] == "D":
            if method_arg[i - 1] == "[":
                isArray = True

            if isArray:
                args.append("double array")
                isArray = False
            else:
                args.append("double")

        # Char
        if method_arg[i] == "C":
            if method_arg[i - 1] == "[":
                isArray = True

            if isArray:
                args.append("char array")
                isArray = False
            else:
                args.append("char")

        # Byte
        if method_arg[i] == "B":
            if method_arg[i - 1] == "[":
                isArray = True

            if isArray:
                args.append("byte array")
                isArray = False
            else:
                args.append("byte")

        # Short
        if method_arg[i] == "S":
            if method_arg[i - 1] == "[":
                isArray = True

            if isArray:
                args.append("short array")
                isArray = False
            else:
                args.append("short")

        i += 1

    return args


def extract_jni_mangled_arguments(method_arg: str) -> list:
    i = 0
    args = "__"
    no_underscore = True
    while i < len(method_arg):
        # class or interface
        if method_arg[i] == "L":
            if method_arg[i - 1] == "[":
                args += "_3"

            args += (
                method_arg[i]
                + method_arg[i + 1 : method_arg.find(";")].replace("/", "_")
                + "_2"
            )

            no_underscore = True

            i = method_arg.find(";") + 1
            method_arg = method_arg.replace(";", " ", 1)

            continue

        # Int
        if method_arg[i] == "I":
            if method_arg[i - 1] == "[":
                args += "_3"
            elif not no_underscore:
                no_underscore = False
                args += "_"

            args += method_arg[i]

        # Boolean
        if method_arg[i] == "Z":
            if method_arg[i - 1] == "[":
                args += "_3"
            elif not no_underscore:
                no_underscore = False
                args += "_"

            args += method_arg[i]

        # Float
        if method_arg[i] == "F":
            if method_arg[i - 1] == "[":
                args += "_3"
            elif not no_underscore:
                no_underscore = False
                args += "_"

            args += method_arg[i]

        # Long
        if method_arg[i] == "J":
            if method_arg[i - 1] == "[":
                args += "_3"
            elif not no_underscore:
                no_underscore = False
                args += "_"

            args += method_arg[i]

        # Double
        if method_arg[i] == "D":
            if method_arg[i - 1] == "[":
                args += "_3"
            elif not no_underscore:
                no_underscore = False
                args += "_"

            args += method_arg[i]

        # Char
        if method_arg[i] == "C":
            if method_arg[i - 1] == "[":
                args += "_3"
            elif not no_underscore:
                no_underscore = False
                args += "_"

            args += method_arg[i]

        # Byte
        if method_arg[i] == "B":
            if method_arg[i - 1] == "[":
                args += "_3"
            elif not no_underscore:
                no_underscore = False
                args += "_"

            args += method_arg[i]

        # Short
        if method_arg[i] == "S":
            if method_arg[i - 1] == "[":
                args += "_3"
            elif not no_underscore:
                no_underscore = False
                args += "_"

            args += method_arg[i]

        i += 1

    return args
