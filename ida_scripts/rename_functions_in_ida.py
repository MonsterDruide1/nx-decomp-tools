# Renames functions in an IDA database to match the function names
# in the decompiled source code.

import ida_name
from pathlib import Path

from ida_util import FunctionStatus, get_status_color, get_repo_root, RGB_BGR

class Function:
    def __init__(self, offset: int, status: FunctionStatus, size: int, name: str):
        self.offset = offset
        self.status = status
        self.size = size
        self.name = name

class File:
    def __init__(self, name: str, functions: list[Function]):
        self.name = name
        self.functions = functions

def parse_file_list(file_list_lines: list[str]) -> dict[str, File]:
    files = {}
    current_object_name = ""
    current_functions = []
    current_offset = 0
    current_size = 0
    current_label = ""
    for i, line_ in enumerate(file_list_lines):
        line = line_.strip()
        if not line_.startswith("  "):
            if len(current_functions) > 0:
                if current_object_name in files:
                    files[current_object_name].functions += current_functions
                else:
                    files[current_object_name] = File(current_object_name, current_functions)
                current_functions = []
            current_object_name = line.strip(":")
        if "offset:" in line:
            current_offset = int(line.split(" ")[-1], 16)
        if "size:" in line:
            current_size = int(line.split(" ")[-1])
        elif "label:" in line:
            # Get first element if label is a string array
            if "-" in file_list_lines[i + 1]:
                current_label = file_list_lines[i + 1].split(" ")[-1].strip()
            else:
                current_label = line.split(" ")[-1]
        elif "status:" in line:
            status_str = line.split(" ")[-1]
            status = FunctionStatus[status_str]
            current_functions.append(Function(current_offset, status, current_size, current_label))

    if len(current_functions) > 0:
        if current_object_name in files:
            files[current_object_name].functions += current_functions
        else:
            files[current_object_name] = File(current_object_name, current_functions)
        current_functions = []
    return files

def can_overwrite_name(addr: int, new_name: str):
    if not new_name or new_name.startswith(("sub_", "nullsub_", "j_")) or new_name == "''":
        return False

    old_name: str = ida_name.get_name(addr)
    # If we don't have an existing name, then the function can always be renamed.
    if not old_name:
        return True

    # Auto-generated names can be overwritten.
    if old_name.startswith(("sub_", "nullsub_", "j_")):
        return True

    # If the existing name is mangled, then it probably came from the function list CSV
    # so it can be overwritten.
    if old_name.startswith("_Z"):
        return True

    # Prefer mangled names to temporary names.
    if new_name.startswith("_Z"):
        return True

    # Otherwise, we return false to avoid losing temporary names.
    if name != old_name:
        print(f"Skipping {name} at {hex(addr)} because it would overwrite an existing name ({old_name}).")
    return False

def can_overwrite_folder(addr: int, new_folder: str):
    if not new_folder or new_folder == "UNKNOWN":
        return False

    old_folder = getFuncAbsPath(addr).rsplit("/", 1)[0].strip("/")
    # If we don't have an existing folder, then the function can always be renamed.
    if not old_folder or old_folder == "UNKNOWN":
        return True

    # Otherwise, we return false to avoid losing temporary folders.
    if new_folder != old_folder:
        print(f"Skipping {new_folder} at {hex(addr)} because it would overwrite an existing folder ({old_folder}).")
    return False

# https://github.com/josephH00/ida-InTooDeep/blob/639258049e8033a939320d9371f961e83db6dfad/InTooDeep.py#L67-L84
def getFuncAbsPath(ea):
    tree = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    funcName = ida_funcs.get_func_name(ea)

    absPath = ""

    class treeTraversal(ida_dirtree.dirtree_visitor_t):
        def visit(self, cursor, direntry):
            if direntry.isdir or funcName != tree.get_entry_name(direntry):
                return 0

            nonlocal absPath
            absPath = tree.get_abspath(cursor)

            return -1

    tree.traverse(treeTraversal())
    return absPath

yml_path = get_repo_root() / "data" / "file_list.yml"
files = parse_file_list(open(yml_path).readlines())

for file in files:
    for fun in files[file].functions:
        addr = 0x7100000000 + fun.offset
        name = fun.name
        color = get_status_color(fun.status)
        if can_overwrite_name(addr, name):
            ok = ida_name.set_name(addr, name, ida_name.SN_CHECK | ida_name.SN_NOWARN)
            if not ok:
                print(f"Failed to rename {name} at {hex(addr)} (existing name: {ida_name.get_name(addr)})")
        if can_overwrite_folder(addr, file):
            tree = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
            existing_name = getFuncAbsPath(addr)
            new_name = f"/{file}/{ida_name.get_name(addr)}"
            ok_mkdir = tree.mkdir(f"/{file}")
            if ok_mkdir not in [ida_dirtree.DTE_OK, ida_dirtree.DTE_ALREADY_EXISTS]:
                print(f"Failed to create folder for {hex(addr)}: /{file} => {ok_mkdir} ({tree.errstr(ok_mkdir)})")
            ok = tree.rename(existing_name, new_name)
            if ok not in [ida_dirtree.DTE_OK]:
                print(f"Failed to rename function for {hex(addr)} from {existing_name} to {new_name} => {ok} ({tree.errstr(ok)})")

        ida_funcs.get_func(addr).color = RGB_BGR(color)

