import ida_hexrays
try:
    from ida_domain import Database
    from ida_domain.pseudocode import PseudocodeExpressionOp
    from ida_domain.types import TypeApplyFlags
except ImportError:
    print("Failed to import ida_domain. Please make sure you have the ida_domain plugin installed.")
    print("Run: `pip install ida-domain` to install it.")
    print("Make sure to install it into the correct Python environment IDA is using!")
    print("You can check the Python environment IDA is by executing `idapyswitch` in the installation directory.")
    exit(1)

def error(msg):
    print(f"Error: {msg}")
    exit(1)
def EXPECT(condition, msg):
    if not condition:
        return error(msg)

def get_all_strings(db, addresses):
    result = [None for _ in addresses]
    for x in db.strings.get_all():
        if x.address in addresses:
            idx = addresses.index(x.address)
            result[idx] = str(x.contents, "utf-8")
    for i, addr in enumerate(addresses):
        EXPECT(result[i] is not None, f"Failed to find string at {addr:#x}")
    return result

def main():
    with Database.open() as db:
        f = db.functions.get_at(db.current_ea)
        EXPECT(f is not None, "Please position the cursor within a function")
        EXPECT(f.get_name() == "nvnLoadCProcs", "Please position the cursor within the nvnLoadCProcs function or rename the current function to nvnLoadCProcs if you are sure it is the correct one")

        f_type = f.get_prototype()
        EXPECT(f_type is not None, "Failed to get function type")
        EXPECT(db.types.get_func_argument_count(f_type) == 2, "Function nvnLoadCProcs should have two arguments")
        EXPECT(str(db.types.get_return_type(f_type)) == "void", f"Function nvnLoadCProcs should be void")
        
        pseudo = db.functions.get_pseudocode(f)
        mapping = {}
        for insn in pseudo.body.block:
            expr = insn.expression
            EXPECT(expr is not None, "Failed to get expression from instruction")
            EXPECT(expr.is_assignment, "Expected only assignment expressions!")
            lhs = expr.x
            rhs = expr.y
            
            EXPECT(lhs.is_object, "Expected left-hand side to be an object")
            lhs_addr = lhs.obj_ea

            if rhs.op == PseudocodeExpressionOp.CAST:
                rhs = rhs.x
            EXPECT(rhs.is_call, "Expected right-hand side to be a function call")
            call_args = [x.expression for x in rhs.call_args]
            EXPECT(len(call_args) == 2, "Expected function call to have two arguments")
            EXPECT(call_args[0].is_variable, "Expected first argument to be a variable")
            EXPECT(call_args[1].is_object, "Expected second argument to be an object (pointer to string)")
            rhs_addr = call_args[1].obj_ea
            
            EXPECT(lhs_addr not in mapping, f"Duplicate assignment to {lhs_addr:#x} found")
            mapping[lhs_addr] = rhs_addr
        
        # fetch all at once, so db.strings is only iterated once
        addr_to_string = get_all_strings(db, list(mapping.values()))

        success = 0
        failure = 0
        for (i, addr) in enumerate(mapping.keys()):
            funcname = "pfnc_" + addr_to_string[i]
            if db.names.get_at(addr) == funcname:
                continue  # name already set correctly, skip
            if db.names.set_name(addr, funcname):
                success += 1
            else:
                print(f"Failed to rename function at {addr:#x} to {funcname}")
                failure += 1
        print(f"Renamed {success} functions, failed to rename {failure} functions")

        success = 0
        failure = 0
        for (i, addr) in enumerate(mapping.keys()):
            typename = "PFN" + addr_to_string[i].upper() + "PROC"
            ftype = db.types.get_by_name(typename)
            if ftype is None:
                print(f"Failed to find type {typename} for function at {addr:#x}")
                failure += 1
                continue
            if str(db.types.get_at(addr)) == str(ftype):
                continue  # type already set correctly, skip
            if db.types.apply_at(ftype, addr, TypeApplyFlags.DEFINITE):
                success += 1
            else:
                print(f"Failed to apply type {typename} to function at {addr:#x}")
                failure += 1
        print(f"Applied types to {success} functions, failed to apply types to {failure} functions")

main()
