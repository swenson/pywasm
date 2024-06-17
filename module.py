from array import array
from collections import namedtuple
from enum import IntEnum
from typing import Callable, BinaryIO, Optional
import sys
import struct
import io
import time

import argparse

global DEBUG
DEBUG = False

# necessary for large function parsing
sys.setrecursionlimit(100000)

Module = namedtuple("Module", ["sections"])

Section = namedtuple("Section", ["section_id", "contents"])
CustomSection = namedtuple("CustomSection", ["name", "bytes"])
TypeSection = namedtuple("TypeSection", ["function_types"])
ImportSection = namedtuple("ImportSection", ["imports"])
FunctionSection = namedtuple("FunctionSection", ["funcs"])
TableSection = namedtuple("TableSection", ["tables"])
MemorySection = namedtuple("MemorySection", ["memories"])
GlobalSection = namedtuple("GlobalSection", ["globals"])
ExportSection = namedtuple("ExportSection", ["exports"])
StartSection = namedtuple("StartSection", ["start"])
ElementSection = namedtuple("ElementSection", ["elemsec"])
CodeSection = namedtuple("CodeSection", ["code"])
DataSection = namedtuple("DataSection", ["seg"])

FunctionType = namedtuple("FunctionType", ["parameter_types", "result_types"])
Import = namedtuple("Import", ["mod", "nm", "d"])
FuncIdx = namedtuple("FuncIdx", ["x"])
TableIdx = namedtuple("TableIdx", ["x"])
MemIdx = namedtuple("MemIdx", ["x"])
GlobalIdx = namedtuple("GlobalIdx", ["x"])
TypeIdx = namedtuple("TypeIdx", ["x"])
LabelIdx = namedtuple("LabelIdx", ["x"])

TableType = namedtuple("TableType", ["et", "lim"])
MemType = namedtuple("MemType", ["lim"])
GlobalType = namedtuple("GlobalType", ["t", "m"])
Global = namedtuple("Global", ["gt", "e"])
FuncRef = 0x70
Limits = namedtuple("Limits", ["n", "m"])
Expr = namedtuple("Expr", ["instructions"])
Export = namedtuple("Export", ["nm", "d"])
Elem = namedtuple("Elem", ["x", "e", "y"])
Code = namedtuple("Code", ["size", "code"])
Func = namedtuple("Func", ["t", "e"])
Locals = namedtuple("Locals", ["n", "t"])
Data = namedtuple("Data", ["x", "e", "b"])

CUSTOM_SECTION_ID = 0
TYPE_SECTION_ID = 1
IMPORT_SECTION_ID = 2
FUNCTION_SECTION_ID = 3
TABLE_SECTION_ID = 4
MEMORY_SECTION_ID = 5
GLOBAL_SECTION_ID = 6
EXPORT_SECTION_ID = 7
START_SECTION_ID = 8
ELEMENT_SECTION_ID = 9
CODE_SECTION_ID = 10
DATA_SECTION_ID = 11

Label = namedtuple('Label', ('valtype', 'name'))
def new_label(bt, name):
    if bt == 0x40:
        return Label(None, name)
    return Label(ValType(bt), name)

class ValType(IntEnum):
    I32 = 0x7F
    I64 = 0x7E
    F32 = 0x7D
    F64 = 0x7C


default_values = {
    ValType.I32: 0,
    ValType.I64: 0,
    ValType.F32: 0.0,
    ValType.F64: 0.0,
}


class Value:
    def __init__(self, val: any, type: ValType):
        self.val = val
        self.type = type

    def __repr__(self):
        return f"{self.val}: {self.type.name}"


class ImportFunction:
    def __init__(self, mod: str, name: str, typeIdx: int):
        self.mod = mod
        self.name = name
        self.typeIdx = typeIdx


class WasmFunction:
    def __init__(
        self, code: Func, parameter_types: list[ValType], result_types: list[ValType]
    ):
        self.code = code
        self.parameter_types = parameter_types
        self.result_types = result_types


def init_module(mod: Module):
    if DEBUG:
        print("Initializing module")
    start: StartSection = None
    functions: FunctionSection = None
    code: CodeSection = None
    typ: TypeSection = None
    data: DataSection = None
    globals_section: GlobalSection = None
    import_section: ImportSection = None
    export_section: ExportSection = None
    element_section: ElementSection = None
    import_functions = []
    for section in mod.sections:
        if isinstance(section, StartSection):
            start = section
        elif isinstance(section, FunctionSection):
            functions = section
        elif isinstance(section, CodeSection):
            code = section
        elif isinstance(section, TypeSection):
            typ = section
        elif isinstance(section, DataSection):
            data = section
        elif isinstance(section, GlobalSection):
            globals_section = section
        elif isinstance(section, ImportSection):
            import_section = section
        elif isinstance(section, ExportSection):
            export_section = section
        elif isinstance(section, ElementSection):
            element_section = section
    if start is None:
        exit("No start section found")

    imports = {
        "__memory_base": 1000000,
        "__stack_pointer": 10000000,
        "__table_base": 15000000,
        "__heap_base": 20000000,
    }
    globals: list[Value] = []
    mem = [0] * 40000000
    tables = []
    function_list = []
    function_names = []
    if import_section is not None:
        for imp in import_section.imports:
            if isinstance(imp.d, TypeIdx):
                # TODO: patch in functions from this file into here
                function_list.append(ImportFunction(imp.mod, imp.nm, imp.d.x))
                if DEBUG:
                    print(f"import function {imp.mod}.{imp.nm}")
                function_names.append(f"{imp.mod}.{imp.nm}")
            elif isinstance(imp.d, GlobalType):
                # TODO: patch in globals from here
                val = imports.get(imp.nm, 0)
                if DEBUG:
                    print(f"globals[{len(globals)}] = import {imp.nm} = {val}")
                globals.append(Value(val, imp.d.t))
            elif isinstance(imp.d, MemType):
                if len(mem) < imp.d.lim.n:
                    mem.extend([0] * (imp.d.lim.n - len(mem)))
            elif isinstance(imp.d, TableType):
                if len(tables) < imp.d.lim.n:
                    tables.extend([0] * imp.d.lim.n)
            else:
                exit(f"Unsupported import: {imp}")

    for g in globals_section.globals:
        g: Global
        assert len(g.e.instructions) == 2
        assert g.e.instructions[1].opcode == Opcode.end
        op = g.e.instructions[0]
        assert op.opcode in (
            Opcode.i32_const,
            Opcode.i64_const,
            Opcode.f32_const,
            Opcode.f64_const,
        )
        arg = op.operands[0]
        if DEBUG:
            print(f"globals[{len(globals)}] = {arg}")
        if op.opcode == Opcode.i32_const:
            globals.append(Value(arg, ValType.I32))
        elif op.opcode == Opcode.i64_const:
            globals.append(Value(arg, ValType.I64))
        elif op.opcode == Opcode.f32_const:
            globals.append(Value(arg, ValType.F32))
        elif op.opcode == Opcode.f64_const:
            globals.append(Value(arg, ValType.F64))

    for d in data.seg:
        d: Data
        memidx = d.x
        expr = d.e
        b = d.b
        assert len(expr.instructions) == 2
        assert expr.instructions[0].opcode == Opcode.global_get
        assert expr.instructions[1].opcode == Opcode.end
        idx = globals[expr.instructions[0].operands[0]].val
        if DEBUG:
            print(f"Initializing data memidx={memidx}, offset={idx}")
        if len(mem) < idx + len(b):
            needed = idx + len(b) - len(mem)
            mem.extend([0] * needed)
        for i in range(idx, idx + len(b)):
            mem[i] = b[i - idx]

    if DEBUG:
        print(f"Functions len = {len(functions.funcs)}, types = {len(code.code)}")
    import_len = len(function_names)
    for i in range(len(functions.funcs)):
        function_list.append(
            WasmFunction(
                code.code[i].code,
                typ.function_types[functions.funcs[i].x].parameter_types,
                typ.function_types[functions.funcs[i].x].result_types,
            )
        )
        function_names.append("?")
    exports = {}
    for export in export_section.exports:
        exports[export.nm] = export.d
        if isinstance(export.d, FuncIdx):
            if export.d.x >= len(function_names):
                function_names.extend(["?"] * (export.d.x + 1 - len(function_names)))
            function_names[export.d.x] = export.nm

    # print(f"start fun = {start.start.x}")
    # startx = start.start.x - len(import_functions)
    # f = functions.funcs[startx]
    # c = code.code[startx].code
    # print(f"Start function idx = {start.start}, type = {typ.function_types[f.x]}")
    # parameter_types = typ.function_types[f.x].parameter_types
    # result_types = typ.function_types[f.x].result_types
    parameters = [
        Value(default_values[t], t)
        for t in function_list[start.start.x].parameter_types
    ]
    stack = []
    exec_function(
        function_list[start.start.x].code,
        [],
        parameters,
        stack,
        globals,
        mem,
        function_list,
        typ,
        code,
        import_functions,
        function_names,
        element_section,
        [],
    )
    if DEBUG:
        print("*** Call(PyRun_SimpleString)")
        print(f"btw PyRun_SimpleStringFlags = {exports['PyRun_SimpleStringFlags'].x}")
        print(f"btw PyObject_Malloc = {exports['PyObject_Malloc'].x}")
        print(f"btw _ZTVSt12length_error = {exports['_ZTVSt12length_error'].x}")
    x = exports["PyRun_SimpleString"].x
    parameters = [Value(default_values[t], t) for t in function_list[x].parameter_types]
    ptr = len(mem)
    mem.extend('print("abc")\0')
    parameters[0] = Value(ptr, ValType.I32)
    if DEBUG:
        print(f"Parameters: {parameters}")
    exec_function(
        function_list[x].code,
        parameters,
        function_list[x].result_types,
        stack,
        globals,
        mem,
        function_list,
        typ,
        code,
        import_functions,
        function_names,
        element_section,
        ["PyRun_SimpleString"],
    )


i64_mask = 0xFFFFFFFFFFFFFFFF
i32_mask = 0xFFFFFFFF
i8_mask = 0xFF
i32_sign = 0x80000000
i64_sign = 0x8000000000000000


def i32_to_u32(a: int) -> int:
    return a & i32_mask


def i64_to_u64(a: int) -> int:
    return a & i64_mask


def i64_to_u64(a: int) -> int:
    return a & i64_mask


def i32_to_s32(a: int) -> int:
    a = i32_to_u32(a)
    if a & i32_sign:
        a = -(-a & i32_mask)
    return a


def i32_add(a: int, b: int) -> int:
    a = a & i32_mask
    b = b & i32_mask
    s = (a + b) & i32_mask
    if s & i32_sign:
        s = -(-s & i32_mask)
    return s

def i32_mul(a: int, b: int) -> int:
    a = a & i32_mask
    b = b & i32_mask
    c = (a * b) & i32_mask
    return c


def i32_div_u(a: int, b: int) -> int:
    a = a & i32_mask
    b = b & i32_mask
    c = (a // b) & i32_mask
    return c


def i32_div_s(a: int, b: int) -> int:
    a = i32_to_s32(a)
    b = i32_to_s32(b)
    c = (a // b) & i32_mask
    return c


def i32_shl(a: int, b: int) -> int:
    s = (a << b) & i32_mask
    if s & i32_sign:
        s = -(-s & i32_mask)
    return s


def i32_shr_u(a: int, b: int) -> int:
    return (a & i32_mask) >> b


def i64_shr_u(a: int, b: int) -> int:
    return (a & i64_mask) >> b


def i32_shr_s(a: int, b: int) -> int:
    return (i32_to_s32(a) >> b) & i32_mask


class Jump:
    def __init__(self, label: int):
        self.label = label
    def __str__(self):
        return f"Jump(label={self.label})"

class Skip:
    def __init__(self, label: int):
        self.label = label
    def __str__(self):
        return f"Skip(label={self.label})"

Return = Jump(-1)


global_counter = 0


def mem_read(mem: list[int], addr: int, size: int) -> bytes:
    x = []
    for i in range(addr, addr + size):
        if i >= len(mem):
            if i > len(mem) + 4:
                raise ValueError(f"Reading too far from memory: {i} > {len(mem)}")
            x.append(0)
        else:
            x.append(mem[i])
    return bytes(x)


def mem_write(mem: list[int], addr: int, data: bytes):
    if len(mem) < addr + len(data):
        if addr + len(data) - len(mem) > 16:
            raise ValueError(
                f"Tried to extend memory too far: current = {len(mem)}, asked = {addr + len(data)}"
            )
        mem.extend([0] * (addr + len(data) - len(mem)))
    for i in range(len(data)):
        mem[addr + i] = data[i]


def exec_instruction(
    inst: "Op",
    locals: list[Value],
    stack: list[Value],
    globals: list[Value],
    mem: list[int],
    functions: list[ImportFunction | WasmFunction],
    typ: TypeSection,
    codes: CodeSection,
    import_functions: list[ImportFunction],
    function_names: list[str],
    element_section: ElementSection,
    call_stack: list[str],
) -> Optional[Jump]:
    try:
        return exec_instruction_inner(inst, locals, stack, globals, mem, functions, typ, codes, import_functions, function_names, element_section, call_stack)
    except KeyboardInterrupt:
        print(f"Stack trace: {call_stack}")
        exit(1)

def find_last_label(stack: list[any]) -> Optional[int]:
    i = len(stack) - 1
    while i >= 0:
        if isinstance(stack[i], Label):
            return i
        i -= 1
    return None

def find_ith_label(stack: list[any], j: int) -> Optional[int]:
    i = len(stack) - 1
    while i >= 0:
        if isinstance(stack[i], Label):
            if j == 0:
                return i
            else:
                return find_ith_label(stack[:i], j - 1)
        i -= 1
    return None

def pop_to_label(stack, i=0):
    while stack and i >= 0:
        x = stack.pop()
        if isinstance(x, Label):
            i = i - 1

def pop_stack(j: Optional[Jump|Skip], stack: list[Label|Value]) -> Optional[Jump|Skip]:
    # we've already popped back to this level, so this is a no-op
    if isinstance(j, Skip):
        if j.label == 0:
            return None
        else:
            return Skip(j.label - 1)

    if DEBUG:
        print(f"Popping back to label {j}")
    keep = None
    if j is None:
        i = find_last_label(stack)
        if i is None:
            raise ValueError(f"Stack did not contain label: {stack}")
        if stack[i].valtype:
            keep = stack.pop()
        pop_to_label(stack)
    else:
        i = find_ith_label(stack, j.label)
        if i is None:
            raise ValueError(f"Was not able to find {j.label} label in stack {stack}")
        if stack[i].valtype:
            keep = stack.pop()
        pop_to_label(stack, j.label)
    if keep is not None:
        stack.append(keep)
    if j is not None and j.label:
        return Skip(j.label - 1)


def exec_instruction_inner(
    inst: "Op",
    locals: list[Value],
    stack: list[Value],
    globals: list[Value],
    mem: list[int],
    functions: list[ImportFunction | WasmFunction],
    typ: TypeSection,
    codes: CodeSection,
    import_functions: list[ImportFunction],
    function_names: list[str],
    element_section: ElementSection,
    call_stack: list[str],
) -> Optional[Jump]:
    global global_counter
    if DEBUG:
        print(
            f"\n{global_counter} Executing {inst.opcode.name} {inst.subop}, stack length {len(stack)}, memory length {len(mem)}, call stack [{','.join(call_stack)}]"
        )
        print(f"Stack: {stack}")
    global_counter += 1
    # if global_counter > 4876:
    #     input("> ")
    if inst.opcode == Opcode.end or inst.opcode == Opcode.else_:
        pass
    elif inst.opcode == Opcode.local_get:
        if DEBUG:
            print(f"Local get {inst.operands[0]} -> {locals[inst.operands[0]]}")
        stack.append(locals[inst.operands[0]])
    elif inst.opcode == Opcode.i32_load:
        offset = inst.operands[1]
        base_addr = stack.pop().val & i32_mask
        addr = base_addr + offset
        num = struct.unpack("<I", mem_read(mem, addr, 4))[0]
        if DEBUG:
            print(f"Load 0x{base_addr:x}+0x{offset:x}={addr:x} -> 0x{num:x}")
        stack.append(Value(num, ValType.I32))
    elif inst.opcode == Opcode.i64_load:
        offset = inst.operands[1]
        base_addr = stack.pop().val & i32_mask
        addr = base_addr + offset
        num = struct.unpack("<Q", mem_read(mem, addr, 8))[0]
        if DEBUG:
            print(f"Load 0x{base_addr:x}+0x{offset:x}={addr:x} -> (64-bit) 0x{num:x}")
        stack.append(Value(num, ValType.I64))
    elif inst.opcode == Opcode.i64_store:
        offset = inst.operands[1]
        val = stack.pop().val & i64_mask
        base_addr = stack.pop().val & i32_mask
        addr = base_addr + offset
        if DEBUG:
            print(f"Store 0x{addr:x} -> (64-bit) 0x{val:x}")
        data = struct.pack("<Q", val)
        mem_write(mem, addr, data)
    elif inst.opcode == Opcode.i32_store:
        offset = inst.operands[1]
        val = stack.pop().val & i32_mask
        base_addr = stack.pop().val & i32_mask
        addr = base_addr + offset
        if DEBUG:
            print(f"Store 0x{addr:x} -> 0x{val:x}")
        data = struct.pack("<I", val)
        mem_write(mem, addr, data)
    elif inst.opcode == Opcode.i32_store8:
        offset = inst.operands[1]
        val = stack.pop().val & i8_mask
        base_addr = stack.pop().val & i32_mask
        addr = base_addr + offset
        if DEBUG:
            print(f"Store 0x{addr:x} -> (8-bit) 0x{val:x}")
        data = struct.pack("<B", val)
        mem_write(mem, addr, data)
    elif inst.opcode == Opcode.i32_load8_u:
        offset = inst.operands[1]
        base_addr = stack.pop().val & i32_mask
        addr = base_addr + offset
        num = struct.unpack("<B", bytes(mem[addr : addr + 1]))[0]
        if DEBUG:
            print(f"  load byte {inst.operands} [0x{addr:x}] -> 0x{num:x}")
        stack.append(Value(num, ValType.I32))
    elif inst.opcode == Opcode.i32_load8_s:
        offset = inst.operands[1]
        base_addr = stack.pop().val & i32_mask
        addr = base_addr + offset
        num = struct.unpack("<b", bytes(mem[addr : addr + 1]))[0]
        stack.append(Value(num, ValType.I32))
    elif inst.opcode == Opcode.i32_load16_u:
        offset = inst.operands[1]
        base_addr = stack.pop().val & i32_mask
        addr = base_addr + offset
        num = struct.unpack("<H", bytes(mem[addr : addr + 2]))[0]
        stack.append(Value(num, ValType.I32))
    elif inst.opcode == Opcode.i64_load32_u:
        offset = inst.operands[1]
        base_addr = stack.pop().val & i32_mask
        addr = base_addr + offset
        num = struct.unpack("<H", bytes(mem[addr : addr + 2]))[0]
        stack.append(Value(num, ValType.I64))
    elif inst.opcode == Opcode.local_set:
        idx = inst.operands[0]
        assert not isinstance(stack[-1], Label)
        locals[idx] = stack.pop()
        if DEBUG:
            print(f"  Set local: [{idx}] <- {locals[idx]}")
    elif inst.opcode == Opcode.local_tee:
        idx = inst.operands[0]
        assert not isinstance(stack[-1], Label)
        locals[idx] = stack[-1]
        if DEBUG:
            print(f"  tee locals[{idx}] = {stack[-1]}")
    elif inst.opcode == Opcode.global_get:
        idx = inst.operands[0]
        if DEBUG:
            print(f"  get globals[{idx}] => {globals[idx]}")
        stack.append(globals[idx])
    elif inst.opcode == Opcode.global_set:
        idx = inst.operands[0]
        assert not isinstance(stack[-1], Label)
        globals[idx] = stack.pop()
        if DEBUG:
            print(f"  set globals[{idx}] <= {globals[idx]}")
    elif inst.opcode == Opcode.i32_const:
        c = inst.operands[0]
        if DEBUG:
            print(f"  push 0x{c:x} ({inst})")
        stack.append(Value(c, ValType.I32))
    elif inst.opcode == Opcode.i64_const:
        c = inst.operands[0]
        stack.append(Value(c, ValType.I64))
    elif inst.opcode == Opcode.i32_add:
        b = stack.pop()
        a = stack.pop()
        if DEBUG:
            print(f"  add: {a.val} + {b.val} = {i32_add(a.val, b.val)}")
        stack.append(Value(i32_add(a.val, b.val), ValType.I32))
    elif inst.opcode == Opcode.i32_sub:
        b = stack.pop()
        a = stack.pop()
        if DEBUG:
            print(f"  sub: {a.val} - {b.val} = {i32_add(a.val, -b.val)}")
        stack.append(Value(i32_add(a.val, -b.val), ValType.I32))
    elif inst.opcode == Opcode.i32_mul:
        b = stack.pop()
        a = stack.pop()
        if DEBUG:
            print(f"  mul: {a.val} * {b.val} = {i32_mul(a.val, b.val)}")
        stack.append(Value(i32_mul(a.val, b.val), ValType.I32))
    elif inst.opcode == Opcode.i32_div_u:
        b = stack.pop()
        a = stack.pop()
        if DEBUG:
            print(f"  div: {a.val} / {b.val} = {i32_div_u(a.val, b.val)}")
        stack.append(Value(i32_div_u(a.val, b.val), ValType.I32))
    elif inst.opcode == Opcode.i32_div_s:
        b = stack.pop()
        a = stack.pop()
        if DEBUG:
            print(f"  div: {a.val} / {b.val} = {i32_div_s(a.val, b.val)}")
        stack.append(Value(i32_div_s(a.val, b.val), ValType.I32))
    elif inst.opcode == Opcode.i32_and:
        b = stack.pop()
        a = stack.pop()
        if DEBUG:
            print(f"  and: {a.val} & {b.val} -> {a.val & b.val}")
        stack.append(Value(a.val & b.val, ValType.I32))
    elif inst.opcode == Opcode.i32_or:
        b = stack.pop()
        a = stack.pop()
        stack.append(Value(a.val | b.val, ValType.I32))
    elif inst.opcode == Opcode.i32_xor:
        b = stack.pop()
        a = stack.pop()
        if DEBUG:
            print(f"  xor: {a.val} ^ {b.val} -> {a.val ^ b.val}")
        stack.append(Value(a.val ^ b.val, ValType.I32))
    elif inst.opcode == Opcode.i32_shl:
        b = stack.pop()
        a = stack.pop()
        stack.append(Value(i32_shl(a.val, b.val), ValType.I32))
    elif inst.opcode == Opcode.i32_shr_u:
        b = stack.pop()
        a = stack.pop()
        stack.append(Value(i32_shr_u(a.val, b.val), ValType.I32))
    elif inst.opcode == Opcode.i32_shr_s:
        b = stack.pop()
        a = stack.pop()
        stack.append(Value(i32_shr_s(a.val, b.val), ValType.I32))
    elif inst.opcode == Opcode.i64_shr_u:
        b = stack.pop()
        a = stack.pop()
        stack.append(Value(i64_shr_u(a.val, b.val), ValType.I32))
    elif inst.opcode == Opcode.i32_eq:
        b = stack.pop()
        a = stack.pop()
        if a.val == b.val:
            stack.append(Value(1, ValType.I32))
        else:
            stack.append(Value(0, ValType.I32))
    elif inst.opcode == Opcode.i32_le_u:
        b = i32_to_u32(stack.pop().val)
        a = i32_to_u32(stack.pop().val)
        if a <= b:
            if DEBUG:
                print(f"  le_u {a} <= {b} => True")
            stack.append(Value(1, ValType.I32))
        else:
            if DEBUG:
                print(f"  le_u {a} <= {b} => False")
            stack.append(Value(0, ValType.I32))
    elif inst.opcode == Opcode.i32_lt_s:
        b = i32_to_s32(stack.pop().val)
        a = i32_to_s32(stack.pop().val)
        if a < b:
            stack.append(Value(1, ValType.I32))
        else:
            stack.append(Value(0, ValType.I32))
    elif inst.opcode == Opcode.i32_eqz:
        a = stack.pop()
        if DEBUG:
            print(f"  eqz? {a.val} -> {a.val == 0}")
        if a.val == 0:
            stack.append(Value(1, ValType.I32))
        else:
            stack.append(Value(0, ValType.I32))
    elif inst.opcode == Opcode.i64_eqz:
        a = stack.pop()
        if DEBUG:
            print(f"  eqz? {a.val} -> {a.val == 0}")
        if a.val == 0:
            stack.append(Value(1, ValType.I32))
        else:
            stack.append(Value(0, ValType.I32))
    elif inst.opcode == Opcode.i64_ne:
        b = stack.pop()
        a = stack.pop()
        if i64_to_u64(a.val) != i64_to_u64(b.val):
            stack.append(Value(1, ValType.I32))
        else:
            stack.append(Value(0, ValType.I32))
    elif inst.opcode == Opcode.i32_ne:
        b = stack.pop()
        a = stack.pop()
        if i32_to_s32(a.val) != i32_to_s32(b.val):
            stack.append(Value(1, ValType.I32))
        else:
            stack.append(Value(0, ValType.I32))
    elif inst.opcode == Opcode.i32_lt_u:
        b = stack.pop()
        a = stack.pop()
        if i32_to_u32(a.val) < i32_to_u32(b.val):
            stack.append(Value(1, ValType.I32))
        else:
            stack.append(Value(0, ValType.I32))
    elif inst.opcode == Opcode.i32_gt_u:
        b = stack.pop()
        a = stack.pop()
        if i32_to_u32(a.val) > i32_to_u32(b.val):
            stack.append(Value(1, ValType.I32))
        else:
            stack.append(Value(0, ValType.I32))
    elif inst.opcode == Opcode.i64_gt_u:
        b = stack.pop()
        a = stack.pop()
        if i64_to_u64(a.val) > i64_to_u64(b.val):
            stack.append(Value(1, ValType.I32))
        else:
            stack.append(Value(0, ValType.I32))
    elif inst.opcode == Opcode.i32_ge_u:
        b = stack.pop()
        a = stack.pop()
        if i32_to_u32(a.val) >= i32_to_u32(b.val):
            if DEBUG:
                print(f"  {i32_to_u32(a.val)} >= {i32_to_u32(b.val)} ? => 1")
            stack.append(Value(1, ValType.I32))
        else:
            if DEBUG:
                print(f"  {i32_to_u32(a.val)} >= {i32_to_u32(b.val)} ? => 0")
            stack.append(Value(0, ValType.I32))
    elif inst.opcode == Opcode.i32_ge_s:
        b = stack.pop()
        a = stack.pop()
        if i32_to_s32(a.val) >= i32_to_s32(b.val):
            stack.append(Value(1, ValType.I32))
        else:
            stack.append(Value(0, ValType.I32))
    elif inst.opcode == Opcode.i32_gt_s:
        b = stack.pop()
        a = stack.pop()
        if i32_to_s32(a.val) > i32_to_s32(b.val):
            stack.append(Value(1, ValType.I32))
        else:
            stack.append(Value(0, ValType.I32))
    elif inst.opcode == Opcode.i32_le_s:
        b = stack.pop()
        a = stack.pop()
        if i32_to_s32(a.val) <= i32_to_s32(b.val):
            stack.append(Value(1, ValType.I32))
        else:
            stack.append(Value(0, ValType.I32))
    elif inst.opcode == Opcode.i32_wrap_i64:
        a = stack.pop()
        stack.append(Value(a.val & i32_mask, ValType.I32))
    elif inst.opcode == Opcode.select:
        c = stack.pop()
        b = stack.pop()
        a = stack.pop()
        if c.val == 0:
            if DEBUG:
                print(f"  select({a}, {b}, {c}) -> {b}")
            stack.append(b)
        else:
            if DEBUG:
                print(f"  select({a}, {b}, {c}) -> {a}")
            stack.append(a)
    elif inst.opcode == Opcode.drop:
        stack.pop()
    elif inst.opcode == Opcode.memory_size:
        stack.append(Value(len(mem) & i32_mask, ValType.I32))
    elif inst.opcode == Opcode.br:
        label = inst.operands[0].x
        if DEBUG:
            print(f"br {label}")
        assert sum(1 for x in stack if isinstance(x, Label)) >= label + 1
        return Jump(label)
    elif inst.opcode == Opcode.br_if:
        x = stack.pop()
        label = inst.operands[0].x
        if DEBUG:
            print(f"br_if {x} {label}")
        if x.val != 0:
            if DEBUG:
                print(f"Branch was true, so jumping to {label}")
            assert sum(1 for x in stack if isinstance(x, Label)) >= label + 1
            return Jump(label)
        else:
            if DEBUG:
                print(f"Branch not taken")
    elif inst.opcode == Opcode.br_table:
        x = stack.pop()
        labels = inst.operands[0]
        default = inst.operands[1]
        if DEBUG:
            print(f"  br_table labels={labels} default={default} val={x.val}")
        if 0 <= x.val < len(labels):
            if DEBUG:
                print(f"  br_table taking label {labels[x.val]} -> {labels[x.val].x}")
            assert sum(1 for x in stack if isinstance(x, Label)) >= labels[x.val].x + 1
            return Jump(labels[x.val].x)
        else:
            if DEBUG:
                print(f"  br_table taking default")
            assert sum(1 for x in stack if isinstance(x, Label)) >= default.x + 1
            return Jump(default.x)
    elif inst.opcode == Opcode.if_:
        bt = inst.subop
        label = new_label(bt, "if")
        then = inst.operands[0]
        else_ = inst.operands[1]
        val = stack.pop().val
        if val:
            if DEBUG:
                print(f"Pushing label: {label}")
            stack.append(label)
            if DEBUG:
                print("  if statement was true")
            j = None
            for inst2 in then:
                j = exec_instruction(
                    inst2,
                    locals,
                    stack,
                    globals,
                    mem,
                    functions,
                    typ,
                    codes,
                    import_functions,
                    function_names,
                    element_section,
                    call_stack,
                )
                if j is Return:
                    return Return
                elif j is not None:
                    break
            return pop_stack(j, stack)
        elif else_:
            if DEBUG:
                print(f"Pushing label: {label}")
            stack.append(label)
            if DEBUG:
                print("  if statement was false and else was defined")
            j = None
            for inst2 in else_.instructions:
                j = exec_instruction(
                    inst2,
                    locals,
                    stack,
                    globals,
                    mem,
                    functions,
                    typ,
                    codes,
                    import_functions,
                    function_names,
                    element_section,
                    call_stack,
                )
                if j is Return:
                    return j
                elif j is not None:
                    break
            return pop_stack(j, stack)
        else:
            if DEBUG:
                print("  if statement was false (but no else)")
    elif inst.opcode == Opcode.block:
        block = inst.operands[0]
        stack.append(new_label(inst.subop, "block"))
        if DEBUG:
            print(f"Pushing label: {stack[-1]}")
        j = None
        for inst2 in block:
            j = exec_instruction(
                inst2,
                locals,
                stack,
                globals,
                mem,
                functions,
                typ,
                codes,
                import_functions,
                function_names,
                element_section,
                call_stack,
            )
            if j is Return:
                return j
            elif j is not None:
                break
        return pop_stack(j, stack)

    elif inst.opcode == Opcode.loop:
        block = inst.operands[0]
        stack.append(new_label(inst.subop, "loop"))
        if DEBUG:
            print(f"Pushing label: {stack[-1]}")
        j = None
        continue_loop = True
        while continue_loop:
            if DEBUG:
                print("*** begin loop")
            for inst2 in block:
                j = exec_instruction(
                    inst2,
                    locals,
                    stack,
                    globals,
                    mem,
                    functions,
                    typ,
                    codes,
                    import_functions,
                    function_names,
                    element_section,
                    call_stack,
                )
                if j is Return:
                    return j
                elif j is not None:
                    if j.label == 0:
                        j = None
                        break  # back to beginning of loop
                    else:
                        continue_loop = False
                        break
            else:
                break
        return pop_stack(j, stack)

    elif inst.opcode == Opcode.call:
        fidx = inst.operands[0]

        f = functions[fidx.x]
        if isinstance(f, ImportFunction):
            raise ValueError("Not supported yet: calling function %d" % fidx.x)
        else:
            code2 = f.code
            parameter_types = f.parameter_types
            # type_idx = functions.funcs[fidx.x].x
            # parameter_types = typ.function_types[type_idx].parameter_types

            parameters = []
            for i in range(len(parameter_types)):
                parameters.append(stack.pop())
            parameters.reverse()
            if fidx.x < len(function_names) and function_names[fidx.x] != "?":
                fname = function_names[fidx.x]
                if DEBUG:
                    print(
                        f"\n\n*** Call {function_names[fidx.x]}({parameters}) (function {fidx.x})"
                    )
            else:
                fname = f"f_{fidx.x}"
                if DEBUG:
                    print(f"\n\n*** Call f_{fidx.x}({parameters})")
            return exec_function(
                code2,
                parameters,
                f.result_types,
                stack,
                globals,
                mem,
                functions,
                typ,
                codes,
                import_functions,
                function_names,
                element_section,
                call_stack + [fname],
            )
    elif inst.opcode == Opcode.call_indirect:
        # tidx = inst.operands[0].x
        # t = typ.function_types[tidx]
        table_idx = stack.pop().val
        if DEBUG:
            print(f"*** Call indirect table idx {table_idx}")
        table = element_section.elemsec[0]
        fidx = table.y[table_idx]
        f = functions[fidx.x]
        if isinstance(f, ImportFunction):
            raise ValueError("Not supported yet: calling function %d" % fidx.x)
        else:
            if fidx.x < len(function_names) and function_names[fidx.x] != "?":
                fname = function_names[fidx.x]
                if DEBUG:
                    print(f"*** Call({function_names[fidx.x]})")
            else:
                fname = f"f_{fidx.x}"
                if DEBUG:
                    print(f"*** Call(f_{fidx.x})")
            code2 = f.code
            parameter_types = f.parameter_types
            # type_idx = functions.funcs[fidx.x].x
            # parameter_types = typ.function_types[type_idx].parameter_types

            parameters = []
            for i in range(len(parameter_types)):
                parameters.append(stack.pop())
            parameters.reverse()
            return exec_function(
                code2,
                parameters,
                f.result_types,
                stack,
                globals,
                mem,
                functions,
                typ,
                codes,
                import_functions,
                function_names,
                element_section,
                call_stack + [fname],
            )
    elif inst.opcode == Opcode.return_:
        return Return
    else:
        if DEBUG:
            print(f"Locals: {locals}")
            print(f"Stack: {stack}")
            print(f"Current instruction: {inst}")
        raise (ValueError(f"Unknown instruction: {inst}"))


def exec_function(
    code: Func,
    parameters: list[Value],
    result_types: list[ValType],
    stack: list[Value],
    globals: list[Value],
    mem: list[int],
    functions: list[ImportFunction | WasmFunction],
    typ: TypeSection,
    codes: CodeSection,
    import_functions: list[ImportFunction],
    function_names: list[str],
    element_section: ElementSection,
    call_stack: list[str],
) -> Optional[Jump]:
    locals = []
    for i in range(len(parameters)):
        locals.append(parameters[i])
    for local_type in code.t:
        for i in range(local_type.n):
            locals.append(Value(default_values[local_type.t], local_type.t))
    instructions = code.e.instructions
    pc = 0
    new_stack = []
    if DEBUG:
        print(f"Pushing label: {None}")
    new_stack.append(Label(None, name="function start"))
    j = None
    while pc < len(instructions):
        j = exec_instruction(
            instructions[pc],
            locals,
            new_stack,
            globals,
            mem,
            functions,
            typ,
            codes,
            import_functions,
            function_names,
            element_section,
            call_stack,
        )
        if j is not None:
            if j is Return:
                if DEBUG:
                    print("Return")
                break
        pc += 1
    if result_types:
        assert len(new_stack) >= len(result_types)
        keep = new_stack[-len(result_types):]
        stack.extend(keep)
    else:
        keep = []
    fname = call_stack[-1] if call_stack else ""
    if DEBUG:
        print(f"*** ({fname}) Return: {keep}")


def read_module(f: bytes) -> Module:
    assert f[:4] == b"\0asm"
    assert f[4:8] == b"\x01\0\0\0"
    current = 8
    sections = []
    while current < len(f):
        section_id = f[current]
        current += 1
        section_size, length = read_u32_bytes(f[current:])
        current += length
        contents = f[current : current + section_size]
        current += section_size
        if section_id == CUSTOM_SECTION_ID:
            section = parse_custom_section(contents)
            if DEBUG:
                print(
                    f"Custom section name: {section.name}, length={len(section.bytes)}"
                )
        elif section_id == TYPE_SECTION_ID:
            section = parse_type_section(contents)
            if DEBUG:
                print(f"Type section, num functions = {len(section.function_types)}")
        elif section_id == IMPORT_SECTION_ID:
            section = parse_import_section(contents)
            if DEBUG:
                print(f"Import section, {len(section.imports)} imports")
        elif section_id == FUNCTION_SECTION_ID:
            section = parse_function_section(contents)
            if DEBUG:
                print(f"Function section, {len(section.funcs)} functions")
        elif section_id == TABLE_SECTION_ID:
            section = parse_table_section(contents)
            if DEBUG:
                print(f"Table section, {section.tables}")
        elif section_id == MEMORY_SECTION_ID:
            section = parse_memory_section(contents)
            if DEBUG:
                print(f"Memory section, {section.memories}")
        elif section_id == GLOBAL_SECTION_ID:
            section = parse_global_section(contents)
            if DEBUG:
                print(f"Global section, {len(section.globals)} globals")
        elif section_id == EXPORT_SECTION_ID:
            section = parse_export_section(contents)
            if DEBUG:
                print(f"Export section, {len(section.exports)} exports")
        elif section_id == START_SECTION_ID:
            section = parse_start_section(contents)
            if DEBUG:
                print(f"Start section, {section.start}")
        elif section_id == ELEMENT_SECTION_ID:
            section = parse_element_section(contents)
            if DEBUG:
                print(f"Element section, {len(section.elemsec)} elements")
        elif section_id == CODE_SECTION_ID:
            section = parse_code_section(contents)
            if DEBUG:
                print(f"Code section, {len(section.code)} entries")
        elif section_id == DATA_SECTION_ID:
            section = parse_data_section(contents)
            data_bytes = sum(len(x.b) for x in section.seg)
            if DEBUG:
                print(
                    f"Data section, {len(section.seg)} entries, size {data_bytes} bytes"
                )
        else:
            if DEBUG:
                print(f"Section {section_id}, size = {section_size}")
            section = Section(section_id, contents)
        sections.append(section)
    return Module(sections)


def parse_data_section(raw: bytes) -> DataSection:
    r = io.BytesIO(raw)
    data = read_vector(r, decoder=read_data)
    return DataSection(data)


def parse_code_section(raw: bytes) -> CodeSection:
    r = io.BytesIO(raw)
    code = read_vector(r, decoder=read_code)
    return CodeSection(code)


def parse_element_section(raw: bytes) -> ElementSection:
    r = io.BytesIO(raw)
    elemsec = read_vector(r, decoder=read_element)
    return ElementSection(elemsec)


def parse_export_section(raw: bytes) -> ExportSection:
    r = io.BytesIO(raw)
    exports = read_vector(r, decoder=read_export)
    return ExportSection(exports)


def parse_start_section(raw: bytes) -> StartSection:
    r = io.BytesIO(raw)
    start = FuncIdx(read_u32(r))
    return StartSection(start)


def parse_global_section(raw: bytes) -> GlobalSection:
    r = io.BytesIO(raw)
    globals = read_vector(r, decoder=read_global)
    return GlobalSection(globals)


def parse_memory_section(raw: bytes) -> MemorySection:
    r = io.BytesIO(raw)
    memories = read_vector(r, decoder=read_mem)
    return MemorySection(memories)


def parse_table_section(raw: bytes) -> TableSection:
    r = io.BytesIO(raw)
    tables = read_vector(r, decoder=read_table)
    return TableSection(tables)


def parse_function_section(raw: bytes) -> FunctionSection:
    r = io.BytesIO(raw)
    funcs = read_vector(r, decoder=read_typeidx)
    return FunctionSection(funcs)


def parse_import_section(raw: bytes) -> ImportSection:
    r = io.BytesIO(raw)
    imports = read_vector(r, decoder=read_import)
    return ImportSection(imports)


def read_element(raw: BinaryIO) -> Elem:
    x = read_u32(raw)
    x = TableIdx(x)
    e = read_expr(raw)
    y = read_vector(raw, decoder=read_u32)
    y = [FuncIdx(z) for z in y]
    return Elem(x, e, y)


def read_export(raw: BinaryIO) -> Export:
    nm = read_name(raw)
    d = read_exportdesc(raw)
    return Export(nm, d)


def read_exportdesc(raw: BinaryIO) -> any:
    t = raw.read(1)[0]
    assert t <= 3
    x = read_u32(raw)
    if t == 0:
        return FuncIdx(x)
    elif t == 1:
        return TableIdx(x)
    elif t == 2:
        return MemIdx(x)
    else:
        return GlobalIdx(x)


def read_global(raw: BinaryIO) -> Global:
    gt = read_globaltype(raw)
    e = read_expr(raw)
    return Global(gt, e)


def peek(r: BinaryIO) -> int:
    c = r.tell()
    p = r.read(1)[0]
    r.seek(c, 0)
    return p


def read_expr(raw: BinaryIO, term=frozenset([0xB])) -> Expr:
    instructions = []
    p = peek(raw)
    while p not in term:
        instr = read_instruction(raw)
        instructions.append(instr)
        p = peek(raw)
    last = Opcode(raw.read(1)[0])
    assert last in term
    instructions.append(Op(last, None, None))
    return Expr(instructions)


def read_data(raw: BinaryIO) -> Data:
    x = read_u32(raw)
    x = MemIdx(x)
    e = read_expr(raw)
    b = read_vector_bytes(raw)
    return Data(x, e, b)


def read_code(raw: BinaryIO) -> Code:
    size = read_u32(raw)
    c = raw.tell()
    code = read_func(raw)
    d = raw.tell()
    assert size == d - c
    # print(f"code = {code.e.instructions}")
    return Code(size, code)


def read_func(raw: BinaryIO) -> Func:
    t = read_vector(raw, decoder=read_locals)
    e = read_expr(raw)
    # print(f"Read function with locals {t} and instructions {len(e.instructions)}")
    return Func(t, e)


def read_locals(raw: BinaryIO) -> Locals:
    n = read_u32(raw)
    t = read_valtype(raw)
    return Locals(n, t)


class Opcode(IntEnum):
    unreachable = 0x00
    nop = 0x01
    block = 0x02
    loop = 0x03
    if_ = 0x04
    else_ = 0x05
    end = 0x0B
    br = 0x0C
    br_if = 0x0D
    br_table = 0x0E
    return_ = 0x0F
    call = 0x10
    call_indirect = 0x11
    ref_null = 0xD0
    ref_is_null = 0xD1
    ref_func = 0xD2
    drop = 0x1A
    select = 0x1B
    select_vec = 0x1C
    local_get = 0x20
    local_set = 0x21
    local_tee = 0x22
    global_get = 0x23
    global_set = 0x24
    table_get = 0x25
    table_set = 0x26
    i32_load = 0x28
    i64_load = 0x29
    f32_load = 0x2A
    f64_load = 0x2B
    i32_load8_s = 0x2C
    i32_load8_u = 0x2D
    i32_load16_s = 0x2E
    i32_load16_u = 0x2F
    i64_load8_s = 0x30
    i64_load8_u = 0x31
    i64_load16_s = 0x32
    i64_load16_u = 0x33
    i64_load32_s = 0x34
    i64_load32_u = 0x35
    i32_store = 0x36
    i64_store = 0x37
    f32_store = 0x38
    f64_store = 0x39
    i32_store8 = 0x3A
    i32_store16 = 0x3B
    i64_store8 = 0x3C
    i64_store16 = 0x3D
    i64_store32 = 0x3E
    memory_size = 0x3F
    memory_grow = 0x40
    i32_const = 0x41
    i64_const = 0x42
    f32_const = 0x43
    f64_const = 0x44

    i32_eqz = 0x45
    i32_eq = 0x46
    i32_ne = 0x47
    i32_lt_s = 0x48
    i32_lt_u = 0x49
    i32_gt_s = 0x4A
    i32_gt_u = 0x4B
    i32_le_s = 0x4C
    i32_le_u = 0x4D
    i32_ge_s = 0x4E
    i32_ge_u = 0x4F
    i64_eqz = 0x50
    i64_eq = 0x51
    i64_ne = 0x52
    i64_lt_s = 0x53
    i64_lt_u = 0x54
    i64_gt_s = 0x55
    i64_gt_u = 0x56
    i64_le_s = 0x57
    i64_le_u = 0x58
    i64_ge_s = 0x59
    i64_ge_u = 0x5A
    f32_eq = 0x5B
    f32_ne = 0x5C
    f32_lt = 0x5D
    f32_gt = 0x5E
    f32_le = 0x5F
    f32_ge = 0x60
    f64_eq = 0x61
    f64_ne = 0x62
    f64_lt = 0x63
    f64_gt = 0x64
    f64_le = 0x65
    f64_ge = 0x66
    i32_clz = 0x67
    i32_ctz = 0x68
    i32_popcnt = 0x69
    i32_add = 0x6A
    i32_sub = 0x6B
    i32_mul = 0x6C
    i32_div_s = 0x6D
    i32_div_u = 0x6E
    i32_rem_s = 0x6F
    i32_rem_u = 0x70
    i32_and = 0x71
    i32_or = 0x72
    i32_xor = 0x73
    i32_shl = 0x74
    i32_shr_s = 0x75
    i32_shr_u = 0x76
    i32_rotl = 0x77
    i32_rotr = 0x78
    i64_clz = 0x79
    i64_ctz = 0x7A
    i64_popcnt = 0x7B
    i64_add = 0x7C
    i64_sub = 0x7D
    i64_mul = 0x7E
    i64_div_s = 0x7F
    i64_div_u = 0x80
    i64_rem_s = 0x81
    i64_rem_u = 0x82
    i64_and = 0x83
    i64_or = 0x84
    i64_xor = 0x85
    i64_shl = 0x86
    i64_shr_s = 0x87
    i64_shr_u = 0x88
    i64_rotl = 0x89
    i64_rotr = 0x8A
    f32_abs = 0x8B
    f32_neg = 0x8C
    f32_ceil = 0x8D
    f32_floor = 0x8E
    f32_trunc = 0x8F
    f32_nearest = 0x90
    f32_sqrt = 0x91
    f32_add = 0x92
    f32_sub = 0x93
    f32_mul = 0x94
    f32_div = 0x95
    f32_min = 0x96
    f32_max = 0x97
    f32_copysign = 0x98
    f64_abs = 0x99
    f64_neg = 0x9A
    f64_ceil = 0x9B
    f64_floor = 0x9C
    f64_trunc = 0x9D
    f64_nearest = 0x9E
    f64_sqrt = 0x9F
    f64_add = 0xA0
    f64_sub = 0xA1
    f64_mul = 0xA2
    f64_div = 0xA3
    f64_min = 0xA4
    f64_max = 0xA5
    f64_copysign = 0xA6
    i32_wrap_i64 = 0xA7
    i32_trunc_f32_s = 0xA8
    i32_trunc_f32_u = 0xA9
    i32_trunc_f64_s = 0xAA
    i32_trunc_f64_u = 0xAB
    i64_extend_i32_s = 0xAC
    i64_extend_i32_u = 0xAD
    i64_trunc_f32_s = 0xAE
    i64_trunc_f32_u = 0xAF
    i64_trunc_f64_s = 0xB0
    i64_trunc_f64_u = 0xB1
    f32_convert_i32_s = 0xB2
    f32_convert_i32_u = 0xB3
    f32_convert_i64_s = 0xB4
    f32_convert_i64_u = 0xB5
    f32_demote_f64 = 0xB6
    f64_convert_i32_s = 0xB7
    f64_convert_i32_u = 0xB8
    f64_convert_i64_s = 0xB9
    f64_convert_i64_u = 0xBA
    f64_promote_f32 = 0xBB
    i32_reinterpret_f32 = 0xBC
    i64_reinterpret_f64 = 0xBD
    f32_reinterpret_i32 = 0xBE
    f64_reinterpret_i64 = 0xBF
    i32_extend8_s = 0xC0
    i32_extend16_s = 0xC1
    i64_extend8_s = 0xC2
    i64_extend16_s = 0xC3
    i64_extend32_s = 0xC4

    ext_fc = 0xFC
    ext_fd = 0xFD


class FCSubOp(IntEnum):
    i32_trunc_sat_f32_s = 0
    i32_trunc_sat_f32_u = 1
    i32_trunc_sat_f64_s = 2
    i32_trunc_sat_f64_u = 3
    i64_trunc_sat_f32_s = 4
    i64_trunc_sat_f32_u = 5
    i64_trunc_sat_f64_s = 6
    i64_trunc_sat_f64_u = 7
    memory_init = 8
    data_drop = 9
    memory_copy = 10
    memory_fill = 11
    table_init = 12
    elem_drop = 13
    table_copy = 14
    table_grow = 15
    table_size = 16
    table_fill = 17


class FDSubOp(IntEnum):
    pass


Op = namedtuple("Op", ["opcode", "subop", "operands"])


def read_fc_subop(r: BinaryIO) -> Op:
    subop = read_u32(r)
    subop = FCSubOp(subop)
    operands = tuple()
    if subop <= 7:
        pass
    elif subop == 12 or subop == 14:
        a = read_u32(r)
        b = read_u32(r)
        operands = (a, b)
    elif subop == 9 or subop == 13 or 15 <= subop <= 17:
        x = read_u32(r)
        operands = (x,)
    elif subop == 8:
        dataidx = read_u32(r)
        operands = (dataidx,)
        assert r.read(1)[0] == 0  # drop
    elif subop == 10:
        r.read(2)  # drop
    elif subop == 11:
        assert r.read(1)[0] == 0  # drop
    else:
        raise ValueError(f"Unknown subop for 0xfc: {subop}")
    return Op(0xFC, subop, operands)


def read_instruction(r: BinaryIO) -> Op:
    op = Opcode(r.read(1)[0])
    if op == 0xFC:
        return read_fc_subop(r)
    if op == 0xB or op == 0x05:
        return Op(op, None, None)
    elif 0x45 <= op <= 0xC4:
        return Op(op, None, None)
    elif op == 0x00 or op == 0x01 or op == 0x0F:
        return Op(op, None, None)
    elif op == 0x1A or op == 0x1B:
        return Op(op, None, None)
    elif op == 0x3F or op == 0x40:
        r.read(1)
        return Op(op, None, None)
    elif op == 0x02 or op == 0x03:
        bt = r.read(1)[0]
        assert bt == 0x40 or 0x7C <= bt <= 0x7F
        expr = read_expr(r).instructions
        return Op(op, bt, (expr,))
    elif op == 0x04:
        bt = r.read(1)[0]
        assert bt == 0x40 or 0x7C <= bt <= 0x7F
        then = read_expr(r, frozenset([0xB, 0x5])).instructions
        else_ = None
        if then[-1].opcode == Opcode.else_:
            else_ = read_expr(r)
        return Op(op, bt, (then, else_))
    elif op == 0xC or op == 0xD:
        label = LabelIdx(read_u32(r))
        return Op(op, None, (label,))
    elif 0x20 <= op <= 0x24:
        arg = read_u32(r)
        return Op(op, None, (arg,))
    elif op == 0x10:
        idx = FuncIdx(read_u32(r))
        return Op(op, None, (idx,))
    elif op == 0x0E:
        v = read_vector(r, decoder=read_u32)
        v = [LabelIdx(z) for z in v]
        a = LabelIdx(read_u32(r))
        return Op(op, None, (v, a))
    elif op == 0x11:
        x = read_u32(r)
        r.read(1)  # TODO: this is contradictory between v1 and v2
        return Op(op, None, (TypeIdx(x),))
    elif 0x28 <= op <= 0x3E:
        a = read_u32(r)
        o = read_u32(r)
        return Op(op, None, (a, o))
    elif op == 0x41:
        n = read_i32(r)
        return Op(op, None, (n,))
    elif op == 0x42:
        n = read_i64(r)
        return Op(op, None, (n,))
    elif op == 0x43:
        n = read_f32(r)
        return Op(op, None, (n,))
    elif op == 0x44:
        n = read_f64(r)
        return Op(op, None, (n,))
    if DEBUG:
        print(f"op = {op:x}")
    assert False


def read_mem(raw: BinaryIO) -> MemType:
    return read_memtype(raw)


def read_table(raw: BinaryIO) -> TableType:
    return read_tabletype(raw)


def read_import(raw: BinaryIO) -> list[Import]:
    mod = read_name(raw)
    nm = read_name(raw)
    d = read_importdesc(raw)
    return Import(mod, nm, d)


def read_importdesc(raw: BinaryIO) -> any:
    t = raw.read(1)[0]
    assert t <= 3
    if t == 0:
        return read_typeidx(raw)
    elif t == 1:
        return read_tabletype(raw)
    elif t == 2:
        return read_memtype(raw)
    else:
        return read_globaltype(raw)


def read_globaltype(raw: BinaryIO) -> GlobalType:
    t = read_valtype(raw)
    m = raw.read(1)[0] == 1
    return GlobalType(t, m)


def read_memtype(raw: BinaryIO) -> MemType:
    limits = read_limits(raw)
    return MemType(limits)


def read_typeidx(raw: BinaryIO) -> TypeIdx:
    x = read_u32(raw)
    return TypeIdx(x)


def read_tabletype(raw: BinaryIO) -> TableType:
    et = read_elemtype(raw)
    lim = read_limits(raw)
    return TableType(et, lim)


def read_limits(raw: BinaryIO) -> Limits:
    t = raw.read(1)[0]
    assert t <= 1
    n = read_u32(raw)
    if t == 0:
        m = None
    else:
        m = read_u32(raw)
    return Limits(n, m)


def read_elemtype(raw: BinaryIO) -> FuncRef:
    assert raw.read(1)[0] == 0x70
    return FuncRef


def parse_type_section(raw: bytes) -> TypeSection:
    r = io.BytesIO(raw)
    function_types = read_vector(r, decoder=read_function_type)
    return TypeSection(function_types)


def read_function_type(raw: BinaryIO) -> FunctionType:
    assert raw.read(1)[0] == 0x60
    parameter_types = read_vector(raw, decoder=read_valtype)
    result_types = read_vector(raw, decoder=read_valtype)
    return FunctionType(parameter_types, result_types)


def read_valtype(raw: BinaryIO) -> ValType:
    return ValType(raw.read(1)[0])


def parse_custom_section(raw: bytes) -> CustomSection:
    r = io.BytesIO(raw)
    name = read_name(r)
    data = r.read()
    return CustomSection(name, data)


def read_name(raw: BinaryIO) -> str:
    name = read_vector_bytes(raw)
    name = name.decode("utf8")
    return name


def read_vector(raw: BinaryIO, decoder: Callable[[BinaryIO], any]) -> list[any]:
    vlen = read_u32(raw)
    v = []
    for _ in range(vlen):
        x = decoder(raw)
        v.append(x)
    return v


def read_vector_bytes(raw: BinaryIO) -> bytes:
    vlen = read_u32(raw)
    return raw.read(vlen)


def read_u32_bytes(f: bytes) -> (int, int):
    l = 0
    b = f[0]
    num = b & 0x7F
    while b & 0x80:
        l += 1
        b = f[l]
        num |= (b & 0x7F) << (7 * l)
    return num, l + 1


def read_u32(f: BinaryIO) -> int:
    l = 0
    b = f.read(1)[0]
    num = b & 0x7F
    while b & 0x80:
        l += 1
        b = f.read(1)[0]
        num |= (b & 0x7F) << (7 * l)
    return num


def read_i32(f: BinaryIO) -> int:
    l = 0
    b = f.read(1)[0]
    num = b & 0x7F
    while b & 0x80:
        l += 7
        b = f.read(1)[0]
        num |= (b & 0x7F) << l
    if b & 0x40:
        num |= (-1) << (l + 6)
    return num


def read_i64(f: BinaryIO) -> int:
    return read_i32(f)


def read_f32(f: BinaryIO) -> float:
    return struct.unpack("<f", f.read(4))[0]


def read_f64(f: BinaryIO) -> float:
    return struct.unpack("<d", f.read(8))[0]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("wasm_file", help="WASM file to execute")
    parser.add_argument("--debug", help="Enable debug output", action="store_true")
    args = parser.parse_args()
    DEBUG = args.debug

    with open(args.wasm_file, "rb") as fin:
        module = read_module(fin.read())
    init_module(module)
