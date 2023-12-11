from collections import namedtuple
from enum import IntEnum
from typing import Callable, BinaryIO, Optional
import sys
import struct
import io

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


def exec_module(mod: Module):
    print("Executing module")
    start: StartSection = None
    functions: FunctionSection = None
    code: CodeSection = None
    typ: TypeSection = None
    data: DataSection = None
    globals_section: GlobalSection = None
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
    if start is None:
        exit("No start section found")

    globals: list[Value] = []
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
        if op.opcode == Opcode.i32_const:
            globals.append(Value(arg, ValType.I32))
        elif op.opcode == Opcode.i64_const:
            globals.append(Value(arg, ValType.I64))
        elif op.opcode == Opcode.f32_const:
            globals.append(Value(arg, ValType.F32))
        elif op.opcode == Opcode.f64_const:
            globals.append(Value(arg, ValType.F64))

    mem = []
    for d in data.seg:
        d: Data
        memidx = d.x
        expr = d.e
        b = d.b
        assert len(expr.instructions) == 2
        assert expr.instructions[0].opcode == Opcode.global_get
        assert expr.instructions[1].opcode == Opcode.end
        idx = globals[expr.instructions[0].operands[0]].val
        if len(mem) < idx + len(b):
            needed = idx + len(b) - len(mem)
            mem.extend([0] * needed)
        for i in range(idx, idx + len(b)):
            mem[i] = b[i - idx]

    f = functions.funcs[start.start.x]
    c = code.code[start.start.x].code
    print(f"Start function idx = {start.start}, type = {typ.function_types[f.x]}")
    parameter_types = typ.function_types[f.x].parameter_types
    result_types = typ.function_types[f.x].result_types
    parameters = [Value(default_values[t], t) for t in parameter_types]
    stack = []
    exec_function(c, parameters, stack, globals, mem, functions, typ, code)


def i32_add(a: int, b: int) -> int:
    mask = 0xFFFFFFFF
    sign = 0x80000000
    a = a & mask
    b = b & mask
    s = (a + b) & mask
    if s & sign:
        s = -(-s & mask)
    return s


class Jump:
    def __init__(self, label: int):
        self.label = label


def exec_instruction(
    inst: "Op",
    locals: list[Value],
    stack: list[Value],
    globals: list[Value],
    mem: list[int],
    functions: FunctionSection,
    typ: TypeSection,
    codes: CodeSection,
) -> Optional[Jump]:
    if inst.opcode == Opcode.end:
        return
    elif inst.opcode == Opcode.local_get:
        stack.append(locals[inst.operands[0]])
        return
    elif inst.opcode == Opcode.i32_load:
        offset = inst.operands[1]
        num = struct.unpack("<i", bytes(mem[offset : offset + 4]))[0]
        stack.append(Value(num, ValType.I32))
        return
    elif inst.opcode == Opcode.i32_store:
        offset = inst.operands[1]
        val = stack.pop()
        data = struct.pack("<i", val.val)
        for i in range(len(data)):
            mem[offset + i] = data[i]
        return
    elif inst.opcode == Opcode.local_set:
        idx = inst.operands[0]
        locals[idx] = stack.pop()
        return
    elif inst.opcode == Opcode.local_tee:
        idx = inst.operands[0]
        locals[idx] = stack[-1]
        return
    elif inst.opcode == Opcode.global_get:
        idx = inst.operands[0]
        stack.append(globals[idx])
        return
    elif inst.opcode == Opcode.global_set:
        idx = inst.operands[0]
        globals[idx] = stack.pop()
        return
    elif inst.opcode == Opcode.i32_const:
        c = inst.operands[0]
        stack.append(Value(c, ValType.I32))
        return
    elif inst.opcode == Opcode.i32_add:
        a = stack.pop()
        b = stack.pop()
        stack.append(Value(i32_add(a.val, b.val), ValType.I32))
        return
    elif inst.opcode == Opcode.i32_eq:
        a = stack.pop()
        b = stack.pop()
        if a.val == b.val:
            stack.append(Value(1, ValType.I32))
        else:
            stack.append(Value(0, ValType.I32))
        return
    elif inst.opcode == Opcode.br_if:
        x = stack.pop()
        label = inst.operands[0].x
        if x.val == 1:
            return Jump(label)
        return
    elif inst.opcode == Opcode.if_:
        then = inst.operands[0]
        else_ = inst.operands[1]
        if stack.pop().val:
            for inst2 in then:
                j = exec_instruction(
                    inst2, locals, stack, globals, mem, functions, typ, codes
                )
                if j is not None:
                    if j.label == 0:
                        break
                    else:
                        return Jump(j.label - 1)
        elif else_:
            for inst2 in else_:
                j = exec_instruction(
                    inst2, locals, stack, globals, mem, functions, typ, codes
                )
                if j is not None:
                    if j.label == 0:
                        break
                    else:
                        return Jump(j.label - 1)
        return
    elif inst.opcode == Opcode.block:
        block = inst.operands[0]
        for inst2 in block:
            j = exec_instruction(
                inst2, locals, stack, globals, mem, functions, typ, codes
            )
            if j is not None:
                if j.label == 0:
                    break
                else:
                    return Jump(j.label - 1)
        return
    elif inst.opcode == Opcode.call:
        fidx = inst.operands[0]

        type_idx = functions.funcs[fidx.x].x
        parameter_types = typ.function_types[type_idx].parameter_types
        code2 = codes.code[fidx.x].code
        parameters = []
        for i in range(len(parameter_types)):
            parameters.append(stack.pop())
        parameters.reverse()
        return exec_function(
            code2, parameters, stack, globals, mem, functions, typ, codes
        )

    print("Unknown instruction")
    print(f"Locals: {locals}")
    print(f"Stack: {stack}")
    print(f"Current instruction: {inst}")
    exit()


def exec_function(
    code: Func,
    parameters: list[Value],
    stack: list[Value],
    globals: list[Value],
    mem: list[int],
    functions: FunctionSection,
    typ: TypeSection,
    codes: CodeSection,
) -> Optional[Jump]:
    locals = []
    for i in range(len(parameters)):
        locals.append(parameters[i])
    for local_type in code.t:
        for i in range(local_type.n):
            locals.append(Value(default_values[local_type.t], local_type.t))
    instructions = code.e.instructions
    pc = 0
    while pc < len(instructions):
        j = exec_instruction(
            instructions[pc], locals, stack, globals, mem, functions, typ, codes
        )
        if j is not None:
            return j
        pc += 1


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
            print(f"Custom section name: {section.name}, length={len(section.bytes)}")
        elif section_id == TYPE_SECTION_ID:
            section = parse_type_section(contents)
            print(f"Type section, num functions = {len(section.function_types)}")
        elif section_id == IMPORT_SECTION_ID:
            section = parse_import_section(contents)
            print(f"Import section, {len(section.imports)} imports")
        elif section_id == FUNCTION_SECTION_ID:
            section = parse_function_section(contents)
            print(f"Function section, {len(section.funcs)} functions")
        elif section_id == TABLE_SECTION_ID:
            section = parse_table_section(contents)
            print(f"Table section, {section.tables}")
        elif section_id == MEMORY_SECTION_ID:
            section = parse_memory_section(contents)
            print(f"Memory section, {section.memories}")
        elif section_id == GLOBAL_SECTION_ID:
            section = parse_global_section(contents)
            print(f"Global section, {len(section.globals)} globals")
        elif section_id == EXPORT_SECTION_ID:
            section = parse_export_section(contents)
            print(f"Export section, {len(section.exports)} exports")
        elif section_id == START_SECTION_ID:
            section = parse_start_section(contents)
            print(f"Start section, {section.start}")
        elif section_id == ELEMENT_SECTION_ID:
            section = parse_element_section(contents)
            print(f"Element section, {len(section.elemsec)} elements")
        elif section_id == CODE_SECTION_ID:
            section = parse_code_section(contents)
            print(f"Code section, {len(section.code)} entries")
        elif section_id == DATA_SECTION_ID:
            section = parse_data_section(contents)
            print(f"Data section, {len(section.seg)} entries")
        else:
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
        print(f"Unknown subop for 0xfc: {subop}")
        assert False
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
        return Op(op, None, (expr,))
    elif op == 0x04:
        bt = r.read(1)[0]
        assert bt == 0x40 or 0x7C <= bt <= 0x7F
        then = read_expr(r, frozenset([0xB, 0x5])).instructions
        else_ = None
        if then[-1].opcode == Opcode.else_:
            else_ = read_expr(r)
        return Op(op, None, (then, else_))
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
    return FuncRef, 1


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
        l += 1
        b = f.read(1)[0]
        num |= (b & 0x7F) << (7 * l)
    if b & 0x40:
        num = (-num) & ((1 << (7 * (l + 1) - 1)) - 1)
        num = -num
    return num


def read_i64(f: BinaryIO) -> int:
    return read_i32(f)


def read_f32(f: BinaryIO) -> float:
    return struct.unpack("<f", f.read(4))[0]


def read_f64(f: BinaryIO) -> float:
    return struct.unpack("<d", f.read(8))[0]


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as fin:
        module = read_module(fin.read())
    exec_module(module)
