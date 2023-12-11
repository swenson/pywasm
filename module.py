from collections import namedtuple
from enum import IntEnum
from typing import Callable, Tuple, BinaryIO
import sys
import struct
import io

# necessary for large function parsing
sys.setrecursionlimit(100000)

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
# START_SECTION_ID = 8
ELEMENT_SECTION_ID = 9
CODE_SECTION_ID = 10
DATA_SECTION_ID = 11


class ValType(IntEnum):
    I32 = 0x7F
    I64 = 0x7E
    F32 = 0x7D
    F64 = 0x7C


def read_module(f: bytes):
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
            print(f"Import section, {section.imports}")
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
            print(f"Global section, {section.globals}")
        elif section_id == EXPORT_SECTION_ID:
            section = parse_export_section(contents)
            print(f"Export section, {section.exports}")
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


def read_expr(raw: BinaryIO, term=0xB) -> Expr:
    instructions = []
    p = peek(raw)
    while p != term:
        instr = read_instruction(raw)
        instructions.append(instr)
        p = peek(raw)
    assert raw.read(1)[0] == term
    instructions.append(term)
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


def read_instruction(raw: BinaryIO) -> bytes:
    op = raw.read(1)[0]
    bop = bytes((op,))

    if op == 0xFC:
        subop = read_u32(raw)
        if subop <= 7:
            pass
        elif subop == 12 or subop == 14:
            read_u32(raw)
            read_u32(raw)
        elif subop == 9 or subop == 13 or 15 <= subop <= 17:
            read_u32(raw)
        elif subop == 8:
            read_u32(raw)
            assert raw.read(1)[0] == 0
        elif subop == 10:
            raw.read(2)
        elif subop == 11:
            assert raw.read(1)[0] == 0
        else:
            print(f"Unknown subop for 0xfc: {subop}")
            assert False

        return op

    if op == 0xB or op == 0x05:
        return bop
    elif 0x45 <= op <= 0xBF:
        return bop
    elif op == 0x00 or op == 0x01 or op == 0x0F:
        return bop
    elif op == 0x1A or op == 0x1B:
        return bop
    elif op == 0x3F or op == 0x40:
        raw.read(1)
        return bop
    elif 0x02 <= op <= 0x04:
        x = raw.read(1)[0]
        assert x == 0x40 or 0x7C <= x <= 0x7F
        read_expr(raw)
        return bop
    elif op == 0xC or op == 0xD or op == 0x10 or (0x20 <= op <= 0x24):
        read_u32(raw)
        return bop
    elif op == 0x0E:
        read_vector(raw, decoder=read_u32)
        read_u32(raw)
        return bop
    elif op == 0x11:
        read_u32(raw)
        raw.read(1)
        return bop
    elif 0x28 <= op <= 0x3E:
        read_u32(raw)
        read_u32(raw)
        return bop
    elif op == 0x41:
        read_i32(raw)
        return bop
    elif op == 0x42:
        read_i64(raw)
        return bop
    elif op == 0x43:
        read_f32(raw)
        return bop
    elif op == 0x44:
        read_f64(raw)
        return bop
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


with open(sys.argv[1], "rb") as fin:
    module = read_module(fin.read())
