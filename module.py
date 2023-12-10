from collections import namedtuple
from enum import IntEnum
from typing import Callable, Tuple
import sys

Section = namedtuple('Section', ['section_id', 'contents'])
CustomSection = namedtuple('CustomSection', ['name', 'bytes'])
TypeSection = namedtuple('TypeSection', ['function_types'])
ImportSection = namedtuple('ImportSection', ['imports'])
FunctionType = namedtuple('FunctionType', ['parameter_types', 'result_types'])
Import = namedtuple('Import', ['mod', 'nm', 'd'])
TypeIdx = namedtuple('TypeIdx', ['x'])
TableType = namedtuple('TableType', ['et', 'lim'])
MemType = namedtuple('MemType', ['lim'])
GlobalType = namedtuple('GlobalType', ['t', 'm'])
FuncRef = 0x70
Limits = namedtuple('Limits', ['n', 'm'])

CUSTOM_SECTION_ID = 0
TYPE_SECTION_ID = 1
IMPORT_SECTION_ID = 2

class ValType(IntEnum):
    I32 = 0x7f
    I64 = 0x7e
    F32 = 0x7d
    F64 = 0x7c


def read_module(f: bytes):
    assert f[:4] == b'\0asm'
    assert f[4:8] == b'\x01\0\0\0'
    current = 8
    sections = []
    while current < len(f):
        section_id = f[current]
        current += 1
        section_size, length = read_u32(f[current:])
        current += length
        contents = f[current:current+section_size]
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
        else:
            print(f"Section {section_id}, size = {section_size}")
            section = Section(section_id, contents)
        sections.append(section)


def parse_import_section(raw: bytes) -> ImportSection:
    imports = read_vector(raw, decoder=read_import)
    return ImportSection(imports)


def read_import(raw: bytes) -> (list[Import], int):
    mod, l1 = read_name(raw)
    nm, l2 = read_name(raw[l1:])
    d, l3 = read_importdesc(raw[l1+l2:])
    return Import(mod, nm, d), l1 + l2 + l3

def read_importdesc(raw: bytes) -> (any, int):
    assert raw[0] <= 3
    if raw[0] == 0:
        typeidx, length = read_typeidx(raw[1:])
        return typeidx, length + 1
    elif raw[1] == 1:
        tt, length = read_tabletype(raw[1:])
        return tt, length + 1
    elif raw[1] == 2:
        memtype, length = read_memtype(raw[1:])
        return memtype, length + 1
    else:
        globaltype, length = read_globaltype(raw[1:])
        return globaltype, length + 1


def read_globaltype(raw: bytes) -> (GlobalType, int):
    t, l1 = read_valtype(raw)
    m = raw[l1] == 1
    return GlobalType(t, m), l1 + 1

def read_memtype(raw: bytes) -> (MemType, int):
    limits, length = read_limits(raw)
    return MemType(limits), length

def read_typeidx(raw: bytes) -> (TypeIdx, int):
    x, length = read_u32(raw)
    return TypeIdx(x), length


def read_tabletype(raw: bytes) -> (TableType, int):
    et, l1 = read_elemtype(raw)
    lim, l2 = read_limits(raw[l1:])
    return TableType(et, lim), l1 + l2


def read_limits(raw: bytes) -> (Limits, int):
    assert raw[0] <= 1
    n, l1 = read_u32(raw[1:])
    if raw[0] == 0:
        m = None
        l2 = 0
    else:
        m, l2 = read_u32(raw[1+l1:])
    return Limits(n, m), 1 + l1 + l2

def read_elemtype(raw: bytes) -> (FuncRef, int):
    assert raw[0] == 0x70
    return FuncRef, 1

def parse_type_section(raw: bytes) -> TypeSection:
    function_types = read_vector(raw, decoder=read_function_type)
    return TypeSection(function_types)


def read_function_type(raw: bytes) -> (FunctionType, int):
    assert raw[0] == 0x60
    parameter_types, len = read_vector(raw[1:], decoder=read_valtype)
    result_types, len2 = read_vector(raw[1+len:], decoder=read_valtype)
    return FunctionType(parameter_types, result_types), 1 + len + len2


def read_valtype(raw: bytes) -> (ValType, int):
    return ValType(raw[0]), 1

def parse_custom_section(raw: bytes) -> CustomSection:
    name, length = read_name(raw)
    data = raw[length:]
    return CustomSection(name, data)


def read_name(raw: bytes) -> (str, int):
    name, length = read_vector_bytes(raw)
    name = name.decode('utf8')
    return name, length


def read_vector(raw: bytes, decoder: Callable[[bytes], Tuple[any, int]]) -> (list[any], int):
    vlen, length = read_u32(raw)
    v = []
    for _ in range(vlen):
        x, l = decoder(raw[length:])
        length += l
        v.append(x)
    return v, length


def read_vector_bytes(raw: bytes) -> (bytes, int):
    vlen, length = read_u32(raw)
    return raw[length:length+vlen], length+vlen


def read_u32(f: bytes) -> (int, int):
    l = 0
    num = f[0] & 0x7f
    while f[l] & 0x80:
        l += 1
        num |= (f[l] & 0x7f) << (7*l)
    return num, l + 1


with open(sys.argv[1], 'rb') as fin:
    module = read_module(fin.read())
