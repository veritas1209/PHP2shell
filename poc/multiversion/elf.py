"""Small bounds-checked ELF64 reader used by the offline profile tooling."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class ElfError(ValueError):
    pass


PT_LOAD = 1
PF_X = 1
SHT_SYMTAB = 2
SHT_NOTE = 7
SHT_DYNSYM = 11
SHN_UNDEF = 0
STT_FUNC = 2
NT_GNU_BUILD_ID = 3


@dataclass(frozen=True)
class Section:
    name_index: int
    kind: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int


@dataclass(frozen=True)
class Segment:
    kind: int
    flags: int
    offset: int
    virtual_address: int
    file_size: int
    memory_size: int


@dataclass(frozen=True)
class ElfMetadata:
    sha256: str
    gnu_build_id: str | None
    elf_class: int
    endianness: str
    machine: str
    elf_type: str
    symbols: dict[str, int]

    def as_dict(self) -> dict:
        return {
            "sha256": self.sha256,
            "gnu_build_id": self.gnu_build_id,
            "elf_class": self.elf_class,
            "endianness": self.endianness,
            "machine": self.machine,
            "type": self.elf_type,
            "symbols": {
                name: {"name": name, "offset": hex(offset)}
                for name, offset in sorted(self.symbols.items())
            },
        }


class ElfFile:
    def __init__(self, raw: bytes, *, label: str = "ELF"):
        self.raw = raw
        self.label = label
        if len(raw) < 64:
            raise ElfError(f"{label}: truncated ELF header")
        if raw[:4] != b"\x7fELF":
            raise ElfError(f"{label}: not an ELF file")
        if raw[4] != 2:
            raise ElfError(f"{label}: only ELF64 is supported")
        if raw[5] != 1:
            raise ElfError(f"{label}: only little-endian ELF is supported")
        if raw[6] != 1:
            raise ElfError(f"{label}: unsupported ELF ident version")
        try:
            header = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
        except struct.error as exc:
            raise ElfError(f"{label}: truncated ELF header") from exc
        (
            self.e_type,
            self.e_machine,
            version,
            _entry,
            phoff,
            shoff,
            _flags,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
        ) = header
        if self.e_type != 3:
            raise ElfError(f"{label}: expected ET_DYN, got {self.e_type}")
        if self.e_machine != 62:
            raise ElfError(f"{label}: expected EM_X86_64, got {self.e_machine}")
        if version != 1 or ehsize != 64:
            raise ElfError(f"{label}: invalid ELF header version/size")
        if phnum and phentsize != 56:
            raise ElfError(f"{label}: unexpected program-header entry size")
        if shnum and shentsize != 64:
            raise ElfError(f"{label}: unexpected section-header entry size")
        self._bounds(phoff, phentsize * phnum, "program-header table")
        self._bounds(shoff, shentsize * shnum, "section-header table")
        if shnum == 0:
            raise ElfError(f"{label}: extended/empty section tables are not supported")
        if shstrndx >= shnum:
            raise ElfError(f"{label}: invalid section-name table index")

        self.segments: list[Segment] = []
        for idx in range(phnum):
            off = phoff + idx * phentsize
            kind, flags, p_off, vaddr, _paddr, filesz, memsz, _align = struct.unpack_from(
                "<IIQQQQQQ", raw, off
            )
            self._bounds(p_off, filesz, f"segment {idx}")
            if filesz > memsz:
                raise ElfError(f"{label}: segment {idx} file size exceeds memory size")
            self.segments.append(Segment(kind, flags, p_off, vaddr, filesz, memsz))

        self.sections: list[Section] = []
        for idx in range(shnum):
            off = shoff + idx * shentsize
            values = struct.unpack_from("<IIQQQQIIQQ", raw, off)
            section = Section(*values)
            if section.kind != 8:  # SHT_NOBITS occupies no bytes in the file.
                self._bounds(section.offset, section.size, f"section {idx}")
            if section.link >= shnum and section.link != 0:
                raise ElfError(f"{label}: section {idx} has an invalid link")
            self.sections.append(section)

    def _bounds(self, offset: int, size: int, what: str) -> None:
        if offset < 0 or size < 0 or offset > len(self.raw) or size > len(self.raw) - offset:
            raise ElfError(f"{self.label}: {what} is out of file bounds")

    def _section_bytes(self, index: int) -> bytes:
        try:
            section = self.sections[index]
        except IndexError as exc:
            raise ElfError(f"{self.label}: bad section index {index}") from exc
        if section.kind == 8:
            return b""
        return self.raw[section.offset:section.offset + section.size]

    @staticmethod
    def _cstring(table: bytes, offset: int, what: str) -> str:
        if offset < 0 or offset >= len(table):
            raise ElfError(f"{what}: string offset out of bounds")
        end = table.find(b"\x00", offset)
        if end < 0:
            raise ElfError(f"{what}: unterminated string")
        try:
            return table[offset:end].decode("utf-8")
        except UnicodeError as exc:
            raise ElfError(f"{what}: invalid UTF-8 string") from exc

    def _in_executable_load(self, value: int) -> bool:
        return any(
            seg.kind == PT_LOAD
            and seg.flags & PF_X
            and seg.virtual_address <= value < seg.virtual_address + seg.memory_size
            for seg in self.segments
        )

    def resolve_functions(self, names: Iterable[str]) -> dict[str, int]:
        wanted = set(names)
        found: dict[str, list[tuple[int, int, int]]] = {name: [] for name in wanted}
        saw_symbol_table = False
        for sec_idx, section in enumerate(self.sections):
            if section.kind not in (SHT_SYMTAB, SHT_DYNSYM):
                continue
            saw_symbol_table = True
            if section.entry_size != 24 or section.size % section.entry_size:
                raise ElfError(f"{self.label}: malformed symbol table {sec_idx}")
            if section.link >= len(self.sections):
                raise ElfError(f"{self.label}: bad symbol string-table link")
            strings = self._section_bytes(section.link)
            for item in range(section.size // section.entry_size):
                off = section.offset + item * section.entry_size
                st_name, st_info, _other, st_shndx, st_value, st_size = struct.unpack_from(
                    "<IBBHQQ", self.raw, off
                )
                name = self._cstring(strings, st_name, f"{self.label} symbol {item}")
                if name not in wanted:
                    continue
                if st_shndx == SHN_UNDEF:
                    continue
                if st_info & 0xF != STT_FUNC:
                    raise ElfError(f"{self.label}: {name} is defined but is not STT_FUNC")
                if not self._in_executable_load(st_value):
                    raise ElfError(f"{self.label}: {name} is outside executable PT_LOAD")
                found[name].append((st_value, st_size, st_shndx))
        if not saw_symbol_table:
            raise ElfError(f"{self.label}: no symbol table (stripped module)")
        resolved: dict[str, int] = {}
        for name, entries in found.items():
            unique = set(entries)
            if not unique:
                raise ElfError(f"{self.label}: required function {name!r} is missing")
            # The same function may occur once in .dynsym and once in .symtab.
            if len(unique) != 1:
                values = ", ".join(hex(x[0]) for x in sorted(unique))
                raise ElfError(f"{self.label}: ambiguous function {name!r}: {values}")
            resolved[name] = next(iter(unique))[0]
        return resolved

    def gnu_build_id(self) -> str | None:
        ids: set[str] = set()
        for sec_idx, section in enumerate(self.sections):
            if section.kind != SHT_NOTE:
                continue
            data = self._section_bytes(sec_idx)
            pos = 0
            while pos < len(data):
                if len(data) - pos < 12:
                    raise ElfError(f"{self.label}: truncated note header")
                namesz, descsz, note_type = struct.unpack_from("<III", data, pos)
                pos += 12
                name_end = pos + namesz
                name_pad_end = (name_end + 3) & ~3
                desc_end = name_pad_end + descsz
                desc_pad_end = (desc_end + 3) & ~3
                if desc_pad_end > len(data):
                    raise ElfError(f"{self.label}: truncated note payload")
                name = data[pos:name_end].rstrip(b"\x00")
                desc = data[name_pad_end:desc_end]
                if name == b"GNU" and note_type == NT_GNU_BUILD_ID:
                    ids.add(desc.hex())
                pos = desc_pad_end
        if len(ids) > 1:
            raise ElfError(f"{self.label}: multiple different GNU build IDs")
        return next(iter(ids), None)


def inspect_elf(path: str | Path, names: Iterable[str] = ("zif_system", "zval_ptr_dtor")) -> ElfMetadata:
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as exc:
        raise ElfError(f"cannot read {p}: {exc}") from exc
    elf = ElfFile(raw, label=str(p))
    return ElfMetadata(
        sha256=hashlib.sha256(raw).hexdigest(),
        gnu_build_id=elf.gnu_build_id(),
        elf_class=64,
        endianness="little",
        machine="EM_X86_64",
        elf_type="ET_DYN",
        symbols=elf.resolve_functions(names),
    )


def verify_elf_against_profile(path: str | Path, profile: object) -> ElfMetadata:
    """Verify a module against a loaded Profile without importing profile.py."""
    meta = inspect_elf(path)
    raw = profile.raw  # type: ignore[attr-defined]
    expected = raw["build"]["libphp"]
    checks = {
        "sha256": meta.sha256,
        "gnu_build_id": meta.gnu_build_id,
        "elf_class": meta.elf_class,
        "endianness": meta.endianness,
        "machine": meta.machine,
        "type": meta.elf_type,
    }
    for key, actual in checks.items():
        if expected[key] != actual:
            raise ElfError(f"libphp {key} mismatch: expected {expected[key]!r}, got {actual!r}")
    for name, actual in meta.symbols.items():
        expected_offset = int(raw["symbols"][name]["offset"], 16)
        if actual != expected_offset:
            raise ElfError(
                f"libphp symbol {name} mismatch: expected {hex(expected_offset)}, got {hex(actual)}"
            )
    return meta

