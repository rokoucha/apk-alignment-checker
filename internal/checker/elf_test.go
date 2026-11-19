package checker

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"strings"
	"testing"
)

type prog struct {
	typ                              elf.ProgType
	flags                            elf.ProgFlag
	off, vaddr, filesz, memsz, align uint64
}

func buildELF(t *testing.T, machine elf.Machine, progs []prog) []byte {
	t.Helper()
	var buf bytes.Buffer
	hdr := elf.Header64{
		Ident:     [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)},
		Type:      uint16(elf.ET_DYN),
		Machine:   uint16(machine),
		Version:   uint32(elf.EV_CURRENT),
		Phoff:     64,
		Ehsize:    64,
		Phentsize: 56,
		Phnum:     uint16(len(progs)),
		Shentsize: 64,
	}
	if err := binary.Write(&buf, binary.LittleEndian, hdr); err != nil {
		t.Fatal(err)
	}
	for _, p := range progs {
		ph := elf.Prog64{Type: uint32(p.typ), Flags: uint32(p.flags), Off: p.off, Vaddr: p.vaddr, Paddr: p.vaddr, Filesz: p.filesz, Memsz: p.memsz, Align: p.align}
		if err := binary.Write(&buf, binary.LittleEndian, ph); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func TestCheckELF(t *testing.T) {
	tests := []struct {
		name    string
		progs   []prog
		problem string // 期待する問題の部分文字列。合格すべき場合は空
	}{
		{
			name: "aligned",
			progs: []prog{
				{typ: elf.PT_LOAD, off: 0, vaddr: 0, filesz: 0x100, memsz: 0x100, align: 0x4000},
				{typ: elf.PT_LOAD, off: 0x4000, vaddr: 0x4000, filesz: 0x100, memsz: 0x100, align: 0x4000},
				{typ: elf.PT_GNU_RELRO, off: 0x4000, vaddr: 0x4000, filesz: 0x100, memsz: 0x4000, align: 1},
			},
		},
		{
			name: "64KB aligned",
			progs: []prog{
				{typ: elf.PT_LOAD, off: 0, vaddr: 0, filesz: 0x100, memsz: 0x100, align: 0x10000},
			},
		},
		{
			name: "4KB aligned LOAD",
			progs: []prog{
				{typ: elf.PT_LOAD, off: 0, vaddr: 0, filesz: 0x100, memsz: 0x100, align: 0x1000},
			},
			problem: "p_align 2**12 < 16KB",
		},
		{
			name: "non power of two",
			progs: []prog{
				{typ: elf.PT_LOAD, off: 0, vaddr: 0, filesz: 0x100, memsz: 0x100, align: 0x6000},
			},
			problem: "not a power of two",
		},
		{
			name: "offset not congruent",
			progs: []prog{
				{typ: elf.PT_LOAD, off: 0x1000, vaddr: 0x4000, filesz: 0x100, memsz: 0x100, align: 0x4000},
			},
			problem: "not congruent",
		},
		{
			name: "RELRO unaligned end",
			progs: []prog{
				{typ: elf.PT_LOAD, off: 0x8000, vaddr: 0x8000, filesz: 0x4250, memsz: 0x4250, align: 0x4000},
				{typ: elf.PT_GNU_RELRO, off: 0xc000, vaddr: 0xc000, filesz: 0x250, memsz: 0x1000, align: 1},
			},
			problem: "end 0xd000 is not 16KB aligned, mprotect(PROT_READ) extends to 0x10000",
		},
		{
			name: "RELRO unaligned end before RW data",
			progs: []prog{
				{typ: elf.PT_LOAD, flags: elf.PF_R | elf.PF_W, off: 0x8000, vaddr: 0x8000, filesz: 0x6000, memsz: 0x6000, align: 0x4000},
				{typ: elf.PT_GNU_RELRO, off: 0x8000, vaddr: 0x8000, filesz: 0x5000, memsz: 0x5000, align: 1},
			},
			problem: "makes RW data 0xd000-0xe000 read-only",
		},
		{
			name: "multiple RELRO",
			progs: []prog{
				{typ: elf.PT_LOAD, off: 0, vaddr: 0, filesz: 0x100, memsz: 0x100, align: 0x4000},
				{typ: elf.PT_GNU_RELRO, off: 0, vaddr: 0xffffffffffffc000, filesz: 0, memsz: 0x4000, align: 1},
				{typ: elf.PT_GNU_RELRO, off: 0, vaddr: 0, filesz: 0x4000, memsz: 0x4000, align: 1},
			},
			problem: "overflows",
		},
		{
			name: "RELRO suffix with unaligned end",
			progs: []prog{
				{typ: elf.PT_LOAD, off: 0x4000, vaddr: 0x4000, filesz: 0x1250, memsz: 0x1250, align: 0x4000},
				{typ: elf.PT_GNU_RELRO, off: 0x4000, vaddr: 0x4000, filesz: 0x1250, memsz: 0x1250, align: 1},
			},
		},
		{
			name: "RELRO overflow",
			progs: []prog{
				{typ: elf.PT_LOAD, off: 0, vaddr: 0, filesz: 0x100, memsz: 0x100, align: 0x4000},
				{typ: elf.PT_GNU_RELRO, off: 0, vaddr: 0xffffffffffffc000, filesz: 0, memsz: 0x4000, align: 1},
			},
			problem: "overflows",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := CheckELF(bytes.NewReader(buildELF(t, elf.EM_AARCH64, tt.progs)))
			if err != nil {
				t.Fatal(err)
			}
			if tt.problem == "" {
				if len(res.Problems) != 0 {
					t.Errorf("unexpected problems: %v", res.Problems)
				}
				return
			}
			if len(res.Problems) != 1 || !strings.Contains(res.Problems[0], tt.problem) {
				t.Errorf("problems = %v, want one containing %q", res.Problems, tt.problem)
			}
		})
	}
}
