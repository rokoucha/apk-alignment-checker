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

type section struct {
	addr, size uint64
}

// buildELFは指定したプログラムヘッダとセクションを持つ最小限の64ビットリトルエンディアンのELF共有オブジェクトを作る。
func buildELF(t *testing.T, machine elf.Machine, progs []prog, sections ...section) []byte {
	t.Helper()
	write := func(buf *bytes.Buffer, v any) {
		if err := binary.Write(buf, binary.LittleEndian, v); err != nil {
			t.Fatal(err)
		}
	}

	phoff := uint64(64)
	strtabOff := phoff + uint64(len(progs))*56
	shoff := (strtabOff + 1 + 7) &^ 7
	hdr := elf.Header64{
		Ident:     [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)},
		Type:      uint16(elf.ET_DYN),
		Machine:   uint16(machine),
		Version:   uint32(elf.EV_CURRENT),
		Phoff:     phoff,
		Ehsize:    64,
		Phentsize: 56,
		Phnum:     uint16(len(progs)),
		Shentsize: 64,
	}
	if len(sections) > 0 {
		// NULLセクションとセクション名の文字列テーブルも必要。
		hdr.Shoff = shoff
		hdr.Shnum = uint16(len(sections) + 2)
		hdr.Shstrndx = 1
	}

	var buf bytes.Buffer
	write(&buf, hdr)
	for _, p := range progs {
		write(&buf, elf.Prog64{Type: uint32(p.typ), Flags: uint32(p.flags), Off: p.off, Vaddr: p.vaddr, Paddr: p.vaddr, Filesz: p.filesz, Memsz: p.memsz, Align: p.align})
	}
	if len(sections) == 0 {
		return buf.Bytes()
	}

	buf.WriteByte(0) // 空の文字列テーブル
	buf.Write(make([]byte, shoff-uint64(buf.Len())))
	write(&buf, elf.Section64{})
	write(&buf, elf.Section64{Type: uint32(elf.SHT_STRTAB), Off: strtabOff, Size: 1})
	for _, s := range sections {
		write(&buf, elf.Section64{Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC), Addr: s.addr, Size: s.size})
	}
	return buf.Bytes()
}

func TestCheckELF(t *testing.T) {
	const rw = elf.PF_R | elf.PF_W
	tests := []struct {
		name     string
		progs    []prog
		sections []section
		problems []string // 期待する問題の部分文字列。合格すべき場合は空
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
			problems: []string{"p_align 2**12 < 16KB"},
		},
		{
			name: "non power of two",
			progs: []prog{
				{typ: elf.PT_LOAD, off: 0, vaddr: 0, filesz: 0x100, memsz: 0x100, align: 0x6000},
			},
			problems: []string{"not a power of two"},
		},
		{
			name: "offset not congruent",
			progs: []prog{
				{typ: elf.PT_LOAD, off: 0x1000, vaddr: 0x4000, filesz: 0x100, memsz: 0x100, align: 0x4000},
			},
			problems: []string{"not congruent"},
		},
		{
			// datastore 1.2.0と同じ形。RELROの終点が16KB境界でもLOADの終端でもない。
			name: "RELRO end unaligned",
			progs: []prog{
				{typ: elf.PT_LOAD, flags: rw, off: 0x8000, vaddr: 0x8000, filesz: 0x4250, memsz: 0x4250, align: 0x4000},
				{typ: elf.PT_GNU_RELRO, off: 0xc000, vaddr: 0xc000, filesz: 0x250, memsz: 0x1000, align: 1},
			},
			sections: []section{{0x8000, 0x4000}, {0xc000, 0x250}},
			problems: []string{"end 0xd000 is neither 16KB aligned nor the end of its LOAD segment, mprotect(PROT_READ) extends to 0x10000"},
		},
		{
			name: "RELRO end unaligned before RW data",
			progs: []prog{
				{typ: elf.PT_LOAD, flags: rw, off: 0x8000, vaddr: 0x8000, filesz: 0x6000, memsz: 0x6000, align: 0x4000},
				{typ: elf.PT_GNU_RELRO, off: 0x8000, vaddr: 0x8000, filesz: 0x5000, memsz: 0x5000, align: 1},
			},
			sections: []section{{0x8000, 0x5000}, {0xd000, 0x1000}},
			problems: []string{"extends to 0x10000 and makes RW data 0xd000-0xe000 read-only"},
		},
		{
			name: "RELRO start unaligned after RW data",
			progs: []prog{
				{typ: elf.PT_LOAD, flags: rw, off: 0x8000, vaddr: 0x8000, filesz: 0x4000, memsz: 0x4000, align: 0x4000},
				{typ: elf.PT_GNU_RELRO, off: 0x9000, vaddr: 0x9000, filesz: 0x3000, memsz: 0x3000, align: 1},
			},
			sections: []section{{0x8000, 0x1000}, {0x9000, 0x3000}},
			problems: []string{"start 0x9000 is neither 16KB aligned nor the start of its LOAD segment, mprotect(PROT_READ) extends down to 0x8000 and makes RW data 0x8000-0x9000 read-only"},
		},
		{
			name: "RELRO start and end unaligned",
			progs: []prog{
				{typ: elf.PT_LOAD, flags: rw, off: 0x8000, vaddr: 0x8000, filesz: 0x8000, memsz: 0x8000, align: 0x4000},
				{typ: elf.PT_GNU_RELRO, off: 0x9000, vaddr: 0x9000, filesz: 0x2000, memsz: 0x2000, align: 1},
			},
			sections: []section{{0x8000, 0x1000}, {0x9000, 0x2000}, {0xb000, 0x5000}},
			problems: []string{"start 0x9000", "end 0xb000"},
		},
		{
			// RELROが16KB境界から始まり、LOADの終端で終わる(suffix)。
			name: "RELRO suffix",
			progs: []prog{
				{typ: elf.PT_LOAD, flags: rw, off: 0x8000, vaddr: 0x8000, filesz: 0x5250, memsz: 0x5250, align: 0x4000},
				{typ: elf.PT_GNU_RELRO, off: 0xc000, vaddr: 0xc000, filesz: 0x1250, memsz: 0x1250, align: 1},
			},
			sections: []section{{0x8000, 0x4000}, {0xc000, 0x1250}},
		},
		{
			// RELROの長さがLOADより切り上げられていても、含まれるセクションが同じなら実質LOAD全体。
			name: "RELRO covers whole LOAD",
			progs: []prog{
				{typ: elf.PT_LOAD, flags: rw, off: 0x4000, vaddr: 0x4000, filesz: 0x1250, memsz: 0x1250, align: 0x4000},
				{typ: elf.PT_LOAD, flags: rw, off: 0x5250, vaddr: 0x9250, filesz: 0x100, memsz: 0x100, align: 0x4000},
				{typ: elf.PT_GNU_RELRO, off: 0x4000, vaddr: 0x4000, filesz: 0x1250, memsz: 0x2000, align: 1},
			},
			sections: []section{{0x4000, 0x1250}, {0x9250, 0x100}},
		},
		{
			name: "RELRO without section headers",
			progs: []prog{
				{typ: elf.PT_LOAD, flags: rw, off: 0x8000, vaddr: 0x8000, filesz: 0x4250, memsz: 0x4250, align: 0x4000},
				{typ: elf.PT_GNU_RELRO, off: 0xc000, vaddr: 0xc000, filesz: 0x250, memsz: 0x1000, align: 1},
			},
		},
		{
			name: "RELRO extends into next LOAD",
			progs: []prog{
				{typ: elf.PT_LOAD, flags: rw, off: 0x4000, vaddr: 0x4000, filesz: 0x1000, memsz: 0x1000, align: 0x4000},
				{typ: elf.PT_LOAD, flags: rw, off: 0x5000, vaddr: 0x5000, filesz: 0x1000, memsz: 0x1000, align: 0x4000},
				{typ: elf.PT_GNU_RELRO, off: 0x4000, vaddr: 0x4000, filesz: 0x2000, memsz: 0x2000, align: 1},
			},
			problems: []string{"extends into the next LOAD segment at 0x5000"},
		},
		{
			name: "RELRO not in LOAD",
			progs: []prog{
				{typ: elf.PT_LOAD, off: 0x4000, vaddr: 0x4000, filesz: 0x100, memsz: 0x100, align: 0x4000},
				{typ: elf.PT_GNU_RELRO, off: 0x1000, vaddr: 0x1000, filesz: 0x100, memsz: 0x100, align: 1},
			},
			problems: []string{"not contained in any LOAD segment"},
		},
		{
			name: "RELRO overflow",
			progs: []prog{
				{typ: elf.PT_LOAD, off: 0, vaddr: 0, filesz: 0x100, memsz: 0x100, align: 0x4000},
				{typ: elf.PT_GNU_RELRO, off: 0, vaddr: 0xffffffffffffc000, filesz: 0, memsz: 0x4000, align: 1},
			},
			problems: []string{"overflows"},
		},
		{
			name: "multiple RELRO",
			progs: []prog{
				{typ: elf.PT_LOAD, off: 0, vaddr: 0, filesz: 0x100, memsz: 0x100, align: 0x4000},
				{typ: elf.PT_GNU_RELRO, off: 0, vaddr: 0xffffffffffffc000, filesz: 0, memsz: 0x4000, align: 1},
				{typ: elf.PT_GNU_RELRO, off: 0, vaddr: 0, filesz: 0x4000, memsz: 0x4000, align: 1},
			},
			problems: []string{"overflows"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := CheckELF(bytes.NewReader(buildELF(t, elf.EM_AARCH64, tt.progs, tt.sections...)))
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Problems) != len(tt.problems) {
				t.Fatalf("problems = %v, want %d problems containing %q", res.Problems, len(tt.problems), tt.problems)
			}
			for i, want := range tt.problems {
				if !strings.Contains(res.Problems[i], want) {
					t.Errorf("problems[%d] = %q, want containing %q", i, res.Problems[i], want)
				}
			}
		})
	}
}
