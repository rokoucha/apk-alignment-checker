package checker

import (
	"debug/elf"
	"fmt"
	"io"
	"math/bits"
)

const PageSize = 16 * 1024

type Segment struct {
	Type   string `json:"type"`
	Flags  string `json:"flags"`
	Offset uint64 `json:"offset"`
	Vaddr  uint64 `json:"vaddr"`
	Filesz uint64 `json:"filesz"`
	Memsz  uint64 `json:"memsz"`
	Align  uint64 `json:"align"`
}

type RelroInfo struct {
	End        uint64 `json:"end"`
	ProtectEnd uint64 `json:"protectEnd"`
	Suffix     bool   `json:"suffix"`
	OK         bool   `json:"ok"`
}

type ELFResult struct {
	Machine   string      `json:"machine"`
	Is64Bit   bool        `json:"is64bit"`
	LoadAlign uint64      `json:"loadAlign"` // PT_LOADセグメントのp_alignの最小値
	Relro     []RelroInfo `json:"relro,omitempty"`
	Problems  []string    `json:"problems,omitempty"`
	Segments  []Segment   `json:"segments,omitempty"`
}

var abiNames = map[elf.Machine]string{
	elf.EM_AARCH64: "arm64-v8a",
	elf.EM_X86_64:  "x86_64",
	elf.EM_ARM:     "armeabi-v7a",
	elf.EM_386:     "x86",
	elf.EM_RISCV:   "riscv64",
}

func CheckELF(r io.ReaderAt) (*ELFResult, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	res := &ELFResult{Machine: f.Machine.String(), Is64Bit: f.Class == elf.ELFCLASS64}
	if abi, ok := abiNames[f.Machine]; ok {
		res.Machine = abi
	}

	var loads, relros []*elf.Prog
	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_LOAD:
			loads = append(loads, p)
		case elf.PT_GNU_RELRO:
			relros = append(relros, p)
		default:
			continue
		}
		res.Segments = append(res.Segments, Segment{
			Type:   segmentType(p.Type),
			Flags:  segmentFlags(p.Flags),
			Offset: p.Off,
			Vaddr:  p.Vaddr,
			Filesz: p.Filesz,
			Memsz:  p.Memsz,
			Align:  p.Align,
		})
	}

	if len(loads) == 0 {
		res.Problems = append(res.Problems, "no PT_LOAD segments")
		return res, nil
	}

	// 1. すべてのLOADセグメントが16KB以上にアラインされていること。
	//    また、カーネルがmmapできるようにファイルオフセットと仮想アドレスを16KBで割った余りが一致していること。
	for i, p := range loads {
		if i == 0 || p.Align < res.LoadAlign {
			res.LoadAlign = p.Align
		}
		switch {
		case p.Align&(p.Align-1) != 0:
			res.Problems = append(res.Problems, fmt.Sprintf("LOAD@0x%x: p_align 0x%x is not a power of two", p.Vaddr, p.Align))
		case p.Align < PageSize:
			res.Problems = append(res.Problems, fmt.Sprintf("LOAD@0x%x: p_align %s < 16KB (2**14)", p.Vaddr, FormatAlign(p.Align)))
		case p.Vaddr%PageSize != p.Off%PageSize:
			res.Problems = append(res.Problems, fmt.Sprintf("LOAD@0x%x: p_offset 0x%x is not congruent with p_vaddr modulo 16KB", p.Vaddr, p.Off))
		}
	}

	// 2. bionicはGNU_RELROをpage_end(vaddr+memsz)までmprotectする。16KBページ端末では次の16KB境界まで
	//    切り上げられるので、終端がアラインされていないと後ろにあるRWデータまで読み取り専用になりうる。
	//    例外はGNU_RELROが同じアドレスから始まるLOAD全体を覆っている場合(suffix)で、範囲がそのLOADの終端まで広げられるので安全。
	//    RWデータと重ならない場合もGoogle Playでは警告されるので、終端がアラインされていなければ問題とする。
	//    https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/linker_phdr.cpp
	for _, relro := range relros {
		end, carry := bits.Add64(relro.Vaddr, relro.Memsz, 0)
		if carry != 0 {
			res.Problems = append(res.Problems, fmt.Sprintf("GNU_RELRO@0x%x: vaddr+memsz overflows", relro.Vaddr))
			continue
		}
		info := RelroInfo{End: end, ProtectEnd: (end + PageSize - 1) &^ (PageSize - 1)}
		for _, p := range loads {
			if p.Vaddr == relro.Vaddr && relro.Memsz >= p.Memsz {
				info.Suffix = true
				break
			}
		}
		info.OK = info.Suffix || end%PageSize == 0
		res.Relro = append(res.Relro, info)
		if !info.OK {
			res.Problems = append(res.Problems, relroProblem(info, loads))
		}
	}

	return res, nil
}

func relroProblem(info RelroInfo, loads []*elf.Prog) string {
	msg := fmt.Sprintf("GNU_RELRO: end 0x%x is not 16KB aligned, mprotect(PROT_READ) extends to 0x%x", info.End, info.ProtectEnd)
	// 読み取り専用になってしまう書き込み可能なデータがあれば、その範囲も示す。
	for _, p := range loads {
		if p.Flags&elf.PF_W == 0 {
			continue
		}
		from, to := max(p.Vaddr, info.End), min(p.Vaddr+p.Memsz, info.ProtectEnd)
		if from < to {
			return msg + fmt.Sprintf(" and makes RW data 0x%x-0x%x read-only", from, to)
		}
	}
	return msg
}

func segmentType(t elf.ProgType) string {
	if t == elf.PT_GNU_RELRO {
		return "GNU_RELRO"
	}
	return "LOAD"
}

func segmentFlags(f elf.ProgFlag) string {
	b := []byte("---")
	if f&elf.PF_R != 0 {
		b[0] = 'R'
	}
	if f&elf.PF_W != 0 {
		b[1] = 'W'
	}
	if f&elf.PF_X != 0 {
		b[2] = 'X'
	}
	return string(b)
}

func FormatAlign(a uint64) string {
	if a != 0 && a&(a-1) == 0 {
		return fmt.Sprintf("2**%d", bits.TrailingZeros64(a))
	}
	return fmt.Sprintf("0x%x", a)
}
