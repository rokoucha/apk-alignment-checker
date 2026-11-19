package checker

import (
	"cmp"
	"debug/elf"
	"fmt"
	"io"
	"math"
	"math/bits"
	"slices"
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
	Start      uint64 `json:"start"`
	End        uint64 `json:"end"`
	CoversLoad bool   `json:"coversLoad"`
	OK         bool   `json:"ok"`
}

type ELFResult struct {
	Machine      string      `json:"machine"`
	Is64Bit      bool        `json:"is64bit"`
	LittleEndian bool        `json:"littleEndian"`
	LoadAlign    uint64      `json:"loadAlign"` // PT_LOADセグメントのp_alignの最小値
	Relro        []RelroInfo `json:"relro,omitempty"`
	Problems     []string    `json:"problems,omitempty"`
	Segments     []Segment   `json:"segments,omitempty"`
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

	res := &ELFResult{Machine: f.Machine.String(), Is64Bit: f.Class == elf.ELFCLASS64, LittleEndian: f.Data == elf.ELFDATA2LSB}
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

	// 2. GNU_RELROはAndroid StudioのAPK Analyzerと同じ条件で検査する。
	//    bionicはRELROをpage_start(始点)からpage_end(終点)までmprotectするので、16KBページ端末では
	//    範囲が16KB境界まで広がり、隣にあるRWデータまで読み取り専用になりうる。
	sorted := slices.SortedStableFunc(slices.Values(loads), func(a, b *elf.Prog) int { return cmp.Compare(a.Vaddr, b.Vaddr) })
	for _, relro := range relros {
		info, problems := checkRelro(relro, sorted, f.Sections)
		if info != nil {
			res.Relro = append(res.Relro, *info)
		}
		res.Problems = append(res.Problems, problems...)
	}

	return res, nil
}

func checkRelro(relro *elf.Prog, loads []*elf.Prog, sections []*elf.Section) (*RelroInfo, []string) {
	end, carry := bits.Add64(relro.Vaddr, relro.Memsz, 0)
	if carry != 0 {
		return nil, []string{fmt.Sprintf("GNU_RELRO@0x%x: vaddr+memsz overflows", relro.Vaddr)}
	}

	// RELROを含むLOADは、RELROの始点以前から始まる最後のLOAD。
	i := -1
	for j, p := range loads {
		if p.Vaddr <= relro.Vaddr {
			i = j
		}
	}
	if i == -1 {
		return nil, []string{fmt.Sprintf("GNU_RELRO@0x%x: not contained in any LOAD segment", relro.Vaddr)}
	}
	load := loads[i]
	loadEnd := segmentEnd(load.Vaddr, load.Memsz)
	info := &RelroInfo{Start: relro.Vaddr, End: end}

	// RELROが次のLOADにはみ出していないこと。
	if i+1 < len(loads) && end > loads[i+1].Vaddr {
		return info, []string{fmt.Sprintf("GNU_RELRO: end 0x%x extends into the next LOAD segment at 0x%x", end, loads[i+1].Vaddr)}
	}

	// RELROとLOADに含まれるセクションが同じなら、RELROは実質LOAD全体なので問題ない。
	if slices.Equal(containedSections(sections, relro.Vaddr, end), containedSections(sections, load.Vaddr, loadEnd)) {
		info.CoversLoad, info.OK = true, true
		return info, nil
	}

	var problems []string
	// 始点は16KB境界か、LOADの先頭であること(prefix)。
	if relro.Vaddr%PageSize != 0 && relro.Vaddr != load.Vaddr {
		from := relro.Vaddr &^ (PageSize - 1)
		problems = append(problems, fmt.Sprintf("GNU_RELRO: start 0x%x is neither 16KB aligned nor the start of its LOAD segment, mprotect(PROT_READ) extends down to 0x%x%s",
			relro.Vaddr, from, rwOverlap(loads, from, relro.Vaddr)))
	}
	// 終点は16KB境界か、LOADの終端であること(suffix)。
	if end%PageSize != 0 && end != loadEnd {
		to := segmentEnd(end, PageSize-1) &^ (PageSize - 1)
		problems = append(problems, fmt.Sprintf("GNU_RELRO: end 0x%x is neither 16KB aligned nor the end of its LOAD segment, mprotect(PROT_READ) extends to 0x%x%s",
			end, to, rwOverlap(loads, end, to)))
	}
	info.OK = len(problems) == 0
	return info, problems
}

type sectionRange struct{ addr, size uint64 }

func containedSections(sections []*elf.Section, start, end uint64) []sectionRange {
	var r []sectionRange
	for _, s := range sections {
		if s.Addr >= start && segmentEnd(s.Addr, s.Size) <= end {
			r = append(r, sectionRange{s.Addr, s.Size})
		}
	}
	slices.SortStableFunc(r, func(a, b sectionRange) int { return cmp.Compare(a.addr, b.addr) })
	return r
}

func rwOverlap(loads []*elf.Prog, from, to uint64) string {
	for _, p := range loads {
		if p.Flags&elf.PF_W == 0 {
			continue
		}
		f, t := max(p.Vaddr, from), min(segmentEnd(p.Vaddr, p.Memsz), to)
		if f < t {
			return fmt.Sprintf(" and makes RW data 0x%x-0x%x read-only", f, t)
		}
	}
	return ""
}

func segmentEnd(addr, size uint64) uint64 {
	end, carry := bits.Add64(addr, size, 0)
	if carry != 0 {
		return math.MaxUint64
	}
	return end
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
