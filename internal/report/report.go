package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/rokoucha/apk-alignment-checker/internal/checker"
)

const pageSizesURL = "https://developer.android.com/guide/practices/page-sizes"

func Text(w io.Writer, results []checker.Result, verbose, color bool) {
	paint := func(code, s string) string {
		if !color {
			return s
		}
		return "\x1b[" + code + "m" + s + "\x1b[0m"
	}
	statusLabel := map[checker.Status]string{
		checker.StatusOK:   paint("32", "✔ OK  "),
		checker.StatusFail: paint("31", "✘ FAIL"),
		checker.StatusSkip: paint("90", "- SKIP"),
	}
	const indent = "        "

	counts := countStatus(results)
	for _, r := range results {
		fmt.Fprintf(w, "%s  %s\n", statusLabel[r.Status], r.Path)
		if r.Error != "" {
			fmt.Fprintf(w, "%s%s\n\n", indent, paint("31", r.Error))
			continue
		}
		fmt.Fprintf(w, "%sABI: %s | LOAD align: %s | GNU_RELRO: %s | ZIP: %s\n", indent,
			r.Machine, checker.FormatAlign(r.LoadAlign), relroSummary(r.Relro), zipSummary(r.Zip))
		switch {
		case r.Status != checker.StatusSkip:
		case !r.Is64Bit:
			fmt.Fprintf(w, "%s%s\n", indent, paint("90", "32-bit library: not required to support 16KB pages"))
		default:
			fmt.Fprintf(w, "%s%s\n", indent, paint("90", "big-endian library: not used on Android"))
		}
		for _, p := range r.Problems {
			fmt.Fprintf(w, "%s%s\n", indent, paint("31", "→ "+p))
		}

		if verbose {
			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', tabwriter.AlignRight)
			fmt.Fprintf(tw, "%s\tType\tFlags\tOffset\tVirtAddr\tFileSiz\tMemSiz\tAlign\t\n", indent)
			for _, s := range r.Segments {
				fmt.Fprintf(tw, "%s\t%s\t%s\t0x%x\t0x%x\t0x%x\t0x%x\t%s\t\n", indent,
					s.Type, s.Flags, s.Offset, s.Vaddr, s.Filesz, s.Memsz, checker.FormatAlign(s.Align))
			}
			tw.Flush()
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "%d libraries: %s, %s, %s\n", len(results),
		paint("32", fmt.Sprintf("%d OK", counts[checker.StatusOK])),
		paint("31", fmt.Sprintf("%d FAIL", counts[checker.StatusFail])),
		paint("90", fmt.Sprintf("%d SKIP", counts[checker.StatusSkip])))
	if counts[checker.StatusFail] > 0 {
		fmt.Fprintln(w, "See "+pageSizesURL)
	}
}

func Annotations(w io.Writer, results []checker.Result) {
	escape := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	for _, r := range results {
		if r.Status != checker.StatusFail {
			continue
		}
		// GitHubはステップごとに10件までしかエラーアノテーションを表示しないので、ライブラリごとに1件にまとめる。
		fmt.Fprintf(w, "::error title=16KB page size::%s\n", escape.Replace(r.Path+": "+strings.Join(issues(r), "; ")))
	}
}

func Markdown(w io.Writer, results []checker.Result) {
	counts := countStatus(results)
	summary := fmt.Sprintf("%d libraries: %d OK, %d FAIL, %d SKIP", len(results),
		counts[checker.StatusOK], counts[checker.StatusFail], counts[checker.StatusSkip])
	if counts[checker.StatusFail] == 0 {
		fmt.Fprintf(w, ":white_check_mark: All native libraries support 16KB page size. (%s)\n", summary)
	} else {
		fmt.Fprintf(w, ":x: %d native libraries do not support 16KB page size. (%s)\n", counts[checker.StatusFail], summary)

		// 失敗したライブラリを入力ファイルごとにまとめる。
		var files []string
		failures := map[string][]checker.Result{}
		for _, r := range results {
			if r.Status != checker.StatusFail {
				continue
			}
			file, _ := splitPath(r.Path)
			if _, ok := failures[file]; !ok {
				files = append(files, file)
			}
			failures[file] = append(failures[file], r)
		}
		for _, file := range files {
			fmt.Fprintln(w)
			if strings.HasSuffix(strings.ToLower(file), ".so") {
				// 直接指定されたライブラリはまとめる必要がない。
				fmt.Fprintf(w, "- %s\n", mdCode(file))
			} else {
				fmt.Fprintf(w, "**%s**\n\n", mdCode(file))
			}
			for _, r := range failures[file] {
				if _, entry := splitPath(r.Path); entry != "" {
					fmt.Fprintf(w, "- %s\n", mdCode(entry))
				}
				for _, p := range issues(r) {
					fmt.Fprintf(w, "  - %s\n", p)
				}
			}
		}
		fmt.Fprintf(w, "\nSee %s\n", pageSizesURL)
	}

	if len(results) == 0 {
		return
	}
	fmt.Fprintf(w, "\n<details><summary>All libraries</summary>\n\n")
	fmt.Fprintf(w, "| Status | Library | ABI | LOAD align | GNU_RELRO | ZIP |\n")
	fmt.Fprintf(w, "| --- | --- | --- | --- | --- | --- |\n")
	for _, r := range results {
		if r.ELFResult == nil {
			fmt.Fprintf(w, "| %s | %s | | | | |\n", r.Status, mdCell(r.Path))
			continue
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s |\n", r.Status, mdCell(r.Path),
			r.Machine, checker.FormatAlign(r.LoadAlign), relroSummary(r.Relro), zipSummary(r.Zip))
	}
	fmt.Fprintf(w, "\n</details>\n")
}

func relroSummary(relros []checker.RelroInfo) string {
	if len(relros) == 0 {
		return "none"
	}
	var parts []string
	for _, r := range relros {
		switch {
		case r.CoversLoad:
			parts = append(parts, fmt.Sprintf("0x%x-0x%x (covers whole LOAD)", r.Start, r.End))
		case r.OK:
			parts = append(parts, fmt.Sprintf("0x%x-0x%x (aligned)", r.Start, r.End))
		default:
			parts = append(parts, fmt.Sprintf("0x%x-0x%x (unaligned)", r.Start, r.End))
		}
	}
	return strings.Join(parts, ", ")
}

func zipSummary(z *checker.ZipInfo) string {
	switch {
	case z == nil:
		return "n/a"
	case z.Compressed:
		return "compressed (extracted on install)"
	case z.OK:
		return fmt.Sprintf("stored @0x%x (aligned)", z.DataOffset)
	default:
		return fmt.Sprintf("stored @0x%x (unaligned)", z.DataOffset)
	}
}

func countStatus(results []checker.Result) map[checker.Status]int {
	counts := map[checker.Status]int{}
	for _, r := range results {
		counts[r.Status]++
	}
	return counts
}

func issues(r checker.Result) []string {
	if r.Error != "" {
		return []string{r.Error}
	}
	if r.ELFResult == nil {
		return nil
	}
	return r.Problems
}

func splitPath(path string) (file, entry string) {
	file, entry, _ = strings.Cut(path, "!/")
	return file, entry
}

func mdCode(s string) string {
	fence := "`"
	for strings.Contains(s, fence) {
		fence += "`"
	}
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		s = " " + s + " "
	}
	return fence + s + fence
}

func mdCell(s string) string {
	return strings.ReplaceAll(mdCode(s), "|", `\|`)
}
