package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/rokoucha/apk-alignment-checker/internal/checker"
	"github.com/rokoucha/apk-alignment-checker/internal/report"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("apk-alignment-checker", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "output results as JSON")
	verbose := fs.Bool("v", false, "show program headers of each library")
	markdown := fs.String("markdown", "", "also write a Markdown report to `file` (e.g. for PR comments)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: apk-alignment-checker [-json] [-v] [-markdown file] <file.apk|.aab|.apks|.so|dir>...\n\n")
		fmt.Fprintf(stderr, "Checks that native libraries support 16KB page size devices.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}

	results := []checker.Result{}
	for _, path := range fs.Args() {
		rs, err := checker.Scan(path)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		results = append(results, rs...)
	}

	// 書き込みエラーを1箇所で検出できるように、一度バッファに描画してから書き出す。
	var out bytes.Buffer
	if *jsonOut {
		if !*verbose {
			for _, r := range results {
				if r.ELFResult != nil {
					r.Segments = nil
				}
			}
		}
		enc := json.NewEncoder(&out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
	} else {
		report.Text(&out, results, *verbose, useColor(stdout))
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		report.Annotations(&out, results)
	}
	if _, err := out.WriteTo(stdout); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	if *markdown != "" {
		var buf bytes.Buffer
		report.Markdown(&buf, results)
		if err := os.WriteFile(*markdown, buf.Bytes(), 0o644); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
	}

	for _, r := range results {
		if r.Status == checker.StatusFail {
			return 1
		}
	}
	return 0
}

func useColor(w io.Writer) bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
