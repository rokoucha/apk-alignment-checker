package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rokoucha/apk-alignment-checker/internal/checker"
)

var reportResults = []checker.Result{
	{Path: "app.apk!/lib/arm64-v8a/libok.so", Status: checker.StatusOK, ELFResult: &checker.ELFResult{Machine: "arm64-v8a", LoadAlign: checker.PageSize}},
	{Path: "app.apk!/lib/arm64-v8a/libng.so", Status: checker.StatusFail, ELFResult: &checker.ELFResult{Machine: "arm64-v8a", LoadAlign: 0x1000, Problems: []string{"problem 1", "problem\n2"}}},
	{Path: "lib/libbroken.so", Status: checker.StatusFail, Error: "not a valid ELF: 100%"},
}

func TestAnnotations(t *testing.T) {
	var buf bytes.Buffer
	Annotations(&buf, reportResults)
	want := "::error title=16KB page size::app.apk!/lib/arm64-v8a/libng.so: problem 1; problem%0A2\n" +
		"::error title=16KB page size::lib/libbroken.so: not a valid ELF: 100%25\n"
	if got := buf.String(); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestMarkdown(t *testing.T) {
	var buf bytes.Buffer
	Markdown(&buf, reportResults)
	got := buf.String()
	for _, want := range []string{
		":x: 2 native libraries do not support 16KB page size. (3 libraries: 1 OK, 2 FAIL, 0 SKIP)",
		"**`app.apk`**\n\n- `lib/arm64-v8a/libng.so`\n  - problem 1\n",
		"- `lib/libbroken.so`\n  - not a valid ELF: 100%\n",
		"| OK | `app.apk!/lib/arm64-v8a/libok.so` | arm64-v8a | 2**14 | none | n/a |",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "libok.so`\n") {
		t.Errorf("OK library listed as failure:\n%s", got)
	}

	buf.Reset()
	Markdown(&buf, reportResults[:1])
	if !strings.HasPrefix(buf.String(), ":white_check_mark: All native libraries support 16KB page size.") {
		t.Errorf("unexpected report:\n%s", buf.String())
	}
}

func TestMarkdownEscape(t *testing.T) {
	for in, want := range map[string]string{
		"lib/libfoo.so": "`lib/libfoo.so`",
		"lib/a`b.so":    "``lib/a`b.so``",
		"`lib/a.so":     "`` `lib/a.so ``",
		"lib/a|b.so":    "`lib/a|b.so`",
	} {
		if got := mdCode(in); got != want {
			t.Errorf("mdCode(%q) = %q, want %q", in, got, want)
		}
	}
	if got, want := mdCell("lib/a|b.so"), "`lib/a\\|b.so`"; got != want {
		t.Errorf("mdCell = %q, want %q", got, want)
	}
}
