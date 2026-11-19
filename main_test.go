package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

const fixture = "internal/checker/testdata/libdatastore_shared_counter.so"

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestRunWriteError(t *testing.T) {
	for _, args := range [][]string{{fixture}, {"-json", fixture}} {
		if code := run(args, errWriter{}, io.Discard); code != 2 {
			t.Errorf("run(%v) = %d, want 2", args, code)
		}
	}
}

func TestRunMarkdownAndAnnotations(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	md := t.TempDir() + "/report.md"
	var stdout bytes.Buffer
	if code := run([]string{"-markdown", md, fixture}, &stdout, &bytes.Buffer{}); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "::error title=16KB page size::"+fixture+": GNU_RELRO") {
		t.Errorf("annotation not found in:\n%s", stdout.String())
	}
	b, err := os.ReadFile(md)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), ":x: 1 native libraries") {
		t.Errorf("unexpected report:\n%s", b)
	}
}
