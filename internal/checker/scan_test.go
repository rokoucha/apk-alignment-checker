package checker

import (
	"archive/zip"
	"bytes"
	"debug/elf"
	"os"
	"strings"
	"testing"
)

func TestScanFixture(t *testing.T) {
	results, err := Scan("testdata/libdatastore_shared_counter.so")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Status != StatusFail || results[0].Machine != "arm64-v8a" {
		t.Fatalf("unexpected results: %+v", results)
	}
}

func TestScanAPKZipAlignment(t *testing.T) {
	lib := buildELF(t, elf.EM_AARCH64, []prog{{typ: elf.PT_LOAD, filesz: 0x100, memsz: 0x100, align: 0x4000}})

	apk := buildZip(t, []zipEntry{
		{"lib/arm64-v8a/libstored.so", zip.Store, lib},
		{"lib/arm64-v8a/libdeflated.so", zip.Deflate, lib},
		{"assets/libasset.so", zip.Store, lib},
	})
	path := t.TempDir() + "/app.apk"
	if err := os.WriteFile(path, apk, 0o644); err != nil {
		t.Fatal(err)
	}
	results, err := Scan(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Status{
		"lib/arm64-v8a/libstored.so":   StatusFail, // ローカルヘッダの直後に格納されるので16KB境界にない
		"lib/arm64-v8a/libdeflated.so": StatusOK,
		"assets/libasset.so":           StatusOK, // システムがAPKから直接ロードしないのでZIPは検査しない
	}
	if len(results) != len(want) {
		t.Fatalf("got %d results, want %d", len(results), len(want))
	}
	for _, r := range results {
		name := strings.TrimPrefix(r.Path, path+"!/")
		if r.Status != want[name] {
			t.Errorf("%s: status = %s, want %s (problems: %v)", name, r.Status, want[name], r.Problems)
		}
	}
}

type zipEntry struct {
	name   string
	method uint16
	data   []byte
}

func buildZip(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: e.method})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestScanAABAndAPKS(t *testing.T) {
	lib := buildELF(t, elf.EM_AARCH64, []prog{{typ: elf.PT_LOAD, filesz: 0x100, memsz: 0x100, align: 0x4000}})
	dir := t.TempDir()

	// AAB: ZIPのアラインはbundletoolが行うので、アラインされていない非圧縮ライブラリでもOK。
	aab := buildZip(t, []zipEntry{{"base/lib/arm64-v8a/libfoo.so", zip.Store, lib}})
	if err := os.WriteFile(dir+"/app.aab", aab, 0o644); err != nil {
		t.Fatal(err)
	}
	// APKS: 中のAPKはZIPのアラインメントも含めて検査する。
	apk := buildZip(t, []zipEntry{{"lib/arm64-v8a/libfoo.so", zip.Store, lib}})
	apks := buildZip(t, []zipEntry{{"splits/base-arm64_v8a.apk", zip.Deflate, apk}})
	if err := os.WriteFile(dir+"/app.apks", apks, 0o644); err != nil {
		t.Fatal(err)
	}

	results, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Status{}
	for _, r := range results {
		got[strings.TrimPrefix(r.Path, dir+"/")] = r.Status
	}
	want := map[string]Status{
		"app.aab!/base/lib/arm64-v8a/libfoo.so":                        StatusOK,
		"app.apks!/splits/base-arm64_v8a.apk!/lib/arm64-v8a/libfoo.so": StatusFail,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: status = %s, want %s", k, got[k], v)
		}
	}
}

func TestScanEscapesControlCharacters(t *testing.T) {
	apk := buildZip(t, []zipEntry{{"lib/arm64-v8a/x\n::error::FORGED\n.so", zip.Store, []byte("invalid")}})
	path := t.TempDir() + "/app.apk"
	if err := os.WriteFile(path, apk, 0o644); err != nil {
		t.Fatal(err)
	}
	results, err := Scan(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || !strings.HasSuffix(results[0].Path, `!/lib/arm64-v8a/x\n::error::FORGED\n.so`) {
		t.Fatalf("unexpected results: %+v", results)
	}
}
