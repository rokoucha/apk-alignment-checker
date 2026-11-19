package checker

import (
	"archive/zip"
	"bytes"
	"debug/elf"
	"encoding/binary"
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

	alignedName := "lib/arm64-v8a/libaligned.so"
	apk := buildZip(t, []zipEntry{
		// 先頭のエントリは、ローカルヘッダの拡張フィールドで埋めてデータを16KB境界に置く。
		{name: alignedName, method: zip.Store, data: lib, extra: padding(PageSize - 30 - len(alignedName))},
		{name: "lib/arm64-v8a/libstored.so", method: zip.Store, data: lib},
		{name: "lib/arm64-v8a/libdeflated.so", method: zip.Deflate, data: lib},
		{name: "assets/libasset.so", method: zip.Store, data: lib},
		{name: "assets/executable", method: zip.Store, data: lib},
		{name: "assets/data.bin", method: zip.Store, data: []byte("not an ELF")},
		{name: "lib/arm64-v8a/libbroken.so", method: zip.Store, data: []byte("not an ELF")},
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
		alignedName:                    StatusOK,
		"lib/arm64-v8a/libstored.so":   StatusFail, // ローカルヘッダの直後に格納されるので16KB境界にない
		"lib/arm64-v8a/libdeflated.so": StatusOK,
		"assets/libasset.so":           StatusFail, // lib/以外にあってもZIP内のアラインメントを検査する
		"assets/executable":            StatusFail, // 拡張子ではなくマジックナンバーでELFと判定する
		"lib/arm64-v8a/libbroken.so":   StatusFail, // .soなのにELFとして読めない
	}
	got := map[string]Status{}
	for _, r := range results {
		got[strings.TrimPrefix(r.Path, path+"!/")] = r.Status
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

// paddingはサイズnの拡張フィールドを作る。zipalignと同じヘッダID(0xd935)を使う。
func padding(n int) []byte {
	b := make([]byte, n)
	b[0], b[1] = 0x35, 0xd9
	b[2], b[3] = byte(n-4), byte((n-4)>>8)
	return b
}

type zipEntry struct {
	name   string
	method uint16
	data   []byte
	extra  []byte
}

func buildZip(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: e.method, Extra: e.extra})
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

	// AAB: APK Analyzerに合わせて、AABでもZIP内のアラインメントを検査する。
	aab := buildZip(t, []zipEntry{{name: "base/lib/arm64-v8a/libfoo.so", method: zip.Store, data: lib}})
	if err := os.WriteFile(dir+"/app.aab", aab, 0o644); err != nil {
		t.Fatal(err)
	}
	// APKS: 中のAPKはZIPのアラインメントも含めて検査する。
	apk := buildZip(t, []zipEntry{{name: "lib/arm64-v8a/libfoo.so", method: zip.Store, data: lib}})
	apks := buildZip(t, []zipEntry{{name: "splits/base-arm64_v8a.apk", method: zip.Deflate, data: apk}})
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
		"app.aab!/base/lib/arm64-v8a/libfoo.so":                        StatusFail,
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

func TestScanBigEndianAndUnreadableEntries(t *testing.T) {
	// 64ビットのビッグエンディアンのELF。Androidでは使われないのでSKIPになり、ZIPも検査しない。
	var be bytes.Buffer
	if err := binary.Write(&be, binary.BigEndian, elf.Header64{
		Ident:     [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2MSB), byte(elf.EV_CURRENT)},
		Type:      uint16(elf.ET_DYN),
		Machine:   uint16(elf.EM_AARCH64),
		Version:   uint32(elf.EV_CURRENT),
		Ehsize:    64,
		Phentsize: 56,
		Shentsize: 64,
	}); err != nil {
		t.Fatal(err)
	}
	lib := buildELF(t, elf.EM_AARCH64, []prog{{typ: elf.PT_LOAD, filesz: 0x100, memsz: 0x100, align: 0x4000}})
	apk := buildZip(t, []zipEntry{
		{name: "assets/bigendian", method: zip.Store, data: be.Bytes()},
		{name: "assets/corrupted", method: zip.Deflate, data: lib},
	})

	// 圧縮データの先頭を予約済みのブロック型にして、読み取れないエントリにする。
	zr, err := zip.NewReader(bytes.NewReader(apk), int64(len(apk)))
	if err != nil {
		t.Fatal(err)
	}
	off, err := zr.File[1].DataOffset()
	if err != nil {
		t.Fatal(err)
	}
	apk[off] = 0x07

	path := t.TempDir() + "/app.apk"
	if err := os.WriteFile(path, apk, 0o644); err != nil {
		t.Fatal(err)
	}
	results, err := Scan(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Status{}
	for _, r := range results {
		got[strings.TrimPrefix(r.Path, path+"!/")] = r.Status
	}
	want := map[string]Status{"assets/bigendian": StatusSkip, "assets/corrupted": StatusFail}
	if len(got) != len(want) || got["assets/bigendian"] != StatusSkip || got["assets/corrupted"] != StatusFail {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestScanEscapesControlCharacters(t *testing.T) {
	apk := buildZip(t, []zipEntry{{name: "lib/arm64-v8a/x\n::error::FORGED\n.so", method: zip.Store, data: []byte("invalid")}})
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
