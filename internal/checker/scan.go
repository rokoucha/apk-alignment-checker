package checker

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

type Status string

const (
	StatusOK   Status = "OK"
	StatusFail Status = "FAIL"
	StatusSkip Status = "SKIP"
)

type ZipInfo struct {
	Compressed bool   `json:"compressed"`
	DataOffset uint64 `json:"dataOffset"`
	OK         bool   `json:"ok"`
}

type Result struct {
	Path   string `json:"path"`
	Status Status `json:"status"`
	*ELFResult
	Zip   *ZipInfo `json:"zip,omitempty"`
	Error string   `json:"error,omitempty"`
}

type archiveKind int

const (
	kindAPK  archiveKind = iota // ネイティブライブラリのZIP内のアラインメントも検査する
	kindAAB                     // APK生成時にbundletoolがアラインするのでZIPは検査しない
	kindAPKS                    // 中のAPKを検査する
)

func Scan(path string) ([]Result, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return scanFile(path)
	}

	var results []Result
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() && isTarget(p) {
			rs, err := scanFile(p)
			if err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			results = append(results, rs...)
		}
		return nil
	})
	return results, err
}

func isTarget(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".so", ".apk", ".aab", ".apks", ".zip":
		return true
	}
	return false
}

func scanFile(path string) ([]Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	name := printable(path)
	if strings.EqualFold(filepath.Ext(path), ".so") {
		return []Result{checkLibrary(name, f, nil)}, nil
	}

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return scanArchive(name, f, info.Size(), kindOf(path))
}

func kindOf(name string) archiveKind {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".aab":
		return kindAAB
	case ".apks", ".zip":
		return kindAPKS
	}
	return kindAPK
}

func scanArchive(name string, r io.ReaderAt, size int64, kind archiveKind) ([]Result, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, err
	}

	var results []Result
	for _, zf := range zr.File {
		entry := name + "!/" + printable(zf.Name)
		lower := strings.ToLower(zf.Name)

		if kind == kindAPKS && strings.HasSuffix(lower, ".apk") {
			// .apks内のAPKは圧縮されていることがあるので、メモリに読み込んでから開く。
			data, err := readEntry(zf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", entry, err)
			}
			rs, err := scanArchive(entry, bytes.NewReader(data), int64(len(data)), kindAPK)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", entry, err)
			}
			results = append(results, rs...)
			continue
		}

		if !strings.HasSuffix(lower, ".so") || zf.FileInfo().IsDir() {
			continue
		}

		var zi *ZipInfo
		// システムがAPKから直接ロードするのはlib/以下のライブラリだけ。
		if kind == kindAPK && strings.HasPrefix(zf.Name, "lib/") {
			zi = zipInfo(zf)
		}

		data, err := readEntry(zf)
		if err != nil {
			results = append(results, Result{Path: entry, Status: StatusFail, Error: err.Error()})
			continue
		}
		results = append(results, checkLibrary(entry, bytes.NewReader(data), zi))
	}
	return results, nil
}

func zipInfo(zf *zip.File) *ZipInfo {
	zi := &ZipInfo{Compressed: zf.Method != zip.Store}
	if off, err := zf.DataOffset(); err == nil {
		zi.DataOffset = uint64(off)
	}
	// 圧縮されたライブラリはインストール時に展開されるので、APKから直接mmapされる
	// 非圧縮のものだけページ境界にアラインされている必要がある(zipalign -P 16)。
	zi.OK = zi.Compressed || zi.DataOffset%PageSize == 0
	return zi
}

func readEntry(zf *zip.File) ([]byte, error) {
	rc, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func checkLibrary(path string, r io.ReaderAt, zi *ZipInfo) Result {
	res := Result{Path: path, Zip: zi}
	er, err := CheckELF(r)
	if err != nil {
		res.Status = StatusFail
		res.Error = fmt.Sprintf("not a valid ELF: %v", err)
		return res
	}
	res.ELFResult = er

	// Google Playは64ビットのABIにしか16KB対応を求めていないので、他はスキップでよい
	if !er.Is64Bit {
		res.Status = StatusSkip
		return res
	}

	if zi != nil && !zi.OK {
		er.Problems = append(er.Problems, fmt.Sprintf("ZIP: stored library data offset 0x%x is not 16KB aligned (zipalign -P 16)", zi.DataOffset))
	}
	if len(er.Problems) > 0 {
		res.Status = StatusFail
	} else {
		res.Status = StatusOK
	}
	return res
}

func printable(s string) string {
	if !strings.ContainsFunc(s, unicode.IsControl) {
		return s
	}
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}
