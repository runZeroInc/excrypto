// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Distpack creates the tgz and zip files for a Go distribution.
// It writes into GOROOT/pkg/distpack:
//
//   - a binary distribution (tgz or zip) for the current GOOS and GOARCH
//   - a source distribution that is independent of GOOS/GOARCH
//   - the module mod, info, and zip files for a distribution in module form
//     (as used by GOTOOLCHAIN support in the go command).
//
// Distpack is typically invoked by the -distpack flag to make.bash.
// A cross-compiled distribution for goos/goarch can be built using:
//
//	GOOS=goos GOARCH=goarch ./make.bash -distpack
//
// To test that the module downloads are usable with the go command:
//
//	./make.bash -distpack
//	mkdir -p /tmp/goproxy/golang.org/toolchain/
//	ln -sf $(pwd)/../pkg/distpack /tmp/goproxy/golang.org/toolchain/@v
//	GOPROXY=file:///tmp/goproxy GOTOOLCHAIN=$(sed 1q ../VERSION) gotip version
//
// gotip can be replaced with an older released Go version once there is one.
// It just can't be the one make.bash built, because it knows it is already that
// version and will skip the download.
package main

import (
	"archive/tar"
	"archive/zip"
	"compress/flate"
	"compress/gzip"
	"github.com/runZeroInc/excrypto/stdlib/crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/runZeroInc/excrypto/stdlib/cmd/internal/telemetry/counter"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: distpack\n")
	os.Exit(2)
}

const (
	modPath          = "golang.org/toolchain"
	modVersionPrefix = "v0.0.1"
)

var (
	goroot     string
	gohostos   string
	gohostarch string
	goos       string
	goarch     string
)

func main() {
	log.SetPrefix("distpack: ")
	log.SetFlags(0)
	counter.Open()
	flag.Usage = usage
	flag.Parse()
	counter.Inc("distpack/invocations")
	counter.CountFlags("distpack/flag:", *flag.CommandLine)
	if flag.NArg() != 0 {
		usage()
	}

	// Load context.
	goroot = runtime.GOROOT()
	if goroot == "" {
		log.Fatalf("missing $GOROOT")
	}
	gohostos = runtime.GOOS
	gohostarch = runtime.GOARCH
	goos = os.Getenv("GOOS")
	if goos == "" {
		goos = gohostos
	}
	goarch = os.Getenv("GOARCH")
	if goarch == "" {
		goarch = gohostarch
	}
	goosUnderGoarch := goos + "_" + goarch
	goosDashGoarch := goos + "-" + goarch
	exe := ""
	if goos == "windows" {
		exe = ".exe"
	}
	version, versionTime := readVERSION(goroot)

	// Start with files from GOROOT, filtering out non-distribution files.
	base, err := NewArchive(goroot)
	if err != nil {
		log.Fatal(err)
	}
	base.SetTime(versionTime)
	base.SetMode(mode)
	base.Remove(
		".git/**",
		".gitattributes",
		".github/**",
		".gitignore",
		"VERSION.cache",
		"misc/cgo/*/_obj/**",
		"**/.DS_Store",
		"**/*.exe~", // go.dev/issue/23894
		// Generated during make.bat/make.bash.
		"src/cmd/dist/dist",
		"src/cmd/dist/dist.exe",
	)

	// The source distribution removes files generated during the release build.
	// See ../dist/build.go's deptab.
	srcArch := base.Clone()
	srcArch.Remove(
		"bin/**",
		"pkg/**",

		// Generated during cmd/dist. See ../dist/build.go:/gentab.
		"src/cmd/go/internal/cfg/zdefaultcc.go",
		"src/go/build/zcgo.go",
		"src/internal/runtime/sys/zversion.go",
		"src/time/tzdata/zzipdata.go",

		// Generated during cmd/dist by bootstrapBuildTools.
		"src/cmd/cgo/zdefaultcc.go",
		"src/github.com/runZeroInc/excrypto/stdlib/cmd/internal/objabi/zbootstrap.go",
		"src/internal/buildcfg/zbootstrap.go",

		// Generated by earlier versions of cmd/dist .
		"src/cmd/go/internal/cfg/zosarch.go",
	)
	srcArch.AddPrefix("go")
	testSrc(srcArch)

	// The binary distribution includes only a subset of bin and pkg.
	binArch := base.Clone()
	binArch.Filter(func(name string) bool {
		// Discard bin/ for now, will add back later.
		if strings.HasPrefix(name, "bin/") {
			return false
		}
		// Discard most of pkg.
		if strings.HasPrefix(name, "pkg/") {
			// Keep pkg/include.
			if strings.HasPrefix(name, "pkg/include/") {
				return true
			}
			// Discard other pkg except pkg/tool.
			if !strings.HasPrefix(name, "pkg/tool/") {
				return false
			}
			// Inside pkg/tool, keep only $GOOS_$GOARCH.
			if !strings.HasPrefix(name, "pkg/tool/"+goosUnderGoarch+"/") {
				return false
			}
			// Inside pkg/tool/$GOOS_$GOARCH, discard helper tools.
			switch strings.TrimSuffix(path.Base(name), ".exe") {
			case "api", "dist", "distpack", "metadata":
				return false
			}
		}
		return true
	})

	// Add go and gofmt to bin, using cross-compiled binaries
	// if this is a cross-compiled distribution.
	binExes := []string{
		"go",
		"gofmt",
	}
	crossBin := "bin"
	if goos != gohostos || goarch != gohostarch {
		crossBin = "bin/" + goosUnderGoarch
	}
	for _, b := range binExes {
		name := "bin/" + b + exe
		src := filepath.Join(goroot, crossBin, b+exe)
		info, err := os.Stat(src)
		if err != nil {
			log.Fatal(err)
		}
		binArch.Add(name, src, info)
	}
	binArch.Sort()
	binArch.SetTime(versionTime) // fix added files
	binArch.SetMode(mode)        // fix added files

	zipArch := binArch.Clone()
	zipArch.AddPrefix("go")
	testZip(zipArch)

	// The module distribution is the binary distribution with unnecessary files removed
	// and file names using the necessary prefix for the module.
	modArch := binArch.Clone()
	modArch.Remove(
		"api/**",
		"doc/**",
		"misc/**",
		"test/**",
	)
	modVers := modVersionPrefix + "-" + version + "." + goosDashGoarch
	modArch.AddPrefix(modPath + "@" + modVers)
	modArch.RenameGoMod()
	modArch.Sort()
	testMod(modArch)

	// distpack returns the full path to name in the distpack directory.
	distpack := func(name string) string {
		return filepath.Join(goroot, "pkg/distpack", name)
	}
	if err := os.MkdirAll(filepath.Join(goroot, "pkg/distpack"), 0777); err != nil {
		log.Fatal(err)
	}

	writeTgz(distpack(version+".src.tar.gz"), srcArch)

	if goos == "windows" {
		writeZip(distpack(version+"."+goos+"-"+goarch+".zip"), zipArch)
	} else {
		writeTgz(distpack(version+"."+goos+"-"+goarch+".tar.gz"), zipArch)
	}

	writeZip(distpack(modVers+".zip"), modArch)
	writeFile(distpack(modVers+".mod"),
		[]byte(fmt.Sprintf("module %s\n", modPath)))
	writeFile(distpack(modVers+".info"),
		[]byte(fmt.Sprintf("{%q:%q, %q:%q}\n",
			"Version", modVers,
			"Time", versionTime.Format(time.RFC3339))))
}

// mode computes the mode for the given file name.
func mode(name string, _ fs.FileMode) fs.FileMode {
	if strings.HasPrefix(name, "bin/") ||
		strings.HasPrefix(name, "pkg/tool/") ||
		strings.HasSuffix(name, ".bash") ||
		strings.HasSuffix(name, ".sh") ||
		strings.HasSuffix(name, ".pl") ||
		strings.HasSuffix(name, ".rc") {
		return 0o755
	} else if ok, _ := amatch("**/go_?*_?*_exec", name); ok {
		return 0o755
	}
	return 0o644
}

// readVERSION reads the VERSION file.
// The first line of the file is the Go version.
// Additional lines are 'key value' pairs setting other data.
// The only valid key at the moment is 'time', which sets the modification time for file archives.
func readVERSION(goroot string) (version string, t time.Time) {
	data, err := os.ReadFile(filepath.Join(goroot, "VERSION"))
	if err != nil {
		log.Fatal(err)
	}
	version, rest, _ := strings.Cut(string(data), "\n")
	for _, line := range strings.Split(rest, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		default:
			log.Fatalf("VERSION: unexpected line: %s", line)
		case "time":
			if len(f) != 2 {
				log.Fatalf("VERSION: unexpected time line: %s", line)
			}
			t, err = time.ParseInLocation(time.RFC3339, f[1], time.UTC)
			if err != nil {
				log.Fatalf("VERSION: bad time: %s", err)
			}
		}
	}
	return version, t
}

// writeFile writes a file with the given name and data or fatals.
func writeFile(name string, data []byte) {
	if err := os.WriteFile(name, data, 0666); err != nil {
		log.Fatal(err)
	}
	reportHash(name)
}

// check panics if err is not nil. Otherwise it returns x.
// It is only meant to be used in a function that has deferred
// a function to recover appropriately from the panic.
func check[T any](x T, err error) T {
	check1(err)
	return x
}

// check1 panics if err is not nil.
// It is only meant to be used in a function that has deferred
// a function to recover appropriately from the panic.
func check1(err error) {
	if err != nil {
		panic(err)
	}
}

// writeTgz writes the archive in tgz form to the file named name.
func writeTgz(name string, a *Archive) {
	out, err := os.Create(name)
	if err != nil {
		log.Fatal(err)
	}

	var f File
	defer func() {
		if err := recover(); err != nil {
			extra := ""
			if f.Name != "" {
				extra = " " + f.Name
			}
			log.Fatalf("writing %s%s: %v", name, extra, err)
		}
	}()

	zw := check(gzip.NewWriterLevel(out, gzip.BestCompression))
	tw := tar.NewWriter(zw)

	// Find the mode and mtime to use for directory entries,
	// based on the mode and mtime of the first file we see.
	// We know that modes and mtimes are uniform across the archive.
	var dirMode fs.FileMode
	var mtime time.Time
	for _, f := range a.Files {
		dirMode = fs.ModeDir | f.Mode | (f.Mode&0444)>>2 // copy r bits down to x bits
		mtime = f.Time
		break
	}

	// mkdirAll ensures that the tar file contains directory
	// entries for dir and all its parents. Some programs reading
	// these tar files expect that. See go.dev/issue/61862.
	haveDir := map[string]bool{".": true}
	var mkdirAll func(string)
	mkdirAll = func(dir string) {
		if dir == "/" {
			panic("mkdirAll /")
		}
		if haveDir[dir] {
			return
		}
		haveDir[dir] = true
		mkdirAll(path.Dir(dir))
		df := &File{
			Name: dir + "/",
			Time: mtime,
			Mode: dirMode,
		}
		h := check(tar.FileInfoHeader(df.Info(), ""))
		h.Name = dir + "/"
		if err := tw.WriteHeader(h); err != nil {
			panic(err)
		}
	}

	for _, f = range a.Files {
		h := check(tar.FileInfoHeader(f.Info(), ""))
		mkdirAll(path.Dir(f.Name))
		h.Name = f.Name
		if err := tw.WriteHeader(h); err != nil {
			panic(err)
		}
		r := check(os.Open(f.Src))
		check(io.Copy(tw, r))
		check1(r.Close())
	}
	f.Name = ""
	check1(tw.Close())
	check1(zw.Close())
	check1(out.Close())
	reportHash(name)
}

// writeZip writes the archive in zip form to the file named name.
func writeZip(name string, a *Archive) {
	out, err := os.Create(name)
	if err != nil {
		log.Fatal(err)
	}

	var f File
	defer func() {
		if err := recover(); err != nil {
			extra := ""
			if f.Name != "" {
				extra = " " + f.Name
			}
			log.Fatalf("writing %s%s: %v", name, extra, err)
		}
	}()

	zw := zip.NewWriter(out)
	zw.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(out, flate.BestCompression)
	})
	for _, f = range a.Files {
		h := check(zip.FileInfoHeader(f.Info()))
		h.Name = f.Name
		h.Method = zip.Deflate
		w := check(zw.CreateHeader(h))
		r := check(os.Open(f.Src))
		check(io.Copy(w, r))
		check1(r.Close())
	}
	f.Name = ""
	check1(zw.Close())
	check1(out.Close())
	reportHash(name)
}

func reportHash(name string) {
	f, err := os.Open(name)
	if err != nil {
		log.Fatal(err)
	}
	h := sha256.New()
	io.Copy(h, f)
	f.Close()
	fmt.Printf("distpack: %x %s\n", h.Sum(nil)[:8], filepath.Base(name))
}
