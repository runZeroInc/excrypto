// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file contains tests applied to the archives before they are written.

package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type testRule struct {
	name    string
	goos    string
	exclude bool
}

var srcRules = []testRule{
	{name: "go/VERSION"},
	{name: "go/src/cmd/go/main.go"},
	{name: "go/src/bytes/bytes.go"},
	{name: "**/.DS_Store", exclude: true},
	{name: "go/.git", exclude: true},
	{name: "go/.gitattributes", exclude: true},
	{name: "go/.github", exclude: true},
	{name: "go/VERSION.cache", exclude: true},
	{name: "go/bin/**", exclude: true},
	{name: "go/pkg/**", exclude: true},
	{name: "go/src/cmd/dist/dist", exclude: true},
	{name: "go/src/cmd/dist/dist.exe", exclude: true},
	{name: "go/src/internal/runtime/sys/zversion.go", exclude: true},
	{name: "go/src/time/tzdata/zzipdata.go", exclude: true},
}

var zipRules = []testRule{
	{name: "go/VERSION"},
	{name: "go/src/cmd/go/main.go"},
	{name: "go/src/bytes/bytes.go"},

	{name: "**/.DS_Store", exclude: true},
	{name: "go/.git", exclude: true},
	{name: "go/.gitattributes", exclude: true},
	{name: "go/.github", exclude: true},
	{name: "go/VERSION.cache", exclude: true},
	{name: "go/bin", exclude: true},
	{name: "go/pkg", exclude: true},
	{name: "go/src/cmd/dist/dist", exclude: true},
	{name: "go/src/cmd/dist/dist.exe", exclude: true},

	{name: "go/bin/go", goos: "linux"},
	{name: "go/bin/go", goos: "darwin"},
	{name: "go/bin/go", goos: "windows", exclude: true},
	{name: "go/bin/go.exe", goos: "windows"},
	{name: "go/bin/gofmt", goos: "linux"},
	{name: "go/bin/gofmt", goos: "darwin"},
	{name: "go/bin/gofmt", goos: "windows", exclude: true},
	{name: "go/bin/gofmt.exe", goos: "windows"},
	{name: "go/pkg/tool/*/compile", goos: "linux"},
	{name: "go/pkg/tool/*/compile", goos: "darwin"},
	{name: "go/pkg/tool/*/compile", goos: "windows", exclude: true},
	{name: "go/pkg/tool/*/compile.exe", goos: "windows"},
}

var modRules = []testRule{
	{name: "golang.org/toolchain@*/VERSION"},
	{name: "golang.org/toolchain@*/src/cmd/go/main.go"},
	{name: "golang.org/toolchain@*/src/bytes/bytes.go"},

	{name: "golang.org/toolchain@*/lib/wasm/go_js_wasm_exec"},
	{name: "golang.org/toolchain@*/lib/wasm/go_wasip1_wasm_exec"},
	{name: "golang.org/toolchain@*/lib/wasm/wasm_exec.js"},
	{name: "golang.org/toolchain@*/lib/wasm/wasm_exec_node.js"},

	{name: "**/.DS_Store", exclude: true},
	{name: "golang.org/toolchain@*/.git", exclude: true},
	{name: "golang.org/toolchain@*/.gitattributes", exclude: true},
	{name: "golang.org/toolchain@*/.github", exclude: true},
	{name: "golang.org/toolchain@*/VERSION.cache", exclude: true},
	{name: "golang.org/toolchain@*/bin", exclude: true},
	{name: "golang.org/toolchain@*/pkg", exclude: true},
	{name: "golang.org/toolchain@*/src/cmd/dist/dist", exclude: true},
	{name: "golang.org/toolchain@*/src/cmd/dist/dist.exe", exclude: true},

	{name: "golang.org/toolchain@*/bin/go", goos: "linux"},
	{name: "golang.org/toolchain@*/bin/go", goos: "darwin"},
	{name: "golang.org/toolchain@*/bin/go", goos: "windows", exclude: true},
	{name: "golang.org/toolchain@*/bin/go.exe", goos: "windows"},
	{name: "golang.org/toolchain@*/bin/gofmt", goos: "linux"},
	{name: "golang.org/toolchain@*/bin/gofmt", goos: "darwin"},
	{name: "golang.org/toolchain@*/bin/gofmt", goos: "windows", exclude: true},
	{name: "golang.org/toolchain@*/bin/gofmt.exe", goos: "windows"},
	{name: "golang.org/toolchain@*/pkg/tool/*/compile", goos: "linux"},
	{name: "golang.org/toolchain@*/pkg/tool/*/compile", goos: "darwin"},
	{name: "golang.org/toolchain@*/pkg/tool/*/compile", goos: "windows", exclude: true},
	{name: "golang.org/toolchain@*/pkg/tool/*/compile.exe", goos: "windows"},

	// go.mod are renamed to _go.mod.
	{name: "**/go.mod", exclude: true},
	{name: "**/_go.mod"},
}

func testSrc(a *Archive) {
	test("source", a, srcRules)

	// Check that no generated files slip in, even if new ones are added.
	for _, f := range a.Files {
		if strings.HasPrefix(path.Base(f.Name), "z") {
			data, err := os.ReadFile(filepath.Join(goroot, strings.TrimPrefix(f.Name, "go/")))
			if err != nil {
				log.Fatalf("checking source archive: %v", err)
			}
			if strings.Contains(string(data), "generated by go tool dist; DO NOT EDIT") {
				log.Fatalf("unexpected source archive file: %s (generated by dist)", f.Name)
			}
		}
	}
}

func testZip(a *Archive) { test("binary", a, zipRules) }
func testMod(a *Archive) { test("module", a, modRules) }

func test(kind string, a *Archive, rules []testRule) {
	ok := true
	have := make([]bool, len(rules))
	for _, f := range a.Files {
		for i, r := range rules {
			if r.goos != "" && r.goos != goos {
				continue
			}
			match, err := amatch(r.name, f.Name)
			if err != nil {
				log.Fatal(err)
			}
			if match {
				if r.exclude {
					ok = false
					if !have[i] {
						log.Printf("unexpected %s archive file: %s", kind, f.Name)
						have[i] = true // silence future prints for excluded directory
					}
				} else {
					have[i] = true
				}
			}
		}
	}
	missing := false
	for i, r := range rules {
		if r.goos != "" && r.goos != goos {
			continue
		}
		if !r.exclude && !have[i] {
			missing = true
			log.Printf("missing %s archive file: %s", kind, r.name)
		}
	}
	if missing {
		ok = false
		var buf bytes.Buffer
		for _, f := range a.Files {
			fmt.Fprintf(&buf, "\n\t%s", f.Name)
		}
		log.Printf("archive contents: %d files%s", len(a.Files), buf.Bytes())
	}
	if !ok {
		log.Fatalf("bad archive file")
	}
}
