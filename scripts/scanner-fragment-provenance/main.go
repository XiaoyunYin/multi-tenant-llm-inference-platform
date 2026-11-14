// Read-only coordinate provenance using the exact pinned scanner source module.
// No fragment text or finding value is ever serialized.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/zricethezav/gitleaks/v8/sources"
)

type boundary struct {
	Offset int    `json:"offset"`
	Bytes  int    `json:"bytes"`
	Line   int    `json:"line"`
	SHA256 string `json:"sha256"`
}

type member struct {
	Bytes     int        `json:"bytes"`
	SHA256    string     `json:"sha256"`
	Fragments []boundary `json:"fragments"`
	hasher    hash.Hash
}

func run() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("fragment_provenance:arguments")
	}
	root := os.Args[1]
	files := map[string]*member{}
	for _, name := range os.Args[2:] {
		if filepath.IsAbs(name) || filepath.ToSlash(filepath.Clean(name)) != name || strings.Contains(name, "..") {
			return fmt.Errorf("fragment_provenance:path")
		}
		input, err := os.Open(filepath.Join(root, name))
		if err != nil {
			return fmt.Errorf("fragment_provenance:open")
		}
		file := sources.File{Content: input, Path: name, MaxArchiveDepth: 3}
		err = file.Fragments(context.Background(), func(fragment sources.Fragment, err error) error {
			if err != nil {
				return fmt.Errorf("fragment_provenance:read")
			}
			name := fragment.FilePath
			row := files[name]
			if row == nil {
				row = &member{hasher: sha256.New()}
				files[name] = row
			}
			data := []byte(fragment.Raw)
			digest := sha256.Sum256(data)
			row.Fragments = append(row.Fragments, boundary{Offset: row.Bytes, Bytes: len(data), Line: fragment.StartLine, SHA256: hex.EncodeToString(digest[:])})
			row.Bytes += len(data)
			_, err = row.hasher.Write(data)
			return err
		})
		input.Close()
		if err != nil {
			return err
		}
	}
	for _, row := range files {
		row.SHA256 = hex.EncodeToString(row.hasher.Sum(nil))
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"go_version": runtime.Version(), "files": files})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
