package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/exp/maps"
)

type exporter struct {
	root string
}

func (ex *exporter) Export() error {
	fmt.Println("* Exporting project...")
	files, err := descopeClient.Management.Project().ExportRaw()
	if err != nil {
		return fmt.Errorf("failed to export project: %w", err)
	}

	if Flags.Debug {
		WriteDebugFile(ex.root, "debug/export.log", files)
	}

	fmt.Println("* Writing files...")
	paths := maps.Keys(files)
	sort.Strings(paths)
	for _, path := range paths {
		fmt.Printf("  - %s\n", path)
		data := files[path]
		if object, ok := data.(map[string]any); ok {
			if err := ex.writeObject(path, object); err != nil {
				return err
			}
		} else if asset, ok := data.(string); ok {
			if err := ex.writeAsset(path, asset); err != nil {
				return err
			}
		} else {
			return errors.New("unexpected exported file data: " + path)
		}
	}

	fmt.Println("* Done")

	return nil
}

func (ex *exporter) writeObject(path string, object map[string]any) error {
	bytes, err := json.MarshalIndent(object, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format object file %s: %w", path, err)
	}
	return ex.writeBytes(path, bytes)
}

func (ex *exporter) writeAsset(path string, asset string) error {
	if filepath.Ext(path) == ".txt" || filepath.Ext(path) == ".html" {
		return ex.writeBytes(path, []byte(asset))
	}
	bytes, err := base64.StdEncoding.DecodeString(asset)
	if err != nil {
		return fmt.Errorf("failed to decode asset file %s: %w", path, err)
	}
	return ex.writeBytes(path, bytes)
}

func (ex *exporter) writeBytes(path string, bytes []byte) error {
	fullpath, err := ex.ensurePath(path)
	if err != nil {
		return err
	}
	if err = os.WriteFile(fullpath, bytes, 0644); err != nil {
		return fmt.Errorf("failed to write asset file %s: %w", path, err)
	}
	return nil
}

func (ex *exporter) ensurePath(path string) (string, error) {
	dir, file := filepath.Split(path)
	fullpath := ex.root
	if dir != "" {
		for _, d := range strings.Split(filepath.Clean(dir), string(filepath.Separator)) {
			fullpath = filepath.Join(fullpath, d)
			if err := os.Mkdir(fullpath, 0755); err != nil && !os.IsExist(err) {
				return "", fmt.Errorf("failed to create export subdirectory %s: %w", fullpath, err)
			}
		}
	}

	fullpath = filepath.Join(fullpath, file)
	return fullpath, nil
}

func WriteDebugFile(root, path string, object map[string]any) {
	ex := exporter{root: root}
	ex.writeObject(path, object)
}

func ExportProject(args []string) error {
	root := Flags.Path
	if root == "" {
		root = "env-" + args[0]
		if err := os.Mkdir(root, 0755); err != nil && !os.IsExist(err) {
			return errors.New("cannot create export path: " + root)
		}
	} else {
		root = filepath.Clean(root)
		if info, err := os.Stat(root); os.IsNotExist(err) {
			return errors.New("export path does not exist: " + root)
		} else if err != nil || !info.IsDir() {
			return errors.New("invalid export path: " + root)
		}
	}
	ex := exporter{root: root}
	return ex.Export()
}
