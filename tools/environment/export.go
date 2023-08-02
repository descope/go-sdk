package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type ExtractMask int

const (
	ExtractNone   ExtractMask = 0
	ExtractOthers ExtractMask = 1
	ExtractFlows  ExtractMask = 2
	ExtractStyles ExtractMask = 4

	ExtractAll = ExtractOthers | ExtractFlows | ExtractStyles
)

type SplitMask int

const (
	SplitNone   SplitMask = 0
	SplitFlows  SplitMask = 1
	SplitStyles SplitMask = 2

	SplitAll = SplitFlows | SplitStyles
)

type StripMask int

const (
	StripNone         StripMask = 0
	StripVersion      StripMask = 1
	StripID           StripMask = 2
	StripModifiedTime StripMask = 4
	StripProjectName  StripMask = 8

	StripModel = StripVersion | StripID
)

var AssetDataURLs = map[string]string{
	"png":  "data:image/png;base64,",
	"jpg":  "data:image/jpeg;base64,",
	"svg":  "data:image/svg+xml;base64,",
	"webp": "data:image/webp;base64,",
}

var NonalphaRegexp = regexp.MustCompile(`[^a-zA-Z0-9]+`)

var EnvironmentFile = map[string]any{
	"version": 1,
}

type Exporter struct {
	Root          string
	AssetNames    map[string]string
	AssetMappings map[string]any
	Split         SplitMask
	Extract       ExtractMask
}

func NewExporter(root string) *Exporter {
	return &Exporter{
		Root:          root,
		AssetNames:    map[string]string{},
		AssetMappings: map[string]any{},
		Split:         SplitAll,
		Extract:       ExtractAll,
	}
}

func (ex *Exporter) Export() error {
	fmt.Println("* Fetching data...")
	m, err := descopeClient.Management.Environment().ExportRaw()
	if err != nil {
		return err
	}
	if Flags.Debug {
		ex.writeObject("debug", "export", m, ExtractNone, StripNone)
	}
	if ok := ex.printProject(m); !ok {
		return errors.New("unexpected export data format")
	}

	fmt.Println("* Writing data...")
	fmt.Println("  - Metadata")
	ex.writeObject("/", "environment", EnvironmentFile, ExtractNone, StripNone)

	fmt.Println("  - Settings")
	ex.writeObject("/", "project", m["settings"], ExtractOthers, StripModel|StripProjectName)
	ex.writeObject("/", "messaging", m["messaging"], ExtractOthers, StripModel)
	ex.writeObject("auth", "magiclink", m["magiclink"], ExtractOthers, StripModel)
	ex.writeObject("auth", "enchantedlink", m["enchantedlink"], ExtractOthers, StripModel)
	ex.writeObject("auth", "otp", m["otp"], ExtractOthers, StripModel)
	ex.writeObject("auth", "totp", m["totp"], ExtractOthers, StripModel)
	ex.writeObject("auth", "saml", m["saml"], ExtractOthers, StripModel)
	ex.writeObject("auth", "oauth", m["oauth"], ExtractOthers, StripModel)
	ex.writeObject("auth", "webauthn", m["webauthn"], ExtractOthers, StripModel)
	ex.writeObject("auth", "password", m["password"], ExtractOthers, StripModel)
	ex.writeObject("auth", "oidcidp", m["oidcidp"], ExtractOthers, StripModel)

	fmt.Println("  - Flows")
	ex.writeFlows(m["flows"])

	fmt.Println("  - Theme")
	ex.writeTheme(m["theme"])

	if len(ex.AssetMappings) > 0 {
		fmt.Println("  - Assets")
		assets := map[string]any{
			"mapping": ex.AssetMappings,
		}
		ex.writeObject("assets", "assets", assets, ExtractNone, StripNone)
	}

	fmt.Println("* Done")

	return nil
}

func (ex *Exporter) printProject(m map[string]any) bool {
	settings, ok := m["settings"].(map[string]any)
	if !ok {
		return false
	}
	projectName, ok := settings["projectName"].(string)
	if !ok {
		return false
	}
	version, ok := settings["version"].(float64)
	if !ok {
		return false
	}
	fmt.Printf("  - Project: %s\n", projectName)
	fmt.Printf("  - Revision: %d\n", int(version))
	return true
}

func (ex *Exporter) writeObject(dir, filename string, object any, extract ExtractMask, strip StripMask) error {
	m, ok := object.(map[string]any)
	if !ok {
		return nil
	}

	if strip&StripVersion != 0 {
		delete(m, "version")
	}
	if strip&StripID != 0 {
		delete(m, "id")
	}
	if strip&StripModifiedTime != 0 {
		delete(m, "modifiedTime")
	}
	if strip&StripProjectName != 0 {
		delete(m, "projectName")
	}

	path, err := ex.ensurePath(dir)
	if err != nil {
		return err
	}

	fullpath := filepath.Join(path, filename+".json")

	if ex.Extract&extract != 0 {
		if err := ex.extractAssets(fullpath, m); err != nil {
			return err
		}
	}

	bytes, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(fullpath, bytes, 0644); err != nil {
		return err
	}

	return nil
}

func (ex *Exporter) writeFlows(arr any) {
	flowIds := []string{}
	if flows, ok := arr.([]any); ok {
		for i := range flows {
			if object, ok := flows[i].(map[string]any); ok {
				if flow, ok := object["flow"].(map[string]any); ok {
					if flowId, ok := flow["id"].(string); ok {
						flowIds = append(flowIds, flowId)
						ex.writeFlow(flowId, object)
					}
				}
			}
		}
	}
	if len(flowIds) > 0 {
		sort.Strings(flowIds)
		list := map[string]any{"flows": flowIds}
		ex.writeObject("flows", "flows", list, ExtractNone, StripNone)
	}
}

func (ex *Exporter) writeFlow(flowId string, object map[string]any) {
	ex.ensurePath("flows")
	if ex.Split&SplitFlows != 0 {
		dir := filepath.Join("flows", flowId)
		ex.writeObject(dir, "flow", object["flow"], ExtractFlows, StripVersion|StripModifiedTime)
		if screens, ok := object["screens"].([]any); ok {
			for j := range screens {
				if screen, ok := screens[j].(map[string]any); ok {
					ex.writeObject(dir, fmt.Sprintf("screen-%d", j+1), screen, ExtractFlows, StripVersion)
				}
			}
		}
	} else {
		if flow, ok := object["flow"].(map[string]any); ok {
			delete(flow, "version")
			delete(flow, "modifiedTime")
		}
		if screens, ok := object["screens"].([]any); ok {
			for j := range screens {
				if screen, ok := screens[j].(map[string]any); ok {
					delete(screen, "version")
				}
			}
		}
		ex.writeObject("flows", flowId, object, ExtractFlows, StripNone)
	}
}

func (ex *Exporter) writeTheme(object any) {
	if ex.Split&SplitStyles != 0 {
		if theme, ok := object.(map[string]any); ok {
			if template, ok := theme["cssTemplate"].(map[string]any); ok {
				ex.writeObject("styles", "dark", template["dark"], ExtractStyles, StripNone)
				ex.writeObject("styles", "light", template["light"], ExtractStyles, StripNone)
			}
		}
	} else {
		ex.writeObject("/", "theme", object, ExtractStyles, StripModel)
	}
}

func (ex *Exporter) ensurePath(dir string) (string, error) {
	path := filepath.Join(ex.Root, dir)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.Mkdir(path, 0755); err != nil {
			return "", err
		}
	}
	return path, nil
}

func (ex *Exporter) extractAssets(path string, m map[string]any) error {
	mapping, err := ex.extractSubassets(path, m)
	if err != nil {
		return err
	}
	if len(mapping) > 0 {
		basepath, err := filepath.Rel(ex.Root, path)
		if err != nil {
			return err
		}
		ex.AssetMappings[basepath] = mapping
	}
	return nil
}

func (ex *Exporter) extractSubassets(path string, m map[string]any) (map[string]any, error) {
	mapping := map[string]any{}
	for key, value := range m {
		switch value := value.(type) {
		case map[string]any:
			submapping, err := ex.extractSubassets(path, value)
			if err != nil {
				return nil, err
			}
			if len(submapping) > 0 {
				mapping[key] = submapping
			}
		case []any:
			found := false
			submappings := make([]any, len(value))
			for i := range value {
				if m, ok := value[i].(map[string]any); ok {
					submapping, err := ex.extractSubassets(path, m)
					if err != nil {
						return nil, err
					}
					if len(submapping) > 0 {
						submappings[i] = submapping
						found = true
					}
				}
			}
			if found {
				mapping[key] = submappings
			}
		case string:
			bytes, extension := ex.extractDataURL(value)
			if bytes != nil {
				hash := sha256.Sum256(bytes)
				hex := fmt.Sprintf("%x", hash)

				if _, ok := ex.AssetNames[hex]; !ok {
					dir, err := ex.ensurePath("assets")
					if err != nil {
						return nil, err
					}

					assetname := fmt.Sprintf("img-%s.%s", hex, extension)
					assetpath := filepath.Join(dir, assetname)
					if err := os.WriteFile(assetpath, bytes, 0644); err != nil {
						return nil, err
					}

					ex.AssetNames[hex] = assetname
				}

				m[key] = fmt.Sprintf("asset:%s", ex.AssetNames[hex])
				mapping[key] = ex.AssetNames[hex]
			} else {
				if len(value) < 512 {
					continue
				}

				bytes := []byte(value)
				extension := "txt"
				if strings.HasPrefix(value, "<!doctype html") {
					extension = "html"
				}

				hash := sha256.Sum256(bytes)
				hex := fmt.Sprintf("%x", hash)

				if _, ok := ex.AssetNames[hex]; !ok {
					dir, err := ex.ensurePath("/assets")
					if err != nil {
						return nil, err
					}

					prefix := NonalphaRegexp.ReplaceAllString(strings.ToLower(key), "")
					if prefix == "" {
						prefix = "text"
					}

					assetname := fmt.Sprintf("%s-%s.%s", prefix, hex, extension)
					assetpath := filepath.Join(dir, assetname)
					if err := os.WriteFile(assetpath, bytes, 0644); err != nil {
						return nil, err
					}

					ex.AssetNames[hex] = assetname
				}

				m[key] = fmt.Sprintf("asset:%s", ex.AssetNames[hex])
				mapping[key] = ex.AssetNames[hex]
			}
		}
	}
	return mapping, nil
}

func (ex *Exporter) extractDataURL(str string) (bytes []byte, extension string) {
	var head string
	for k, v := range AssetDataURLs {
		if strings.HasPrefix(str, v) {
			head = v
			extension = k
		}
	}
	if extension == "" {
		return nil, ""
	}

	bytes, err := base64.StdEncoding.DecodeString(str[len(head):])
	if err != nil {
		fmt.Printf("Error decoding base64: %v\n", err)
		return nil, ""
	}

	return bytes, extension
}

func environmentExport(args []string) error {
	root := Flags.Path
	if root == "" {
		root = "env-" + args[0]
		os.Mkdir(root, 0755)
	} else {
		root = filepath.Clean(root)
		if info, err := os.Stat(root); os.IsNotExist(err) {
			return errors.New("export path does not exist: " + root)
		} else if err != nil || !info.IsDir() {
			return errors.New("invalid export path: " + root)
		}
	}

	exporter := NewExporter(root)

	if len(Flags.Extract) > 0 {
		exporter.Extract = ExtractNone
	}
	for _, v := range Flags.Extract {
		switch v {
		case "none":
			exporter.Extract = ExtractNone
		case "others":
			exporter.Extract |= ExtractOthers
		case "flows":
			exporter.Extract |= ExtractFlows
		case "styles":
			exporter.Extract |= ExtractStyles
		case "all":
			exporter.Extract = ExtractAll
		default:
			return flag.ErrHelp
		}
	}

	if len(Flags.Split) > 0 {
		exporter.Split = SplitNone
	}
	for _, v := range Flags.Split {
		switch v {
		case "none":
			exporter.Split = SplitNone
		case "flows":
			exporter.Split |= SplitFlows
		case "styles":
			exporter.Split |= SplitStyles
		case "all":
			exporter.Split = SplitAll
		default:
			return flag.ErrHelp
		}
	}

	return exporter.Export()
}
