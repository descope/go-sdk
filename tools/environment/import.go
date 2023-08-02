package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/exp/maps"
)

type Importer struct {
	Root          string
	AssetValues   map[string]string
	AssetMappings map[string]any
}

func NewImporter(root string) *Importer {
	return &Importer{
		Root:          filepath.Clean(root),
		AssetValues:   map[string]string{},
		AssetMappings: map[string]any{},
	}
}

func (im *Importer) Import() error {
	fmt.Println("* Reading data...")
	fmt.Println("  - Metadata")
	err := im.checkEnvironment()
	if err != nil {
		return err
	}

	fmt.Println("  - Assets")
	if err := im.readAssets(); err != nil {
		return err
	}

	m := map[string]any{}

	fmt.Println("  - Settings")
	im.readField("/", "project", m, "settings")
	im.readField("/", "messaging", m, "messaging")
	im.readField("/auth", "magiclink", m, "magiclink")
	im.readField("/auth", "enchantedlink", m, "enchantedlink")
	im.readField("/auth", "otp", m, "otp")
	im.readField("/auth", "totp", m, "totp")
	im.readField("/auth", "saml", m, "saml")
	im.readField("/auth", "oauth", m, "oauth")
	im.readField("/auth", "webauthn", m, "webauthn")
	im.readField("/auth", "password", m, "password")
	im.readField("/auth", "oidcidp", m, "oidcidp")

	fmt.Println("  - Flows")
	flows, err := im.readFlows()
	if err != nil {
		return err
	}
	if len(flows) > 0 {
		m["flows"] = flows
	}

	fmt.Println("  - Theme")
	theme, err := im.readTheme()
	if err != nil {
		return err
	}
	if theme != nil {
		m["theme"] = theme
	}

	if Flags.Debug {
		NewExporter(im.Root).writeObject("debug", "import", m, ExtractNone, StripNone)
	}

	fmt.Println("* Importing data...")
	if err := descopeClient.Management.Environment().ImportRaw(m); err != nil {
		return err
	}

	fmt.Println("* Done")
	return nil
}

func (im *Importer) checkEnvironment() error {
	object, err := im.readObject("/", "environment")
	if err != nil {
		return errors.New("missing or invalid environment.json file")
	}

	version, ok := object["version"].(float64)
	if !ok || version < 1 {
		return errors.New("missing or invalid version value in environment.json file")
	}
	if version > 1 {
		return fmt.Errorf("unsupported export version %d in environment.json file", int(version))
	}
	return nil
}

func (im *Importer) readField(dir, filename string, m map[string]any, key string) error {
	object, err := im.readObject(dir, filename)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	m[key] = object
	return nil
}

func (im *Importer) readObject(dir, filename string) (map[string]any, error) {
	fullpath := filepath.Join(im.Root, dir, filename+".json")
	json, err := im.readJSON(fullpath)
	if err != nil {
		return nil, err
	}
	assetpath, err := filepath.Rel(im.Root, fullpath)
	if err != nil {
		return nil, err
	}
	if mapping, ok := im.AssetMappings[assetpath].(map[string]any); ok {
		im.insertAssets(assetpath, json, mapping)
	}
	return json, nil
}

func (im *Importer) readTheme() (map[string]any, error) {
	theme, err := im.readObject("/", "theme")
	if theme != nil {
		return theme, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	dark, err := im.readObject("styles", "dark")
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	light, err := im.readObject("styles", "light")
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	object := map[string]any{
		"cssTemplate": map[string]any{
			"dark":  dark,
			"light": light,
		},
	}
	return object, nil
}

func (im *Importer) readFlows() ([]any, error) {
	file := filepath.Join(im.Root, "flows", "flows.json")
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return nil, nil
	}

	flows, err := im.readJSON(file)
	if err != nil {
		return nil, err
	}

	flowIds, ok := flows["flows"].([]any)
	if !ok {
		return nil, errors.New("missing or invalid list of flows in flows.json")
	}

	result := []any{}
	for _, flowId := range flowIds {
		flowId, ok := flowId.(string)
		if !ok {
			return nil, errors.New("invalid list of flows in flows.json")
		}
		flow, err := im.readFlow(flowId)
		if err != nil {
			return nil, err
		}
		result = append(result, flow)
	}
	return result, nil
}

func (im *Importer) readFlow(flowId string) (map[string]any, error) {
	flow, err := im.readObject("flows", flowId)
	if os.IsNotExist(err) {
		return im.readSplitFlow(flowId)
	}
	if err != nil {
		return nil, err
	}
	return flow, nil
}

func (im *Importer) readSplitFlow(flowId string) (map[string]any, error) {
	dir := filepath.Join("flows", flowId)
	flow, err := im.readObject(dir, "flow")
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("missing or invalid json files for %s flow", flowId)
	}

	screens := []map[string]any{}
	for i := 1; true; i++ {
		screen, err := im.readObject(dir, fmt.Sprintf("screen-%d", i))
		if os.IsNotExist(err) {
			break
		}
		if err != nil {
			return nil, err
		}
		screens = append(screens, screen)
	}
	if len(screens) == 0 {
		return nil, fmt.Errorf("missing screen files for %s flow", flowId)
	}

	object := map[string]any{
		"flow":    flow,
		"screens": screens,
	}
	return object, nil
}

func (im *Importer) insertAssets(file string, object map[string]any, mapping map[string]any) {
	for k, v := range mapping {
		switch value := v.(type) {
		case map[string]any:
			subobject, ok := object[k].(map[string]any)
			if !ok {
				panic("missing expected map key '" + k + "' in target object in file " + file)
			}
			im.insertAssets(file, subobject, value)
		case []any:
			other, ok := object[k].([]any)
			if !ok {
				panic("missing expected array key '" + k + "' in target object in file " + file)
			}
			if len(value) != len(other) {
				panic("different size array '" + k + "' in target object in file " + file)
			}
			for i := range value {
				if submapping, ok := value[i].(map[string]any); ok {
					subobject, ok := other[i].(map[string]any)
					if !ok {
						panic("missing expected map array child '" + k + "' in target object in file " + file)
					}
					im.insertAssets(file, subobject, submapping)
				}
			}
		case string:
			if _, ok := object[k].(string); !ok {
				panic("missing expected string key '" + k + "' in target object in file " + file)
			}
			asset, ok := im.AssetValues[value]
			if !ok {
				panic("missing expected asset value for '" + value + "' for key '" + k + "' in file " + file)
			}
			object[k] = asset
		}
	}
}

func (im *Importer) readAssets() error {
	dir := filepath.Join(im.Root, "assets")
	file := filepath.Join(dir, "assets.json")
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return nil
	}

	fmt.Println("Reading assets...")
	json, err := im.readJSON(filepath.Join(dir, "assets.json"))
	if err != nil {
		return err
	}

	mapping, ok := json["mapping"].(map[string]any)
	if !ok {
		return errors.New("missing or invalid mapping key in assets.json")
	}
	im.AssetMappings = mapping

	filenames := im.searchAssets(mapping)
	for _, filename := range filenames {
		value, err := im.loadAsset(dir, filename)
		if err != nil {
			return err
		}
		im.AssetValues[filename] = value
	}

	return nil
}

func (im *Importer) loadAsset(dir, filename string) (string, error) {
	path := filepath.Join(dir, filename)
	bytes, err := im.readBytes(path)
	if err != nil {
		return "", err
	}

	extension := strings.TrimPrefix(filepath.Ext(filename), ".")
	dataurl, ok := AssetDataURLs[extension]
	if !ok {
		return string(bytes), nil
	}

	value := base64.StdEncoding.EncodeToString(bytes)
	return dataurl + value, nil
}

func (im *Importer) searchAssets(object any) []string {
	files := map[string]struct{}{}
	im.searchSubassets(object, files)
	return maps.Keys(files)
}

func (im *Importer) searchSubassets(object any, results map[string]struct{}) {
	switch value := object.(type) {
	case map[string]any:
		for _, v := range value {
			im.searchSubassets(v, results)
		}
	case []any:
		for _, v := range value {
			im.searchSubassets(v, results)
		}
	case string:
		results[value] = struct{}{}
	}
}

func (im *Importer) readJSON(path string) (map[string]any, error) {
	bytes, err := im.readBytes(path)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	err = json.Unmarshal(bytes, &m)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (im *Importer) readBytes(path string) ([]byte, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func environmentImport(args []string) error {
	root := Flags.Path
	if root == "" {
		root = "env-" + args[0]
	} else {
		root = filepath.Clean(root)
	}
	if info, err := os.Stat(root); os.IsNotExist(err) || !info.IsDir() {
		return errors.New("import path does not exist: " + root)
	}
	return NewImporter(root).Import()
}
