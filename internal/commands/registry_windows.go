//go:build windows

package commands

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func regRead(p string) (string, error) {
	// p like HKCU\Software\...\Value or HKLM\...
	// Split last \ as value name
	idx := strings.LastIndex(p, "\\")
	if idx == -1 {
		return "", fmt.Errorf("invalid path")
	}
	keyPath := p[:idx]
	valName := p[idx+1:]
	var k registry.Key
	var err error
	if strings.HasPrefix(strings.ToUpper(keyPath), "HKCU") {
		rest := strings.TrimPrefix(keyPath, "HKCU\\")
		if strings.EqualFold(keyPath, "HKCU") {
			rest = ""
		} else if strings.HasPrefix(strings.ToUpper(keyPath), "HKCU\\") {
			rest = keyPath[5:]
		}
		k, err = registry.OpenKey(registry.CURRENT_USER, rest, registry.QUERY_VALUE)
	} else if strings.HasPrefix(strings.ToUpper(keyPath), "HKLM") {
		rest := ""
		if len(keyPath) > 4 {
			rest = keyPath[5:]
		}
		k, err = registry.OpenKey(registry.LOCAL_MACHINE, rest, registry.QUERY_VALUE)
	} else {
		return "", fmt.Errorf("unsupported hive, use HKCU or HKLM")
	}
	if err != nil {
		return "", err
	}
	defer k.Close()
	val, _, err := k.GetStringValue(valName)
	if err != nil {
		// try GetInteger
		if v, _, err2 := k.GetIntegerValue(valName); err2 == nil {
			return fmt.Sprintf("%d", v), nil
		}
		return "", err
	}
	return val, nil
}

func regWrite(arg string) (string, error) {
	parts := strings.SplitN(arg, "|", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("usage: reg-write <path>|<value>")
	}
	p := strings.TrimSpace(parts[0])
	val := parts[1]
	idx := strings.LastIndex(p, "\\")
	if idx == -1 {
		return "", fmt.Errorf("invalid path")
	}
	keyPath := p[:idx]
	valName := p[idx+1:]
	var k registry.Key
	var err error
	// CreateKey (not OpenKey): reg-write must work for brand-new keys too.
	if strings.HasPrefix(strings.ToUpper(keyPath), "HKCU") {
		rest := ""
		if len(keyPath) > 4 {
			rest = keyPath[5:]
		}
		k, _, err = registry.CreateKey(registry.CURRENT_USER, rest, registry.SET_VALUE)
		if err != nil {
			return "", err
		}
	} else if strings.HasPrefix(strings.ToUpper(keyPath), "HKLM") {
		rest := ""
		if len(keyPath) > 4 {
			rest = keyPath[5:]
		}
		k, _, err = registry.CreateKey(registry.LOCAL_MACHINE, rest, registry.SET_VALUE)
		if err != nil {
			return "", err
		}
	} else {
		return "", fmt.Errorf("unsupported hive")
	}
	defer k.Close()
	return "", k.SetStringValue(valName, val)
}

func regDelete(p string) (string, error) {
	idx := strings.LastIndex(p, "\\")
	if idx == -1 {
		return "", fmt.Errorf("invalid path")
	}
	keyPath := p[:idx]
	valName := p[idx+1:]
	var k registry.Key
	var err error
	if strings.HasPrefix(strings.ToUpper(keyPath), "HKCU") {
		rest := ""
		if len(keyPath) > 4 {
			rest = keyPath[5:]
		}
		k, err = registry.OpenKey(registry.CURRENT_USER, rest, registry.SET_VALUE)
	} else {
		return "", fmt.Errorf("only HKCU supported for delete")
	}
	if err != nil {
		return "", err
	}
	defer k.Close()
	return "", k.DeleteValue(valName)
}

func regEnumKeys(p string) (string, error) {
	var k registry.Key
	var err error
	if strings.HasPrefix(strings.ToUpper(p), "HKCU") {
		rest := ""
		if len(p) > 4 {
			rest = p[5:]
		}
		k, err = registry.OpenKey(registry.CURRENT_USER, rest, registry.ENUMERATE_SUB_KEYS)
	} else if strings.HasPrefix(strings.ToUpper(p), "HKLM") {
		rest := ""
		if len(p) > 4 {
			rest = p[5:]
		}
		k, err = registry.OpenKey(registry.LOCAL_MACHINE, rest, registry.ENUMERATE_SUB_KEYS)
	} else {
		return "", fmt.Errorf("use HKCU\\... or HKLM\\...")
	}
	if err != nil {
		return "", err
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return "", err
	}
	return strings.Join(names, "\n"), nil
}

func regEnumValues(p string) (string, error) {
	var k registry.Key
	var err error
	if strings.HasPrefix(strings.ToUpper(p), "HKCU") {
		rest := ""
		if len(p) > 4 {
			rest = p[5:]
		}
		k, err = registry.OpenKey(registry.CURRENT_USER, rest, registry.QUERY_VALUE)
	} else if strings.HasPrefix(strings.ToUpper(p), "HKLM") {
		rest := ""
		if len(p) > 4 {
			rest = p[5:]
		}
		k, err = registry.OpenKey(registry.LOCAL_MACHINE, rest, registry.QUERY_VALUE)
	} else {
		return "", fmt.Errorf("use HKCU\\... or HKLM\\...")
	}
	if err != nil {
		return "", err
	}
	defer k.Close()
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return "", err
	}
	return strings.Join(names, "\n"), nil
}
