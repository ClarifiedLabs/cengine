//go:build linux

package boot

import (
	"errors"
	"os"
	"strings"
)

func KernelParameter(name string) (string, error) {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", err
	}
	return kernelParameter(data, name)
}

func kernelParameter(data []byte, name string) (string, error) {
	prefix := name + "="
	for _, field := range strings.Fields(string(data)) {
		if strings.HasPrefix(field, prefix) {
			value := strings.TrimPrefix(field, prefix)
			if value != "" {
				return value, nil
			}
		}
	}
	return "", errors.New("kernel parameter " + name + " is missing")
}
