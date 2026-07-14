//go:build linux

package supervisor

import (
	"os"
	"strconv"
	"strings"
)

const defaultContainerPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

func processEnvironment(configured []string, hostname, home string, terminal bool) []string {
	defaults := []string{
		"PATH=" + defaultContainerPath,
		"HOSTNAME=" + hostname,
		"HOME=" + home,
	}
	if terminal {
		defaults = append(defaults, "TERM=xterm")
	}

	order := make([]string, 0, len(defaults)+len(configured))
	values := make(map[string]string, len(defaults)+len(configured))
	for _, entry := range append(defaults, configured...) {
		key, _, found := strings.Cut(entry, "=")
		if !found || key == "" {
			continue
		}
		if _, exists := values[key]; !exists {
			order = append(order, key)
		}
		values[key] = entry
	}

	result := make([]string, 0, len(order))
	for _, key := range order {
		result = append(result, values[key])
	}
	return result
}

func homeDirectory(uid int) string {
	if contents, err := os.ReadFile("/etc/passwd"); err == nil {
		identifier := strconv.Itoa(uid)
		for _, line := range strings.Split(string(contents), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) >= 6 && fields[2] == identifier && fields[5] != "" {
				return fields[5]
			}
		}
	}
	if uid == 0 {
		return "/root"
	}
	return "/"
}
