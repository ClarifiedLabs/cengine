//go:build linux

package volume

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const Root = "/run/cengine/volumes"

func MountNFS(server string) error {
	if netOptions, err := nfsMountOptions(server); err != nil {
		return err
	} else if err := os.MkdirAll(Root, 0755); err != nil {
		return err
	} else if err := unix.Mount(server+":/", Root, "nfs", unix.MS_NOSUID|unix.MS_NODEV, netOptions); err != nil && !errors.Is(err, unix.EBUSY) {
		return fmt.Errorf("mount NFS volume store: %w", err)
	}
	return nil
}

func Ensure(name string) (string, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
		return "", fmt.Errorf("invalid volume name %q", name)
	}
	path := filepath.Join(Root, name)
	if err := os.MkdirAll(path, 0755); err != nil {
		return "", err
	}
	return path, nil
}

func nfsMountOptions(server string) (string, error) {
	ip := netParseIPv4(server)
	if ip == "" {
		return "", fmt.Errorf("invalid NFS server address %q", server)
	}
	return "vers=3,addr=" + ip + ",proto=tcp,port=2049,mountaddr=" + ip + ",mountvers=3,mountproto=tcp,mountport=2049,sec=sys,nolock,hard,timeo=50,retrans=3,actimeo=1", nil
}

func netParseIPv4(value string) string {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return ""
	}
	for _, part := range parts {
		if part == "" || len(part) > 3 {
			return ""
		}
		value := 0
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				return ""
			}
			value = value*10 + int(digit-'0')
		}
		if value > 255 {
			return ""
		}
	}
	return strings.Join(parts, ".")
}
