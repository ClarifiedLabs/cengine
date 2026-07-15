//go:build linux

package supervisor

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"dev.cengine/guest/internal/protocol"
	"dev.cengine/guest/internal/vsock"
	"golang.org/x/sys/unix"
)

const socketProxyStageArgument = "cengine-socket-proxy"

func IsSocketProxyStage(arguments []string) bool {
	return len(arguments) == 3 && arguments[1] == socketProxyStageArgument
}

func RunSocketProxyStage(arguments []string) error {
	port, err := strconv.ParseUint(arguments[2], 10, 32)
	if err != nil || port == 0 {
		return fmt.Errorf("invalid socket proxy port %q", arguments[2])
	}
	file := os.NewFile(3, "socket-proxy-listener")
	if file == nil {
		return errors.New("socket proxy listener is unavailable")
	}
	defer file.Close()
	listener, err := net.FileListener(file)
	if err != nil {
		return fmt.Errorf("open socket proxy listener: %w", err)
	}
	defer listener.Close()
	return serveSocketProxy(listener, func() (net.Conn, error) {
		return vsock.Dial(uint32(port))
	})
}

func serveSocketProxy(listener net.Listener, dial func() (net.Conn, error)) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			target, err := dial()
			if err != nil {
				connection.Close()
				return
			}
			relaySocketProxy(connection, target)
		}()
	}
}

func relaySocketProxy(left, right net.Conn) {
	var group sync.WaitGroup
	group.Add(2)
	forward := func(destination, source net.Conn) {
		defer group.Done()
		_, _ = io.Copy(destination, source)
		if value, ok := destination.(interface{ CloseWrite() error }); ok {
			_ = value.CloseWrite()
		} else {
			_ = destination.Close()
		}
	}
	go forward(right, left)
	go forward(left, right)
	group.Wait()
	_ = left.Close()
	_ = right.Close()
}

func startSocketProxies(mounts []protocol.Mount) (result error) {
	var processes []*os.Process
	defer func() {
		if result != nil {
			for _, process := range processes {
				_ = process.Kill()
			}
		}
	}()

	for _, mount := range mounts {
		if mount.Kind != "socket" {
			continue
		}
		if mount.SocketPort < protocol.SocketProxyPortBase {
			return fmt.Errorf("socket proxy for %s has invalid vsock port %d", mount.Destination, mount.SocketPort)
		}
		destination, err := workloadDestination(mount.Destination)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
			return err
		}
		if info, err := os.Lstat(destination); err == nil {
			if info.IsDir() {
				return fmt.Errorf("socket proxy destination %s is a directory", mount.Destination)
			}
			if err := os.Remove(destination); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: destination, Net: "unix"})
		if err != nil {
			return fmt.Errorf("listen on socket proxy %s: %w", mount.Destination, err)
		}
		mode := os.FileMode(mount.SocketMode)
		if mode == 0 {
			mode = 0600
		}
		if err := os.Chmod(destination, mode); err != nil {
			listener.Close()
			return err
		}
		if err := os.Chown(destination, int(mount.SocketUID), int(mount.SocketGID)); err != nil {
			listener.Close()
			return err
		}
		file, err := detachUnixListener(listener)
		if err != nil {
			return err
		}
		command := exec.Command("/proc/self/exe", socketProxyStageArgument, strconv.FormatUint(uint64(mount.SocketPort), 10))
		command.ExtraFiles = []*os.File{file}
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: unix.SIGKILL}
		if err := command.Start(); err != nil {
			file.Close()
			return fmt.Errorf("start socket proxy for %s: %w", mount.Destination, err)
		}
		file.Close()
		processes = append(processes, command.Process)
	}
	for _, process := range processes {
		_ = process.Release()
	}
	return nil
}

func detachUnixListener(listener *net.UnixListener) (*os.File, error) {
	file, err := listener.File()
	if err != nil {
		listener.Close()
		return nil, err
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func workloadDestination(destination string) (string, error) {
	if !filepath.IsAbs(destination) {
		return "", errors.New("socket proxy destination must be absolute")
	}
	clean := filepath.Clean(destination)
	if clean == "/" {
		return "", errors.New("socket proxy destination cannot replace the workload root")
	}
	return clean, nil
}
