//go:build linux

package supervisor

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSocketProxyStageArguments(t *testing.T) {
	if !IsSocketProxyStage([]string{"/init", socketProxyStageArgument, "4200"}) {
		t.Fatal("socket proxy stage was not recognized")
	}
	for _, arguments := range [][]string{{"/init"}, {"/init", socketProxyStageArgument}, {"/init", socketProxyStageArgument, "4200", "extra"}} {
		if IsSocketProxyStage(arguments) {
			t.Fatalf("invalid socket proxy arguments were accepted: %v", arguments)
		}
	}
}

func TestSocketProxyRelaysBidirectionally(t *testing.T) {
	client, left := net.Pipe()
	right, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		relaySocketProxy(left, right)
		close(done)
	}()

	request := []byte("request")
	requestWritten := make(chan error, 1)
	go func() {
		_, err := client.Write(request)
		requestWritten <- err
	}()
	receivedRequest := make([]byte, len(request))
	if _, err := io.ReadFull(server, receivedRequest); err != nil {
		t.Fatal(err)
	}
	if err := <-requestWritten; err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(receivedRequest, request) {
		t.Fatalf("unexpected relayed request %q", receivedRequest)
	}

	response := []byte("response")
	responseWritten := make(chan error, 1)
	go func() {
		_, err := server.Write(response)
		responseWritten <- err
	}()
	receivedResponse := make([]byte, len(response))
	if _, err := io.ReadFull(client, receivedResponse); err != nil {
		t.Fatal(err)
	}
	if err := <-responseWritten; err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(receivedResponse, response) {
		t.Fatalf("unexpected relayed response %q", receivedResponse)
	}

	client.Close()
	server.Close()
	<-done
}

func TestSocketProxyDestinationMustBeAbsoluteAndNonRoot(t *testing.T) {
	if value, err := workloadDestination("/var/run/docker.sock"); err != nil || value != "/var/run/docker.sock" {
		t.Fatalf("unexpected destination %q: %v", value, err)
	}
	for _, invalid := range []string{"relative.sock", "/"} {
		if _, err := workloadDestination(invalid); err == nil {
			t.Fatalf("accepted invalid destination %q", invalid)
		}
	}
}

func TestDetachUnixListenerPreservesSocketPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	file, err := detachUnixListener(listener)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if info, err := os.Lstat(path); err != nil {
		t.Fatalf("socket path was removed during listener handoff: %v", err)
	} else if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("handoff path mode is %v, want a Unix socket", info.Mode())
	}
}
