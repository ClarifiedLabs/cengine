//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"dev.cengine/guest/internal/boot"
	"dev.cengine/guest/internal/diskbootstrap"
	guestnetwork "dev.cengine/guest/internal/network"
	"dev.cengine/guest/internal/operations"
	"dev.cengine/guest/internal/protocol"
	guestrootfs "dev.cengine/guest/internal/rootfs"
	"dev.cengine/guest/internal/supervisor"
	"dev.cengine/guest/internal/vsock"
	"dev.cengine/guest/internal/workloadstorage"
)

type controlServer struct {
	managed         *workloadstorage.Server // installed before any control listener starts
	process         *supervisor.Supervisor
	setTime         func(seconds, microseconds int64) error
	rootMu          sync.Mutex
	rootConnections map[net.Conn]struct{}
	rootSealed      bool
	rootWorkers     sync.WaitGroup
}

func main() {
	if supervisor.IsExecStage1(os.Args) {
		pid, err := strconv.Atoi(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		if err := supervisor.RunExecStage1(pid); err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				os.Exit(supervisor.ExecStageExitCode(exit))
			}
			log.Fatal(err)
		}
		return
	}
	if supervisor.IsExecStage2(os.Args) {
		if err := supervisor.RunExecStage2(); err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				log.Print(err)
			}
			os.Exit(supervisor.ExecStageExitCode(err))
		}
		return
	}
	if supervisor.IsExecStage3(os.Args) {
		if err := supervisor.RunExecStage3(); err != nil {
			log.Print(err)
			os.Exit(supervisor.ExecStageExitCode(err))
		}
		return
	}
	if supervisor.IsSocketProxyStage(os.Args) {
		if err := supervisor.RunSocketProxyStage(os.Args); err != nil {
			log.Fatal(err)
		}
		return
	}
	if supervisor.IsStage2(os.Args) {
		if err := supervisor.RunStage2(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if os.Getpid() != 1 {
		log.Fatal("cengine-init must run as PID 1")
	}
	if err := boot.MountKernelFilesystems(); err != nil {
		log.Fatalf("mount kernel filesystems: %v", err)
	}
	verifiedBoot, err := diskbootstrap.RunVerified("container")
	if err != nil {
		log.Fatalf("disk bootstrap: %v", err)
	}
	defer verifiedBoot.Close()
	if err := boot.MountBinfmtMisc(); err != nil {
		log.Printf("mount binfmt_misc: %v", err)
	}
	// Container VMs carry a Rosetta for Linux virtiofs share; the storage VM
	// and hosts without Rosetta do not, so an absent share is not an error.
	if err := boot.MountVirtioFS("rosetta", "/run/cengine/rosetta"); err != nil {
		log.Printf("rosetta share unavailable: %v", err)
	} else if err := boot.RegisterRosetta("/run/cengine/rosetta/rosetta"); err != nil {
		log.Printf("register rosetta binfmt handler: %v", err)
	}
	if err := boot.MountVirtioFS("cengine-io", "/run/cengine/io"); err != nil {
		log.Fatalf("mount I/O share: %v", err)
	}
	managementAddress, err := boot.KernelParameter("cengine.management_address")
	if err != nil {
		log.Fatal(err)
	}
	managementVLAN, err := boot.KernelParameter("cengine.management_vlan")
	if err != nil {
		log.Fatal(err)
	}
	vlan, err := strconv.ParseUint(managementVLAN, 10, 16)
	if err != nil {
		log.Fatalf("parse management VLAN: %v", err)
	}
	if err := guestnetwork.ConfigureManagement(managementAddress, uint16(vlan)); err != nil {
		log.Fatalf("configure management network: %v", err)
	}
	state := &controlServer{process: supervisor.New(), setTime: operations.SetTime}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	managed, err := workloadstorage.NewManagedServer(verifiedBoot, state.process, state.cancelRootFS)
	if err != nil {
		log.Fatal("private workload storage startup refused")
	}
	state.managed = managed
	var daemons sync.WaitGroup
	startDaemon := func(run func()) { daemons.Add(1); go func() { defer daemons.Done(); run() }() }
	listener, err := vsock.Listen(protocol.ControlPort)
	if err != nil {
		log.Fatalf("listen on control vsock: %v", err)
	}
	defer listener.Close()
	rootListener, err := vsock.Listen(protocol.RootFSContentPort)
	if err != nil {
		log.Fatalf("listen on rootfs vsock: %v", err)
	}
	defer rootListener.Close()
	startDaemon(func() { state.serveRootFS(rootListener) })
	execListener, err := vsock.Listen(protocol.ExecIOPort)
	if err != nil {
		log.Fatalf("listen on exec I/O vsock: %v", err)
	}
	defer execListener.Close()
	startDaemon(func() { state.serveExecIO(execListener) })
	portListener, err := vsock.Listen(protocol.PortProxyPort)
	if err != nil {
		log.Fatalf("listen on port proxy vsock: %v", err)
	}
	defer portListener.Close()
	startDaemon(func() { state.servePortProxy(portListener) })
	if managed != nil {
		startDaemon(func() { _ = managed.Serve(ctx) })
	}
	defer func() {
		cancel()
		_ = listener.Close()
		_ = rootListener.Close()
		_ = execListener.Close()
		_ = portListener.Close()
		if managed != nil {
			_ = managed.Close()
		}
		state.cancelRootFS()
		daemons.Wait()
		state.rootWorkers.Wait()
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return
			}
			log.Print("control accept failed")
			continue
		}
		go state.serve(connection)
	}
}

func (state *controlServer) servePortProxy(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return
			}
			continue
		}
		if !hostPeer(connection) {
			_ = connection.Close()
			continue
		}
		go state.handlePortProxy(connection)
	}
}

func (state *controlServer) handlePortProxy(connection net.Conn) {
	defer connection.Close()
	if !hostPeer(connection) {
		return
	}
	request, err := protocol.ReadEnvelope(connection)
	if err != nil {
		return
	}
	response := protocol.ResponseEnvelope(request)
	if request.Operation != "start-port-stream" {
		response.Error = &protocol.Error{Code: "unsupported", Message: "unsupported port proxy operation"}
		_ = protocol.WriteEnvelope(connection, response)
		return
	}
	var value struct {
		Transport string `json:"transport"`
		Port      uint16 `json:"port"`
		IPv6      bool   `json:"ipv6"`
	}
	if err := json.Unmarshal(request.Payload, &value); err != nil {
		response.Error = &protocol.Error{Code: "invalid_request", Message: err.Error()}
		_ = protocol.WriteEnvelope(connection, response)
		return
	}
	target, err := state.process.DialPublishedPort(value.Transport, value.Port, value.IPv6)
	if err != nil {
		response.Error = &protocol.Error{Code: "connect", Message: err.Error()}
		_ = protocol.WriteEnvelope(connection, response)
		return
	}
	defer target.Close()
	response.Payload = json.RawMessage(`{"status":"connected"}`)
	if err := protocol.WriteEnvelope(connection, response); err != nil {
		return
	}
	if value.Transport == "udp" {
		relayPortDatagrams(connection, target)
		return
	}
	relayPortStream(connection, target)
}

func relayPortStream(left, right net.Conn) {
	var group sync.WaitGroup
	var closeOnce sync.Once
	closeBoth := func() {
		_ = left.Close()
		_ = right.Close()
	}
	group.Add(2)
	forward := func(destination, source net.Conn) {
		defer group.Done()
		defer closeOnce.Do(closeBoth)
		_, _ = io.Copy(destination, source)
	}
	go forward(right, left)
	go forward(left, right)
	group.Wait()
}

func relayPortDatagrams(stream, datagrams net.Conn) {
	var group sync.WaitGroup
	var closeOnce sync.Once
	closeBoth := func() {
		_ = stream.Close()
		_ = datagrams.Close()
	}
	group.Add(2)
	go func() {
		defer group.Done()
		defer closeOnce.Do(closeBoth)
		for {
			payload, err := readPortDatagram(stream)
			if err != nil {
				return
			}
			if _, err := datagrams.Write(payload); err != nil {
				return
			}
		}
	}()
	go func() {
		defer group.Done()
		defer closeOnce.Do(closeBoth)
		buffer := make([]byte, 65_535)
		for {
			count, err := datagrams.Read(buffer)
			if err != nil {
				return
			}
			if err := writePortDatagram(stream, buffer[:count]); err != nil {
				return
			}
		}
	}()
	group.Wait()
}

func readPortDatagram(reader io.Reader) ([]byte, error) {
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	if size > 65_535 {
		return nil, fmt.Errorf("invalid port datagram size %d", size)
	}
	payload := make([]byte, size)
	_, err := io.ReadFull(reader, payload)
	return payload, err
}

func writePortDatagram(writer io.Writer, payload []byte) error {
	if len(payload) > 65_535 {
		return fmt.Errorf("port datagram is too large: %d", len(payload))
	}
	if err := binary.Write(writer, binary.BigEndian, uint32(len(payload))); err != nil {
		return err
	}
	for len(payload) > 0 {
		count, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		payload = payload[count:]
	}
	return nil
}

func (state *controlServer) serveExecIO(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return
			}
			continue
		}
		if !hostPeer(connection) {
			_ = connection.Close()
			continue
		}
		go state.handleExecIO(connection)
	}
}

func (state *controlServer) handleExecIO(connection net.Conn) {
	defer connection.Close()
	if !hostPeer(connection) {
		return
	}
	request, err := protocol.ReadEnvelope(connection)
	if err != nil {
		return
	}
	response := protocol.ResponseEnvelope(request)
	if request.Operation != "start-exec-stream" {
		response.Error = &protocol.Error{Code: "unsupported", Message: "unsupported exec I/O operation"}
		_ = protocol.WriteEnvelope(connection, response)
		return
	}
	var value struct {
		ID          string                 `json:"id"`
		ConsoleSize *protocol.TerminalSize `json:"consoleSize,omitempty"`
	}
	if err := json.Unmarshal(request.Payload, &value); err != nil {
		response.Error = &protocol.Error{Code: "invalid_request", Message: err.Error()}
		_ = protocol.WriteEnvelope(connection, response)
		return
	}

	prepared := false
	_, err = state.process.StartExecAttached(value.ID, value.ConsoleSize, connection, func(protocol.ProcessStatus) error {
		prepared = true
		return nil
	})
	if err != nil {
		log.Printf("attached exec stream %s failed: %v", value.ID, err)
		if !prepared {
			response.Payload = nil
			response.Error = &protocol.Error{Code: "exec", Message: err.Error()}
			_ = protocol.WriteEnvelope(connection, response)
		}
		return
	}
	state.process.WaitExec(value.ID)
}

func hostPeer(connection net.Conn) bool {
	peer, ok := connection.RemoteAddr().(vsock.Addr)
	return ok && peer.CID == 2
}

func (state *controlServer) cancelRootFS() {
	state.rootMu.Lock()
	defer state.rootMu.Unlock()
	state.rootSealed = true
	for connection := range state.rootConnections {
		_ = connection.Close()
	}
}

func (state *controlServer) serveRootFS(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return
			}
			continue
		}
		if !hostPeer(connection) {
			_ = connection.Close()
			continue
		}
		state.rootMu.Lock()
		if state.rootSealed {
			state.rootMu.Unlock()
			_ = connection.Close()
			continue
		}
		if state.rootConnections == nil {
			state.rootConnections = make(map[net.Conn]struct{})
		}
		state.rootConnections[connection] = struct{}{}
		state.rootWorkers.Add(1)
		state.rootMu.Unlock()
		go func() {
			defer state.rootWorkers.Done()
			defer func() { state.rootMu.Lock(); delete(state.rootConnections, connection); state.rootMu.Unlock() }()
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(120 * time.Second))
			envelope, err := protocol.ReadEnvelope(connection)
			// Layer transfer duration scales with image size. Cancellation closes
			// owned rootfs connections; only the bounded envelope has a deadline.
			if err == nil {
				err = connection.SetDeadline(time.Time{})
			}
			response := protocol.ResponseEnvelope(envelope)
			response.Operation = "prepare-rootfs"
			if err == nil {
				var request protocol.RootFSRequest
				err = json.Unmarshal(envelope.Payload, &request)
				if err == nil {
					err = state.process.WithRootFSPreparation(func() error { return guestrootfs.Apply(request.RootDevice, request.Layers, connection) })
				}
			}
			if err != nil {
				response.Error = &protocol.Error{Code: "rootfs", Message: err.Error()}
			} else {
				response.Payload = json.RawMessage(`{"status":"prepared"}`)
			}
			_ = protocol.WriteEnvelope(connection, response)
		}()
	}
}

func (state *controlServer) serve(connection net.Conn) {
	defer connection.Close()
	if !hostPeer(connection) {
		return
	}
	for {
		request, err := protocol.ReadEnvelope(connection)
		if err != nil {
			return
		}
		response := protocol.ResponseEnvelope(request)
		payload, operationError := state.handle(request)
		if operationError != nil {
			code := "internal"
			var rollbackIncomplete *supervisor.ResourceRollbackIncompleteError
			if errors.As(operationError, &rollbackIncomplete) {
				code = protocol.ErrorResourceRollbackIncomplete
			} else if request.Operation == "prepare-exec" &&
				supervisor.IsIdentityNotFound(operationError) {
				code = protocol.ErrorBadRequest
			}
			response.Error = &protocol.Error{Code: code, Message: operationError.Error()}
		} else {
			response.Payload = payload
		}
		if err := protocol.WriteEnvelope(connection, response); err != nil {
			return
		}
	}
}

func (state *controlServer) handle(request protocol.Envelope) (json.RawMessage, error) {
	// This closed observer vocabulary precedes all ordinary process admission.
	// It cannot start or reconnect a workload or revive the private session.
	switch request.Operation {
	case "original-consumer-arm", "original-consumer-begin", "original-consumer-probe", "original-consumer-result", "original-consumer-release", "original-consumer-positive", "original-consumer-resume":
		return state.managed.OriginalConsumerControl(request.Operation, request.Payload)
	case "ping":
		return json.RawMessage(`{"status":"ready"}`), nil
	case "set-time":
		var value protocol.WallClockTime
		if err := json.Unmarshal(request.Payload, &value); err != nil {
			return nil, fmt.Errorf("decode wall clock time: %w", err)
		}
		setTime := state.setTime
		if setTime == nil {
			setTime = operations.SetTime
		}
		if err := setTime(value.Seconds, value.Microseconds); err != nil {
			return nil, err
		}
		return json.RawMessage(`{"status":"synchronized"}`), nil
	case "prepare-memory-reclaim":
		status, err := operations.PrepareMemoryReclaim()
		if err != nil {
			return nil, err
		}
		return json.Marshal(status)
	case "prepare":
		var spec protocol.WorkloadSpec
		if err := json.Unmarshal(request.Payload, &spec); err != nil {
			return nil, fmt.Errorf("decode workload: %w", err)
		}
		spec.ApplyCompatibilityDefaults(request.Version)
		if err := state.process.Prepare(spec); err != nil {
			return nil, err
		}
		return json.RawMessage(`{"status":"prepared"}`), nil
	case "start":
		status, err := state.process.Start()
		if err != nil {
			return nil, err
		}
		return json.Marshal(status)
	case "update-resources":
		var update protocol.ResourceUpdate
		if err := json.Unmarshal(request.Payload, &update); err != nil {
			return nil, fmt.Errorf("decode resources: %w", err)
		}
		if err := state.process.UpdateResourcesWithCompatibilityFailure(
			update.Resources, update.CompatibilityFailureAfterWrites,
		); err != nil {
			return nil, err
		}
		return json.Marshal(state.process.Status())
	case "signal":
		var signal protocol.SignalRequest
		if err := json.Unmarshal(request.Payload, &signal); err != nil {
			return nil, err
		}
		if err := state.process.Signal(signal.Signal); err != nil {
			return nil, err
		}
		return json.Marshal(state.process.Status())
	case "wait":
		return json.Marshal(state.process.Wait())
	case "connect-network":
		var networkRequest protocol.NetworkRequest
		if err := json.Unmarshal(request.Payload, &networkRequest); err != nil {
			return nil, err
		}
		if err := state.process.ConnectNetwork(networkRequest.Endpoint); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]string{"status": "connected"})
	case "disconnect-network":
		var networkRequest protocol.NetworkRequest
		if err := json.Unmarshal(request.Payload, &networkRequest); err != nil {
			return nil, err
		}
		if err := state.process.DisconnectNetwork(networkRequest.Name); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]string{"status": "disconnected"})
	case "status":
		return json.Marshal(state.process.Status())
	case "statistics":
		pid := state.process.PID()
		if pid == 0 {
			return nil, errors.New("workload is not running")
		}
		value, err := operations.Stats(pid, state.process.CgroupPath())
		if err != nil {
			return nil, err
		}
		return json.Marshal(value)
	case "top":
		pid := state.process.PID()
		if pid == 0 {
			return nil, errors.New("workload is not running")
		}
		value, err := operations.Top(pid)
		if err != nil {
			return nil, err
		}
		return json.Marshal(value)
	case "copy-in":
		var value struct {
			Source      string                 `json:"source"`
			Destination string                 `json:"destination"`
			Ownership   []operations.Ownership `json:"ownership"`
		}
		if err := json.Unmarshal(request.Payload, &value); err != nil {
			return nil, err
		}
		if err := operations.CopyIn(state.process.PID(), value.Source, value.Destination, value.Ownership); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]string{"status": "copied"})
	case "copy-out":
		var value struct {
			Source      string `json:"source"`
			Destination string `json:"destination"`
		}
		if err := json.Unmarshal(request.Payload, &value); err != nil {
			return nil, err
		}
		if err := operations.CopyOut(state.process.PID(), value.Source, value.Destination); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]string{"status": "copied"})
	case "prepare-exec":
		var value protocol.ExecSpec
		if err := json.Unmarshal(request.Payload, &value); err != nil {
			return nil, err
		}
		if err := state.process.PrepareExec(value); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]string{"status": "created"})
	case "discard-exec":
		var value struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(request.Payload, &value); err != nil {
			return nil, err
		}
		if err := state.process.DiscardExec(value.ID); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]string{"status": "discarded"})
	case "start-exec":
		var value struct {
			ID          string                 `json:"id"`
			ConsoleSize *protocol.TerminalSize `json:"consoleSize,omitempty"`
		}
		if err := json.Unmarshal(request.Payload, &value); err != nil {
			return nil, err
		}
		status, err := state.process.StartExec(value.ID, value.ConsoleSize)
		if err != nil {
			return nil, err
		}
		return json.Marshal(status)
	case "resize":
		var value protocol.TerminalSize
		if err := json.Unmarshal(request.Payload, &value); err != nil {
			return nil, err
		}
		if err := state.process.Resize(value); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]string{"status": "resized"})
	case "resize-exec":
		var value struct {
			ID string `json:"id"`
			protocol.TerminalSize
		}
		if err := json.Unmarshal(request.Payload, &value); err != nil {
			return nil, err
		}
		if err := state.process.ResizeExec(value.ID, value.TerminalSize); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]string{"status": "resized"})
	case "exec-status":
		var value struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(request.Payload, &value); err != nil {
			return nil, err
		}
		return json.Marshal(state.process.ExecStatus(value.ID))
	case "wait-exec":
		var value struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(request.Payload, &value); err != nil {
			return nil, err
		}
		return json.Marshal(state.process.WaitExec(value.ID))
	case "signal-exec":
		var value struct {
			ID     string `json:"id"`
			Signal int    `json:"signal"`
		}
		if err := json.Unmarshal(request.Payload, &value); err != nil {
			return nil, err
		}
		if err := state.process.SignalExec(value.ID, value.Signal); err != nil {
			return nil, err
		}
		return json.Marshal(state.process.ExecStatus(value.ID))
	default:
		return nil, fmt.Errorf("unsupported operation %q", request.Operation)
	}
}
