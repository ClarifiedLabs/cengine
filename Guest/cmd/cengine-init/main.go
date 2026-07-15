//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"

	"dev.cengine/guest/internal/boot"
	guestnetwork "dev.cengine/guest/internal/network"
	"dev.cengine/guest/internal/operations"
	"dev.cengine/guest/internal/protocol"
	guestrootfs "dev.cengine/guest/internal/rootfs"
	"dev.cengine/guest/internal/supervisor"
	"dev.cengine/guest/internal/vsock"
)

type controlServer struct {
	process *supervisor.Supervisor
}

func main() {
	if supervisor.IsExecStage1(os.Args) {
		pid, err := strconv.Atoi(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		if err := supervisor.RunExecStage1(pid); err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				os.Exit(exit.ExitCode())
			}
			log.Fatal(err)
		}
		return
	}
	if supervisor.IsExecStage2(os.Args) {
		if err := supervisor.RunExecStage2(); err != nil {
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
	go serveRootFS(rootListener)
	state := &controlServer{process: supervisor.New()}
	execListener, err := vsock.Listen(protocol.ExecIOPort)
	if err != nil {
		log.Fatalf("listen on exec I/O vsock: %v", err)
	}
	defer execListener.Close()
	go state.serveExecIO(execListener)
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Printf("accept control connection: %v", err)
			continue
		}
		go state.serve(connection)
	}
}

func (state *controlServer) serveExecIO(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Printf("accept exec I/O connection: %v", err)
			continue
		}
		go state.handleExecIO(connection)
	}
}

func (state *controlServer) handleExecIO(connection net.Conn) {
	defer connection.Close()
	request, err := protocol.ReadEnvelope(connection)
	if err != nil {
		return
	}
	response := protocol.Envelope{ID: request.ID, Operation: request.Operation}
	if request.Operation != "start-exec-stream" {
		response.Error = &protocol.Error{Code: "unsupported", Message: "unsupported exec I/O operation"}
		_ = protocol.WriteEnvelope(connection, response)
		return
	}
	var value struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(request.Payload, &value); err != nil {
		response.Error = &protocol.Error{Code: "invalid_request", Message: err.Error()}
		_ = protocol.WriteEnvelope(connection, response)
		return
	}

	prepared := false
	_, err = state.process.StartExecAttached(value.ID, connection, func(protocol.ProcessStatus) error {
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

func serveRootFS(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Printf("accept rootfs connection: %v", err)
			continue
		}
		go func() {
			defer connection.Close()
			envelope, err := protocol.ReadEnvelope(connection)
			response := protocol.Envelope{ID: envelope.ID, Operation: "prepare-rootfs"}
			if err == nil {
				var request protocol.RootFSRequest
				err = json.Unmarshal(envelope.Payload, &request)
				if err == nil {
					err = guestrootfs.Apply(request.RootDevice, request.Layers, connection)
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
	for {
		request, err := protocol.ReadEnvelope(connection)
		if err != nil {
			return
		}
		response := protocol.Envelope{ID: request.ID, Operation: request.Operation}
		payload, operationError := state.handle(request)
		if operationError != nil {
			response.Error = &protocol.Error{Code: "internal", Message: operationError.Error()}
		} else {
			response.Payload = payload
		}
		if err := protocol.WriteEnvelope(connection, response); err != nil {
			return
		}
	}
}

func (state *controlServer) handle(request protocol.Envelope) (json.RawMessage, error) {
	switch request.Operation {
	case "ping":
		return json.RawMessage(`{"status":"ready"}`), nil
	case "prepare":
		var spec protocol.WorkloadSpec
		if err := json.Unmarshal(request.Payload, &spec); err != nil {
			return nil, fmt.Errorf("decode workload: %w", err)
		}
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
		var resources protocol.Resources
		if err := json.Unmarshal(request.Payload, &resources); err != nil {
			return nil, fmt.Errorf("decode resources: %w", err)
		}
		if err := state.process.UpdateResources(resources); err != nil {
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
		value, err := operations.Stats(pid)
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
		if err := operations.CopyIn(value.Source, value.Destination, value.Ownership); err != nil {
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
		if err := operations.CopyOut(value.Source, value.Destination); err != nil {
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
	case "start-exec":
		var value struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(request.Payload, &value); err != nil {
			return nil, err
		}
		status, err := state.process.StartExec(value.ID)
		if err != nil {
			return nil, err
		}
		return json.Marshal(status)
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
