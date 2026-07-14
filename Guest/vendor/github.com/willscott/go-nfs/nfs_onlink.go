package nfs

import (
	"bytes"
	"context"
	"os"
	"reflect"

	"github.com/go-git/go-billy/v5"
	"github.com/willscott/go-nfs-client/nfs/xdr"
)

// Backing billy.FS doesn't support hard links
func onLink(ctx context.Context, w *response, userHandle Handler) error {
	w.errorFmt = wccDataErrorFormatter
	targetHandle, err := xdr.ReadOpaque(w.req.Body)
	if err != nil {
		return &NFSStatusError{NFSStatusInval, err}
	}
	link := DirOpArg{}
	if err := xdr.Read(w.req.Body, &link); err != nil {
		return &NFSStatusError{NFSStatusInval, err}
	}

	targetFS, targetPath, err := userHandle.FromHandle(targetHandle)
	if err != nil {
		return &NFSStatusError{NFSStatusStale, err}
	}
	linkFS, linkPath, err := userHandle.FromHandle(link.Handle)
	if err != nil {
		return &NFSStatusError{NFSStatusStale, err}
	}
	if !reflect.DeepEqual(targetFS, linkFS) {
		return &NFSStatusError{NFSStatusXDev, os.ErrInvalid}
	}
	if !billy.CapabilityCheck(linkFS, billy.WriteCapability) {
		return &NFSStatusError{NFSStatusROFS, os.ErrPermission}
	}

	if len(string(link.Filename)) > PathNameMax {
		return &NFSStatusError{NFSStatusNameTooLong, os.ErrInvalid}
	}

	targetFilePath := targetFS.Join(targetPath...)
	if _, err := targetFS.Stat(targetFilePath); err != nil {
		if os.IsNotExist(err) {
			return &NFSStatusError{NFSStatusNoEnt, err}
		}
		return &NFSStatusError{NFSStatusIO, err}
	}
	linkDirectoryPath := linkFS.Join(linkPath...)
	linkDirectoryInfo, err := linkFS.Stat(linkDirectoryPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &NFSStatusError{NFSStatusNoEnt, err}
		}
		return &NFSStatusError{NFSStatusIO, err}
	}
	if !linkDirectoryInfo.IsDir() {
		return &NFSStatusError{NFSStatusNotDir, nil}
	}
	preLinkDirectory := ToFileAttribute(linkDirectoryInfo, linkDirectoryPath).AsCache()
	newFilePath := linkFS.Join(append(linkPath, string(link.Filename))...)
	if _, err := linkFS.Stat(newFilePath); err == nil {
		return &NFSStatusError{NFSStatusExist, os.ErrExist}
	}

	changer := userHandle.Change(linkFS)
	if changer == nil {
		return &NFSStatusError{NFSStatusAccess, os.ErrPermission}
	}
	cos, ok := changer.(UnixChange)
	if !ok {
		return &NFSStatusError{NFSStatusNotSupp, os.ErrInvalid}
	}

	err = cos.Link(targetFilePath, newFilePath)
	if err != nil {
		return &NFSStatusError{NFSStatusAccess, err}
	}

	writer := bytes.NewBuffer([]byte{})
	if err := xdr.Write(writer, uint32(NFSStatusOk)); err != nil {
		return &NFSStatusError{NFSStatusServerFault, err}
	}

	if err := WritePostOpAttrs(writer, tryStat(targetFS, targetPath)); err != nil {
		return &NFSStatusError{NFSStatusServerFault, err}
	}

	if err := WriteWcc(writer, preLinkDirectory, tryStat(linkFS, linkPath)); err != nil {
		return &NFSStatusError{NFSStatusServerFault, err}
	}

	if err := w.Write(writer.Bytes()); err != nil {
		return &NFSStatusError{NFSStatusServerFault, err}
	}
	return nil
}
