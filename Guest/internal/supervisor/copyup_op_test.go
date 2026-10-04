package supervisor

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The op token is diagnostic-only: errno identity, prepare stage identity and
// nil behavior are preserved, and the vocabulary stays closed and printable.
func TestManagedCopyOperationTokens(t *testing.T) {
	wrapped := wrapManagedCopyOp(opPublicChildRename, unix.EACCES)
	if wrapped == nil || !errors.Is(wrapped, unix.EACCES) {
		t.Fatal("errno identity lost")
	}
	if got := ManagedCopyOperation(wrapped); got != "public-child-rename" {
		t.Fatal("op token mismatch", got)
	}
	nested := wrapManagedCopyOp(opCheckRoot, wrapManagedCopyOp(opIdentityQuery, unix.EACCES))
	if got := ManagedCopyOperation(nested); got != "identity-query" {
		t.Fatal("innermost op must win", got)
	}
	if wrapManagedCopyOp(opCheckRoot, nil) != nil {
		t.Fatal("nil passthrough changed")
	}
	if got := ManagedCopyOperation(unix.EACCES); got != "" {
		t.Fatal("unrelated error must not claim an op", got)
	}
	if got := ManagedCopyOperation(nil); got != "" {
		t.Fatal("nil error must not claim an op", got)
	}
	stage := WithPrepareFailureStage(PrepareManagedCopyUp, wrapManagedCopyOp(opBeginCopy, unix.EACCES))
	if PrepareFailureStage(stage) != "managed-copyup" || !errors.Is(stage, unix.EACCES) {
		t.Fatal("prepare stage identity lost")
	}
	if got := ManagedCopyOperation(stage); got != "begin-copy" {
		t.Fatal("op lost across prepare stage wrap", got)
	}
	for _, op := range []string{
		opVolumeBaseOpen, opRootGrantOpen, opBeginCopy, opCheckRoot, opRecover,
		opEmptinessProbe, opSourceRootOpen, opSourcePin, opTransactionBind,
		opTransactionCheck, opTransactionOpen, opStagingMkdir, opStagingOpen,
		opCopyContents, opStagingSync, opIdentityQuery, opManifestWrite,
		opSealManifest, opAuthenticateManifest, opPublicationIO, opPublicChildRename,
		opPublicDirSync, opRootMetadata, opRootTimes, opRootFsync, opRootWitness,
		opStartCleanup, opFinishCopy, opFinishNoCopy,
	} {
		if op == "" || len(op) > 32 || strings.ContainsAny(op, " \t\n=") {
			t.Fatal("open or unbounded op vocabulary", op)
		}
	}
}
