package supervisor

import "errors"

// Managed copy-up operation tokens are a closed diagnostic vocabulary: they name
// a code boundary, never a path, request field, credential or errno-derived text.
// They exist only to attribute an ambiguous managed-copy-up failure (currently
// EACCES) to one bounded operation site on the storage VM.
type managedCopyOpError struct {
	op  string
	err error
}

func (e *managedCopyOpError) Error() string { return "managed copy-up: " + e.op }
func (e *managedCopyOpError) Unwrap() error { return e.err }

// wrapManagedCopyOp preserves the original error identity for errors.Is/As and
// never replaces an existing op wrapper: the innermost (most precise) op stays
// visible; outer boundaries only name errors no inner boundary claimed.
func wrapManagedCopyOp(op string, err error) error {
	if err == nil {
		return nil
	}
	var existing *managedCopyOpError
	if errors.As(err, &existing) {
		return err
	}
	return &managedCopyOpError{op: op, err: err}
}

// ManagedCopyOperation returns the outermost closed op token, or "" when the
// failure did not pass through a managed copy-up boundary.
func ManagedCopyOperation(err error) string {
	var failure *managedCopyOpError
	if errors.As(err, &failure) && failure != nil {
		return failure.op
	}
	return ""
}

const (
	opVolumeBaseOpen       = "volume-base-open"
	opRootGrantOpen        = "root-grant-open"
	opBeginCopy            = "begin-copy"
	opCheckRoot            = "check-root"
	opRecover              = "recover"
	opEmptinessProbe       = "emptiness-probe"
	opSourceRootOpen       = "source-root-open"
	opSourcePin            = "source-pin"
	opTransactionBind      = "transaction-bind"
	opTransactionCheck     = "transaction-check"
	opTransactionOpen      = "transaction-open"
	opStagingMkdir         = "staging-mkdir"
	opStagingOpen          = "staging-open"
	opCopyContents         = "copy-contents"
	opStagingSync          = "staging-sync"
	opIdentityQuery        = "identity-query"
	opManifestWrite        = "manifest-write"
	opSealManifest         = "seal-manifest"
	opAuthenticateManifest = "authenticate-manifest"
	opPublicationIO        = "publication-io"
	opPublicChildRename    = "public-child-rename"
	opPublicDirSync        = "public-directory-sync"
	opRootMetadata         = "root-metadata"
	opRootTimes            = "root-times"
	opRootFsync            = "root-fsync"
	opRootWitness          = "root-witness"
	opStartCleanup         = "start-cleanup"
	opFinishCopy           = "finish-copy"
	opFinishNoCopy         = "finish-nocopy"
)
