package supervisor

import "errors"

// PrepareStage is diagnostic-only: never a wire value or an admission decision.
type PrepareStage uint8

const (
	PrepareValidation PrepareStage = iota
	PrepareRootMount
	PrepareManagedCopyUp
	PrepareVolume
	PrepareIOMount
	PrepareIOClaim
	PrepareCommit
)

func (s PrepareStage) name() string {
	switch s {
	case PrepareValidation:
		return "validation"
	case PrepareRootMount:
		return "root-mount"
	case PrepareManagedCopyUp:
		return "managed-copyup"
	case PrepareVolume:
		return "volume"
	case PrepareIOMount:
		return "io-mount"
	case PrepareIOClaim:
		return "io-claim"
	case PrepareCommit:
		return "commit"
	default:
		return "other"
	}
}

type prepareFailure struct {
	stage PrepareStage
	cause error
}

func (*prepareFailure) Error() string   { return "supervisor: prepare failure" }
func (e *prepareFailure) Unwrap() error { return e.cause }

// WithPrepareFailureStage preserves the innermost recorded prepare boundary and
// original errors.Is/As identity. It never formats the potentially private cause.
func WithPrepareFailureStage(stage PrepareStage, err error) error {
	if err == nil {
		return nil
	}
	var existing *prepareFailure
	if errors.As(err, &existing) {
		return err
	}
	return &prepareFailure{stage: stage, cause: err}
}

func PrepareFailureStage(err error) string {
	var failure *prepareFailure
	if errors.As(err, &failure) && failure != nil {
		return failure.stage.name()
	}
	return "other"
}

// Keep the observed operation boundary when existing cancellation policy replaces
// the cause. Do not join the old cause: cancellation keeps its original identity.
func replacePrepareFailureCause(previous, cause error) error {
	var failure *prepareFailure
	if errors.As(previous, &failure) && failure != nil {
		return WithPrepareFailureStage(failure.stage, cause)
	}
	return cause
}
