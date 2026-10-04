package storageworker

import "os"

// ReplyPendingError means the complete packet was sent, but receiving its reply
// hit a deadline. It is not permission to resend: only a receive-only continuation
// may resolve the outstanding reply. Send errors and EOF never have this type.
type ReplyPendingError struct{}

func (*ReplyPendingError) Error() string { return "storageworker: sent packet awaiting reply" }
func (*ReplyPendingError) Unwrap() error { return os.ErrDeadlineExceeded }
