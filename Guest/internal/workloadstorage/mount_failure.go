package workloadstorage

import (
	"sync"

	"dev.cengine/guest/internal/storagefuse"
)

// One line per attachment, before retirement can cancel the private channel.
// The sink receives ONLY fixed text and storagefuse's closed diagnostic tokens.
// No original error, attachment identifier or other configuration reaches it.
type mountFailureReporter struct {
	once sync.Once
	emit func(string)
}

func (r *mountFailureReporter) report(err error, namespace bool) {
	if err == nil {
		return
	}
	r.once.Do(func() {
		stage, site, operation, category := storagefuse.MountFailureDetails(err)
		if namespace {
			stage = "namespace" // native attachment-parent setup, before storagefuse
		}
		r.emit("cengine managed-mount-failure stage=" + stage + " site=" + site + " op=" + operation + " category=" + category)
	})
}

func (r *mountFailureReporter) retirement(retire func(error)) func(error) {
	return func(err error) {
		defer retire(err) // unchanged cause, count and authority, even if the sink panics
		r.report(err, false)
	}
}
