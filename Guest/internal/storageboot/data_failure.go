package storageboot

import (
	"strings"
	"sync"
)

// One best-effort breadcrumb per worker. The only production caller receives
// storageserver's closed formatter output; no error value reaches the console.
// The worker's stdio remains /dev/null and its private command channel is unchanged.
type dataFailureReporter struct{ once sync.Once }

func (r *dataFailureReporter) report(line string, write func([]byte)) {
	if line == "" || len(line) > 192 || !strings.HasPrefix(line, "cengine storage-data-handshake-failure phase=") || strings.ContainsAny(line, "\x00\r\n") {
		return
	}
	r.once.Do(func() { write([]byte(line + "\n")) })
}

var lifecycleDataFailureReporter dataFailureReporter

func reportLifecycleDataFailure(line string) {
	lifecycleDataFailureReporter.report(line, writeDataFailureConsole)
}
