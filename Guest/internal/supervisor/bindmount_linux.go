//go:build linux

package supervisor

// Both read-only and writable host bind shares need the stronger reopen policy.
// Keep this separate from unrelated virtiofs shares (including Rosetta and IO).
func mountHostBindShare(source, staging string, mount mountOperation) error {
	return mount(source, staging, "virtiofs", 0, "host_close_to_open")
}
