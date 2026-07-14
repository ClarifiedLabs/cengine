//go:build linux

package boot

import "testing"

func TestKernelParameterReadsExactField(t *testing.T) {
	value, err := kernelParameter([]byte("console=hvc0 cengine.management_vlan=4094 other=value\n"), "cengine.management_vlan")
	if err != nil || value != "4094" {
		t.Fatalf("unexpected parameter %q, %v", value, err)
	}
}

func TestKernelParameterRejectsMissingAndEmptyValues(t *testing.T) {
	for _, data := range []string{"console=hvc0", "cengine.volume_server="} {
		if _, err := kernelParameter([]byte(data), "cengine.volume_server"); err == nil {
			t.Fatalf("expected %q to be rejected", data)
		}
	}
}
