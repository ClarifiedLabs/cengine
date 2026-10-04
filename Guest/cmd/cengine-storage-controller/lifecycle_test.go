//go:build darwin && cgo

package main

import "testing"

func TestOnlyLifecycleArguments(t *testing.T) {
	for _, args := range [][]string{{"controller"}, {"controller", "--lifecycle-v2"}} {
		if !validLifecycleArguments(args) {
			t.Fatalf("rejected lifecycle arguments %v", args)
		}
	}
	for _, args := range [][]string{nil, {"controller", "--test-compat"}, {"controller", "--lifecycle-v2", "--test-compat"}, {"controller", "--lifecycle-v2=true"}} {
		if validLifecycleArguments(args) {
			t.Fatalf("accepted obsolete/invalid arguments %v", args)
		}
	}
}
