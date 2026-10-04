package storagepki

import "testing"

func TestRootChallengeMatchesSwiftPrincipalAndInitialEpochValidation(t *testing.T) {
	key, err := NewControllerKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*RootChallengeFields){
		func(f *RootChallengeFields) { f.ChildUniqueID = 0 },
		func(f *RootChallengeFields) { f.DaemonUniqueID = 0 },
		func(f *RootChallengeFields) { f.ExpectedEpoch = 2 },
	} {
		f := challengeFields(t, key)
		mutate(&f)
		if _, err := NewRootChallenge(f); err == nil {
			t.Fatal("Swift-rejected ROOT challenge accepted")
		}
	}
}
