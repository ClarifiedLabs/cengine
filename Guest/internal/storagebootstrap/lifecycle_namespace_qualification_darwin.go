//go:build darwin && cgo && cengine_lifecycle_v2_qualification

package storagebootstrap

/*
// This package-local build tag selects qualification pin validation, separately
// from ordinary compatibility namespace builds. No runtime value supplies pins.
#cgo CFLAGS: -DCE_STORAGE_LIFECYCLE_QUALIFICATION=1
#ifndef CE_STORAGE_LIFECYCLE_QUALIFICATION
#error missing qualification namespace
#endif
enum { ce_lifecycle_qualification_namespace = 1 };
*/
import "C"

const lifecycleQualificationNamespace = C.ce_lifecycle_qualification_namespace == 1
