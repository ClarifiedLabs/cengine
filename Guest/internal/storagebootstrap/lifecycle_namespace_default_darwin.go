//go:build darwin && cgo && !cengine_lifecycle_v2_qualification

package storagebootstrap

/*
#ifdef CE_STORAGE_LIFECYCLE_QUALIFICATION
#error qualification namespace requires the qualification build tag
#endif
*/
import "C"

const lifecycleQualificationNamespace = false
