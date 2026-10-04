package consumercompat

import a "dev.cengine/guest/internal/storageauthority"

// ExactOriginalHello includes the absent PREPARE field: OriginalFor alone would
// discard it and is not sufficient to establish full runtime Hello equality.
func ExactOriginalHello(original Original, h a.DataHello) bool {
	return h.Binding.Prepare == "" && OriginalFor(h) == original
}
