package storageboot

import (
	pc "dev.cengine/guest/internal/preparecompat"
	"encoding/json"
)

// Recheck original bytes before the outer JSON decoder can repair Unicode.
func validCompatibilityRaw(raw []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	for key, body := range fields {
		var err error
		switch key {
		case "prepareCompatibilityArm":
			_, err = pc.DecodeStorageArm(body)
		case "prepareCompatibilityQuery":
			_, err = pc.DecodeStorageQuery(body)
		case "prepareCompatibilityWorkerWait":
			_, err = pc.DecodeStorageWorkerWait(body)
		case "prepareCompatibilityCheckpointExit", "prepareCompatibilityCheckpointAck":
			_, err = pc.DecodeWorkerCheckpointExit(body)
		case "prepareCompatibilityCheckpointWait":
			_, err = pc.DecodeWorkerCheckpointWait(body)
		case "prepareCompatibilityRelease", "prepareCompatibilityWorkerExit":
			_, err = pc.DecodeStorageRelease(body)
		case "prepareCompatibilityStatus":
			_, err = pc.DecodeStorageStatus(body)
		}
		if err != nil {
			return false
		}
	}
	return true
}
