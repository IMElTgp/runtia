package report

import (
	"encoding/json"

	"github.com/IMElTgp/container-runtime-analysis/internal/model"
)

/**
 * json.go
 * store all findings as JSON
 */

// findingsToJSON is expected to be called once for each category, and process all findings
// of one category at a time
// input findings should be one of NamespaceFindings, MountFindings, CapabilitiesFindings, and
// SeccompFindings
func findingsToJSON(findings []*model.Finding) (jsons []byte, err error, Type string) {
	if len(findings) == 0 {
		return nil, nil, ""
	}

	jsons, err = json.MarshalIndent(findings, "", " ")
	// assume the input findings are of the same category
	Type = findings[0].Category
	return
}
