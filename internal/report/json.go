package report

import (
	"encoding/json"
	"fmt"

	"github.com/IMElTgp/container-runtime-analysis/internal/model"
)

/**
 * json.go
 * store all findings as JSON
 */

// FindingsToJSON is expected to be called once for each category, and process all findings
// of one category at a time
// input findings should be one of namespaceFindings, mountFindings, capabilitiesFindings, and
// seccompFindings
func FindingsToJSON(findings []*model.Finding) (jsons []byte, err error, Type string) {
	if len(findings) == 0 {
		return nil, fmt.Errorf("internal/report.go: FindingsToJSON: empty findings"), ""
	}

	jsons, err = json.MarshalIndent(findings, "", " ")
	// assume the input findings are of the same category
	Type = findings[0].Category
	return
}
