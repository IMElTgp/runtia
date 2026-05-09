package report

import (
	"fmt"
	"os"

	"github.com/IMElTgp/container-runtime-analysis/internal/model"
)

/**
 * writer.go
 * write JSON content into files (separately, by finding type)
 */

func writeJSONFile(jsons []byte, Type string) error {
	var (
		fd  *os.File
		err error
	)

	switch Type {
	case "namespace":
		fd, err = os.OpenFile("namespace.json", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		defer fd.Close()
	case "mount":
		fd, err = os.OpenFile("mount.json", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		defer fd.Close()
	case "seccomp":
		fd, err = os.OpenFile("seccomp.json", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		defer fd.Close()
	case "capabilities":
		fd, err = os.OpenFile("capabilities.json", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}
		defer fd.Close()
	case "":
	default:
		return fmt.Errorf("internal/report/writer.go: unknown finding category %s, unable to create json file", Type)
	}
	if fd != nil {
		_, err = fd.Write(jsons)
		return err
	}
	return nil
}

// WriteFindingsAsJSON is expected to be called once for each category
func WriteFindingsAsJSON(findings []*model.Finding) error {
	jsons, err, Type := findingsToJSON(findings)
	if err != nil {
		return err
	}
	return writeJSONFile(jsons, Type)
}
