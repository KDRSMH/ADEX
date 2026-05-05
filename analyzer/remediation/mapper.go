package remediation

import (
	"encoding/json"
	"fmt"
	"os"

	"analyzer/scoring"
)

func LoadDB(dbPath string) (map[string]scoring.Remediation, error) {
	data, err := os.ReadFile(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read remediation db: %w", err)
	}

	var db map[string]scoring.Remediation
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("failed to parse remediation db: %w", err)
	}

	return db, nil
}

func MapRemediation(findings []scoring.Finding, db map[string]scoring.Remediation) []scoring.Finding {
	for i, f := range findings {
		if rem, ok := db[f.Code]; ok {
			findings[i].Remediation = rem
		} else {
			findings[i].Remediation = scoring.Remediation{
				Title: "Manual review required",
			}
		}
	}
	return findings
}
