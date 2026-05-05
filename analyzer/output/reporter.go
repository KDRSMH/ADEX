package output

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"analyzer/scoring"
	coutput "collector/output"
)

type Report struct {
	GeneratedAt   time.Time         `json:"generated_at"`
	Domain        string            `json:"domain"`
	TotalFindings int               `json:"total_findings"`
	CriticalCount int               `json:"critical_count"`
	HighCount     int               `json:"high_count"`
	MediumCount   int               `json:"medium_count"`
	LowCount      int               `json:"low_count"`
	Findings      []scoring.Finding `json:"findings"`
}

func WriteReport(findings []scoring.Finding, raw coutput.ScanResult, outputPath string) error {
	report := Report{
		GeneratedAt:   time.Now(),
		Domain:        raw.Domain,
		TotalFindings: len(findings),
		Findings:      findings,
	}

	for _, f := range findings {
		switch f.Color {
		case "red":
			report.CriticalCount++
		case "orange":
			report.HighCount++
		case "yellow":
			report.MediumCount++
		case "green":
			report.LowCount++
		}
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	return nil
}
