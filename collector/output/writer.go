package output

import (
	"collector/modules"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type KerberoastResult struct{}
type ASREPResult struct{}

type ScanResult struct {
	ScanTime       time.Time          `json:"scan_time"`
	Domain         string             `json:"domain"`
	CollectorVer   string             `json:"collector_ver"`
	Users          []modules.User     `json:"users"`
	Groups         []modules.Group    `json:"groups"`
	Kerberoastable []KerberoastResult `json:"kerberoastable"`
	ASREPRoastable []ASREPResult      `json:"asrep_roastable"`
}

func WriteJSON(result ScanResult, outputPath string) error {
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal scan result: %w", err)
	}

	if err := os.WriteFile(outputPath, jsonBytes, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}
