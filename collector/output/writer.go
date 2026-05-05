package output

import (
	"collector/modules"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type ScanResult struct {
	ScanTime               time.Time                     `json:"scan_time"`
	Domain                 string                        `json:"domain"`
	CollectorVer           string                        `json:"collector_ver"`
	Users                  []modules.User                `json:"users"`
	Groups                 []modules.Group               `json:"groups"`
	Kerberoastable         []modules.KerberoastResult    `json:"kerberoastable"`
	ASREPRoastable         []modules.ASREPResult         `json:"asrep_roastable"`
	StaleAccounts          []modules.StaleAccount        `json:"stale_accounts"`
	PasswordPolicy         *modules.PasswordPolicy       `json:"password_policy"`
	DelegationIssues       []modules.DelegationResult    `json:"delegation_issues"`
	AdminSDHolderAnomalies []modules.AdminSDHolderResult `json:"adminsdholder_anomalies"`
	LAPSMissing            []modules.LAPSMissingResult   `json:"laps_missing"`
	SigningStatus          *modules.SigningResult        `json:"signing_status"`
	GPOs                   []modules.GPOResult           `json:"gpos"`
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
