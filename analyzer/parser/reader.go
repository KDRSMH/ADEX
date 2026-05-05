package parser

import (
	"encoding/json"
	"fmt"
	"os"

	"collector/output"
)

func ReadRawJSON(filepath string) (*output.ScanResult, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read raw json: %w", err)
	}

	var result output.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal raw json: %w", err)
	}

	return &result, nil
}
