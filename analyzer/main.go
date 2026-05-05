package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	aoutput "analyzer/output"
	"analyzer/parser"
	"analyzer/scoring"
)

func main() {
	inPath  := flag.String("in",  "adex_raw.json",    "Path to adex_raw.json")
	outPath := flag.String("out", "adex_report.json", "Path to output report")
	flag.Parse()

	if _, err := os.Stat(*inPath); os.IsNotExist(err) {
		log.Fatalf("Input file not found: %s", *inPath)
	}

	raw, err := parser.ReadRawJSON(*inPath)
	if err != nil {
		log.Fatalf("Failed to read raw JSON: %v", err)
	}

	findings := scoring.ScoreAll(*raw)

	if err := aoutput.WriteReport(findings, *raw, *outPath); err != nil {
		log.Fatalf("Failed to write report: %v", err)
	}

	critCount := 0
	for _, f := range findings {
		if f.Color == "red" {
			critCount++
		}
	}

	fmt.Printf("✓ Report written to %s\n", *outPath)
	fmt.Printf("  Total findings : %d\n", len(findings))
	fmt.Printf("  Critical       : %d\n", critCount)
}
