package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func projectRoot() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}

	exeDir := filepath.Dir(exe)
	if _, statErr := os.Stat(filepath.Join(exeDir, "collector")); statErr == nil {
		return exeDir
	}
	return filepath.Join(exeDir, "..")
}

func binPath(name string) string {
	root := projectRoot()
	if runtime.GOOS == "windows" {
		return filepath.Join(root, name+".exe")
	}
	return filepath.Join(root, name)
}

func clearScreen() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func printBanner() {
	darkRed := "\x1b[38;2;160;0;0m"
	white := "\x1b[97m"
	dimGray := "\x1b[2;37m"
	reset := "\x1b[0m"

	adPart := []string{
		`  ████   █████  `,
		` ██  ██ ██   ██ `,
		` ██  ██ ██   ██ `,
		` ██████ ██   ██ `,
		` ██  ██ ██   ██ `,
		` ██  ██ ██   ██ `,
		` ██  ██ █████   `,
	}
	exPart := []string{
		`████████ ██   ██`,
		`██       ██   ██`,
		`██        ██ ██ `,
		`██████     ███  `,
		`██        ██ ██ `,
		`██       ██   ██`,
		`████████ ██   ██`,
	}

	fmt.Println()
	for i := range adPart {
		fmt.Printf("%s%s%s%s%s\n", darkRed, adPart[i], white, exPart[i], reset)
	}

	fmt.Println()
	fmt.Printf("  %s╔══════════════════════════════════════╗%s\n", dimGray, reset)
	fmt.Printf("  %s║%s  %s Active Directory Security Auditor%s  %s║%s\n", dimGray, reset, darkRed, reset, dimGray, reset)
	fmt.Printf("  %s╚══════════════════════════════════════╝%s\n", dimGray, reset)
	fmt.Println()
}

func printMenu() {
	fmt.Println("  [1] Scan    - Scan Active Directory")
	fmt.Println("  [2] Analyze - Analyze raw JSON.")
	fmt.Println("  [3] Report  - Open dashboard in browser.")
	fmt.Println("  [4] Exit")
	fmt.Println()
	fmt.Print("  Choice: ")
}

func readInput(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func readPasswordMasked(prompt string) string {
	fmt.Print(prompt)

	fd := int(syscall.Stdin)
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return ""
	}
	defer term.Restore(fd, oldState)

	reader := bufio.NewReader(os.Stdin)
	var password []rune

	for {
		ch, _, err := reader.ReadRune()
		if err != nil {
			break
		}

		switch ch {
		case '\n', '\r':
			fmt.Println()
			return string(password)
		case 127, 8:
			if len(password) > 0 {
				password = password[:len(password)-1]
				fmt.Print("\b \b")
			}
		default:
			password = append(password, ch)
			fmt.Print("*")
		}
	}

	fmt.Println()
	return string(password)
}

func normalizeDomainAndBaseDN(input string) (string, string) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		trimmed = "adex.local"
	}

	if strings.Contains(strings.ToUpper(trimmed), "DC=") {
		return "", trimmed
	}

	parts := strings.Split(trimmed, ".")
	var dnParts []string
	for _, part := range parts {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		dnParts = append(dnParts, "DC="+p)
	}

	if len(dnParts) == 0 {
		return "", "DC=adex,DC=local"
	}

	return trimmed, strings.Join(dnParts, ",")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func openBrowser(path string) error {
	var cmd *exec.Cmd
	abs, _ := filepath.Abs(path)
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", abs)
	case "darwin":
		cmd = exec.Command("open", abs)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", abs)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
	return cmd.Start()
}

func runCommand(args []string) error {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			fmt.Println("  " + scanner.Text())
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			fmt.Println("  [!] " + scanner.Text())
		}
	}()

	return cmd.Wait()
}

func pressEnter() {
	fmt.Print("\n  Press Enter to return to the menu...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// ─── MENÜ AKIŞLARI ──────────────────────────────────────────────────────────

func menuScan() (string, bool) {
	fmt.Println()
	fmt.Println("  ── SCAN ────────────────────────────────")

	host := readInput("  DC IP or Hostname: ")
	if host == "" {
		fmt.Println("  [✗] Error: Host is required")
		pressEnter()
		return "", false
	}

	domainInput := readInput("  Domain(e.g., company.local): ")
	domain, baseDN := normalizeDomainAndBaseDN(domainInput)

	username := readInput("  Username (e.g., Administrator@company.local or COMPANY\\Administrator): ")
	if username == "" {
		fmt.Println("  [✗] Error: Username is required")
		pressEnter()
		return "", false
	}
	if !strings.Contains(username, "\\") && !strings.Contains(username, "@") && domain != "" {
		username = username + "@" + domain
	}

	password := readPasswordMasked("  Password: ")

	portStr := readInput("  Port [389]: ")
	if portStr == "" {
		portStr = "389"
	}

	output := readInput("  Output file [adex_raw.json]: ")
	if output == "" {
		output = "adex_raw.json"
	}

	collectorBin := binPath("collector/collector")

	if !fileExists(collectorBin) {
		fmt.Printf("  [✗] Error: collector binary not found → %s\n", collectorBin)
		fmt.Println("  Hint: cd collector && go build -o collector .")
		pressEnter()
		return "", false
	}

	args := []string{
		collectorBin,
		"-Host", host,
		"-Username", username,
		"-Password", password,
		"-BaseDN", baseDN,
		"-Port", portStr,
		"-Output", output,
	}

	fmt.Println()
	fmt.Println("  [*] Scan starting...")
	fmt.Println()

	if err := runCommand(args); err != nil {
		fmt.Printf("\n  [✗] Error: %v\n", err)
		pressEnter()
		return "", false
	}

	fmt.Printf("\n  [✓] Scan completed → %s\n", output)

	cont := readInput("  Do you want to analyze the results? (y/n): ")
	if strings.ToLower(cont) == "y" {
		return output, true
	}

	pressEnter()
	return "", false
}

func menuAnalyze(inputOverride string) (string, bool) {
	fmt.Println()
	fmt.Println("  ── ANALYZE ─────────────────────────────")

	inputDefault := "adex_raw.json"
	if inputOverride != "" {
		inputDefault = inputOverride
	}

	input := readInput(fmt.Sprintf("  Raw JSON file [%s]: ", inputDefault))
	if input == "" {
		input = inputDefault
	}

	output := readInput("  Report file [adex_report.json]: ")
	if output == "" {
		output = "adex_report.json"
	}

	if !fileExists(input) {
		fmt.Printf("  [✗] Error: %s not found\n", input)
		pressEnter()
		return "", false
	}

	analyzerBin := binPath("analyzer/analyzer")

	if !fileExists(analyzerBin) {
		fmt.Printf("  [✗] Error: analyzer binary not found → %s\n", analyzerBin)
		fmt.Println("  Hint: cd analyzer && go build -o analyzer .")
		pressEnter()
		return "", false
	}

	args := []string{analyzerBin, "-in", input, "-out", output}

	fmt.Println()
	fmt.Println("  [*] Analyzing...")
	fmt.Println()

	if err := runCommand(args); err != nil {
		fmt.Printf("\n  [✗] Error: %v\n", err)
		pressEnter()
		return "", false
	}

	fmt.Printf("\n  [✓] Report generated → %s\n", output)

	cont := readInput("  Open dashboard? (y/n): ")
	if strings.ToLower(cont) == "y" {
		return output, true
	}

	pressEnter()
	return "", false
}

func menuReport(reportOverride string) {
	fmt.Println()
	fmt.Println("  ── REPORT ──────────────────────────────")

	reportFile := "report.json"
	if reportOverride != "" {
		reportFile = reportOverride
	}

	root := projectRoot()
	distDir := filepath.Join(root, "web", "dist")
	indexPath := filepath.Join(distDir, "index.html")
	distReport := filepath.Join(distDir, "report.json")

	if !fileExists(indexPath) {
		fmt.Println("  [✗] web/dist/index.html not found — please run 'npm run build' first")
		pressEnter()
		return
	}

	if fileExists(reportFile) {
		if err := copyFile(reportFile, distReport); err != nil {
			fmt.Printf("  [✗] Error copying file: %v\n", err)
			pressEnter()
			return
		}
	} else {
		fmt.Printf("  [!] %s could not be found,current dashboard data is being used\n", reportFile)
	}

	if err := openBrowser(indexPath); err != nil {
		fmt.Printf("  [✗] Error opening browser: %v\n", err)
		pressEnter()
		return
	}

	fmt.Println("  [✓] Dashboard opened ")
	pressEnter()
}

func main() {
	for {
		clearScreen()
		printBanner()
		printMenu()

		reader := bufio.NewReader(os.Stdin)
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			rawFile, runAnalyze := menuScan()
			if runAnalyze {
				reportFile, openReport := menuAnalyze(rawFile)
				if openReport {
					menuReport(reportFile)
				}
			}

		case "2":
			reportFile, openReport := menuAnalyze("")
			if openReport {
				menuReport(reportFile)
			}

		case "3":
			menuReport("")

		case "4":
			fmt.Println("\n  Exiting...\n")
			os.Exit(0)

		default:
			fmt.Println("\n  [!] Invalid selection")
			pressEnter()
		}
	}
}
