package scoring

import (
	"collector/output"
	"sort"
)

type Remediation struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Steps       []string `json:"steps"`
	Powershell  string   `json:"powershell"`
}

type Finding struct {
	Code        string      `json:"id"`
	Title       string      `json:"title"`
	AffectedObj string      `json:"affectedObj"`
	Likelihood  int         `json:"likelihood"`
	Severity    int         `json:"severity"`
	Score       int         `json:"risk_score"`
	Color       string      `json:"color"`
	Remediation Remediation `json:"remediation"`
}

type scoreEntry struct {
	Likelihood int
	Severity   int
}

var SCORE_MAP = map[string]scoreEntry{
	"KERB-001":  {Likelihood: 4, Severity: 4},
	"ASRP-001":  {Likelihood: 4, Severity: 4},
	"DELG-001":  {Likelihood: 3, Severity: 5},
	"DACL-001":  {Likelihood: 4, Severity: 5},
	"LAPS-001":  {Likelihood: 3, Severity: 3},
	"SIGN-001":  {Likelihood: 3, Severity: 4},
	"SIGN-002":  {Likelihood: 3, Severity: 4},
	"PWD-001":   {Likelihood: 2, Severity: 2},
	"PWD-002":   {Likelihood: 3, Severity: 4},
	"STALE-001": {Likelihood: 2, Severity: 2},
	"ADMN-001":  {Likelihood: 3, Severity: 4},
	"GPO-001":   {Likelihood: 3, Severity: 3},
}

var remediationMap = map[string]Remediation{
	"KERB-001": {
		Title:       "Kerberoastable Account",
		Description: "The account has a Service Principal Name set and its TGS ticket can be requested by any domain user for offline cracking.",
		Steps: []string{
			"Verify whether the service account actually requires an SPN.",
			"If not, remove it: Set-ADUser -Clear ServicePrincipalName.",
			"If required, set a random password of at least 25 characters.",
			"Consider migrating to a Managed Service Account (MSA) or gMSA.",
		},
		Powershell: "Set-ADAccountPassword -Identity '<account>' -NewPassword (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force)",
	},
	"ASRP-001": {
		Title:       "AS-REP Roastable Account",
		Description: "Kerberos pre-authentication is disabled, allowing an attacker to request an AS-REP and crack it offline.",
		Steps: []string{
			"In ADUC, uncheck 'Do not require Kerberos preauthentication'.",
			"Investigate why this setting was disabled; restrict access if a legacy app requires it.",
		},
		Powershell: "Set-ADAccountControl -Identity '<account>' -DoesNotRequirePreAuth $false",
	},
	"DELG-001": {
		Title:       "Dangerous Delegation Configuration",
		Description: "Unconstrained or constrained Kerberos delegation is configured, allowing credential forwarding attacks.",
		Steps: []string{
			"Identify unconstrained delegation: Get-ADComputer/Get-ADUser -Filter {TrustedForDelegation -eq $true}",
			"Replace unconstrained delegation with constrained delegation where possible.",
			"Add sensitive accounts to the Protected Users group to block delegation entirely.",
		},
		Powershell: "Get-ADUser -Filter {TrustedForDelegation -eq $true} | Select SamAccountName",
	},
	"DACL-001": {
		Title:       "Overly Permissive DACL",
		Description: "GenericAll, WriteDACL, or WriteOwner permissions grant an attacker the ability to take over objects.",
		Steps: []string{
			"Use BloodHound or ADACLScanner to identify GenericAll/WriteDACL/WriteOwner permissions.",
			"Remove unnecessary permissions; apply the principle of least privilege.",
			"Review the ACL on the AdminSDHolder object.",
		},
		Powershell: "",
	},
	"LAPS-001": {
		Title:       "LAPS Not Deployed",
		Description: "Local Administrator Password Solution is not installed; local admin passwords may be shared or stale.",
		Steps: []string{
			"Enable Microsoft LAPS or Windows LAPS (Windows Server 2019+) via GPO.",
			"Install ms-Mcs-AdmPwd / msLAPS-Password schema extensions.",
			"Link the GPO to the affected OUs and run gpupdate /force.",
		},
		Powershell: "Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd' | Where-Object { $_.'ms-Mcs-AdmPwd' -eq $null }",
	},
	"SIGN-001": {
		Title:       "SMB Signing Not Required",
		Description: "SMB signing is not enforced, exposing the network to relay and man-in-the-middle attacks.",
		Steps: []string{
			"GPO: Computer Configuration > Security Settings > Local Policies > Security Options > 'Microsoft network server: Digitally sign communications (always)' = Enabled.",
			"Apply to both domain controllers and member servers.",
			"Audit existing SMB connections before enforcing to avoid disruption.",
		},
		Powershell: "Get-SmbServerConfiguration | Select RequireSecuritySignature",
	},
	"SIGN-002": {
		Title:       "LDAP Signing Not Required",
		Description: "LDAP signing is not enforced on the domain controller, enabling LDAP relay attacks.",
		Steps: []string{
			"Verify KB4520412 and later updates are applied to all DCs.",
			"GPO: 'Domain controller: LDAP server channel binding token requirements' = Always.",
			"Monitor Event ID 3039/3040 for channel binding failures.",
		},
		Powershell: "",
	},
	"PWD-001": {
		Title:       "Weak Password Policy",
		Description: "The domain password policy has weak settings that allow short, simple, or reused passwords.",
		Steps: []string{
			"Set minimum password length to at least 12 characters.",
			"Enable password complexity requirements.",
			"Set password history length to at least 10.",
		},
		Powershell: "Get-ADDefaultDomainPasswordPolicy",
	},
	"PWD-002": {
		Title:       "Excessive Password Maximum Age",
		Description: "Passwords are allowed to remain unchanged for too long, increasing the window of exploitation if credentials are compromised.",
		Steps: []string{
			"Set maximum password age to 90 days or less.",
			"Apply Fine-Grained Password Policy with shorter cycles for privileged accounts.",
		},
		Powershell: "Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge (New-TimeSpan -Days 90)",
	},
	"STALE-001": {
		Title:       "Stale Account Detected",
		Description: "The account has not logged in for over 90 days and represents an unnecessary attack surface.",
		Steps: []string{
			"List accounts: Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00",
			"Disable accounts with business unit approval: Disable-ADAccount.",
			"After a retention period, permanently remove with Remove-ADUser.",
		},
		Powershell: "Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly | Select SamAccountName,LastLogonDate",
	},
	"ADMN-001": {
		Title:       "AdminSDHolder Anomaly",
		Description: "Account has adminCount=1 but is not a member of any privileged group, indicating a residual or misconfigured access right.",
		Steps: []string{
			"Identify accounts with adminCount=1 that are not members of any privileged group.",
			"Manually reset adminCount to 0 on those accounts.",
			"Verify the DACL is corrected after the SDProp task runs.",
		},
		Powershell: "Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount,MemberOf | Select SamAccountName,MemberOf",
	},
	"GPO-001": {
		Title:       "Misconfigured GPO",
		Description: "A Group Policy Object is fully disabled (both user and computer settings), adding clutter and potential confusion to policy management.",
		Steps: []string{
			"List unlinked and disabled GPOs in Group Policy Management Console.",
			"Delete or archive unnecessary GPOs.",
			"Confirm active GPOs are linked to the correct OUs.",
		},
		Powershell: "Get-GPO -All | Where-Object { $_.GpoStatus -eq 'AllSettingsDisabled' }",
	},
}

var titleMap = map[string]string{
	"KERB-001":  "Kerberoastable Account Detected",
	"ASRP-001":  "AS-REP Roastable Account Detected",
	"DELG-001":  "Dangerous Delegation Configuration",
	"DACL-001":  "Overly Permissive DACL Entry",
	"LAPS-001":  "LAPS Missing on Computer",
	"SIGN-001":  "SMB Signing Not Required",
	"SIGN-002":  "LDAP Signing Not Required",
	"PWD-001":   "Weak Password Policy",
	"PWD-002":   "Excessive Password Maximum Age",
	"STALE-001": "Stale Account Detected",
	"ADMN-001":  "AdminSDHolder Anomaly",
	"GPO-001":   "Misconfigured GPO",
}

func scoreToColor(score int) string {
	switch {
	case score >= 16:
		return "red"
	case score >= 11:
		return "orange"
	case score >= 6:
		return "yellow"
	default:
		return "green"
	}
}

func ScoreFinding(code string) Finding {
	entry, ok := SCORE_MAP[code]
	if !ok {
		entry = scoreEntry{Likelihood: 1, Severity: 1}
	}

	score := entry.Likelihood * entry.Severity

	return Finding{
		Code:        code,
		Title:       titleMap[code],
		Likelihood:  entry.Likelihood,
		Severity:    entry.Severity,
		Score:       score,
		Color:       scoreToColor(score),
		Remediation: remediationMap[code],
	}
}

func ScoreAll(raw output.ScanResult) []Finding {
	var findings []Finding

	for _, acc := range raw.Kerberoastable {
		f := ScoreFinding("KERB-001")
		f.AffectedObj = acc.SAMAccountName
		findings = append(findings, f)
	}

	for _, acc := range raw.ASREPRoastable {
		f := ScoreFinding("ASRP-001")
		f.AffectedObj = acc.SAMAccountName
		findings = append(findings, f)
	}

	for _, d := range raw.DelegationIssues {
		f := ScoreFinding("DELG-001")
		f.AffectedObj = d.SAMAccountName
		findings = append(findings, f)
	}

	for _, comp := range raw.LAPSMissing {
		f := ScoreFinding("LAPS-001")
		f.AffectedObj = comp.ComputerName
		findings = append(findings, f)
	}

	if raw.SigningStatus != nil {
		// SMBSigning şu an collector tarafından doldurulamıyor (LDAP yoluyla tespit edilemiyor).
		// Alan varsayılan olarak false döner; ağ/registry tarayıcısı eklenince bu kontrol otomatik çalışacak.
		if !raw.SigningStatus.SMBSigning {
			f := ScoreFinding("SIGN-001")
			f.AffectedObj = raw.Domain
			findings = append(findings, f)
		}
		if raw.SigningStatus.LDAPSigning != "required" {
			f := ScoreFinding("SIGN-002")
			f.AffectedObj = raw.Domain
			findings = append(findings, f)
		}
	}

	if raw.PasswordPolicy != nil {
		pol := raw.PasswordPolicy
		if pol.MinLength < 12 || !pol.ComplexityEnabled || pol.HistoryLength < 10 {
			f := ScoreFinding("PWD-001")
			f.AffectedObj = raw.Domain
			findings = append(findings, f)
		}
		if pol.MaxAge == 0 || pol.MaxAge > 90 {
			f := ScoreFinding("PWD-002")
			f.AffectedObj = raw.Domain
			findings = append(findings, f)
		}
	}

	for _, acc := range raw.StaleAccounts {
		f := ScoreFinding("STALE-001")
		f.AffectedObj = acc.SAMAccountName
		findings = append(findings, f)
	}

	for _, a := range raw.AdminSDHolderAnomalies {
		f := ScoreFinding("ADMN-001")
		f.AffectedObj = a.SAMAccountName
		findings = append(findings, f)
	}

	for _, gpo := range raw.GPOs {
		if !gpo.UserEnabled && !gpo.ComputerEnabled {
			f := ScoreFinding("GPO-001")
			f.AffectedObj = gpo.Name
			findings = append(findings, f)
		}
	}

	// TODO: DACL-001 — requires DCSync/DACL field in ScanResult

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Score > findings[j].Score
	})

	return findings
}
