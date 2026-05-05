package modules

import (
	"fmt"
	"math"
	"strconv"

	gldap "github.com/go-ldap/ldap/v3"
)

type PasswordPolicy struct {
	MinLength         int
	MaxAge            int
	ComplexityEnabled bool
	LockoutThreshold  int
	LockoutDuration   int
	HistoryLength     int
	RiskNote          string
}

func GetPasswordPolicy(conn *gldap.Conn, baseDN string) (*PasswordPolicy, error) {
	filter := "(objectClass=domainDNS)"
	attributes := []string{
		"minPwdLength",
		"maxPwdAge",
		"pwdProperties",
		"lockoutThreshold",
		"lockoutDuration",
		"pwdHistoryLength",
	}

	req := gldap.NewSearchRequest(
		baseDN,
		gldap.ScopeBaseObject,
		gldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("failed to search for password policy: %w", err)
	}

	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("Password policy entry not found")
	}

	entry := res.Entries[0]

	minLen := parseInt(entry.GetAttributeValue("minPwdLength"))
	maxAgeDays := filetimeDurationDays(entry.GetAttributeValue("maxPwdAge"))
	pwdProps := parseInt(entry.GetAttributeValue("pwdProperties"))
	lockoutThreshold := parseInt(entry.GetAttributeValue("lockoutThreshold"))
	lockoutDurationMins := filetimeDurationMinutes(entry.GetAttributeValue("lockoutDuration"))
	historyLen := parseInt(entry.GetAttributeValue("pwdHistoryLength"))

	policy := &PasswordPolicy{
		MinLength:         minLen,
		MaxAge:            maxAgeDays,
		ComplexityEnabled: (pwdProps & 1) != 0,
		LockoutThreshold:  lockoutThreshold,
		LockoutDuration:   lockoutDurationMins,
		HistoryLength:     historyLen,
	}

	return policy, nil
}

func parseInt(value string) int {
	if value == "" {
		return 0
	}

	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return int(n)
}

func filetimeDurationDays(value string) int {
	n := parseInt64(value)
	if n == 0 {
		return 0
	}
	abs := int64(math.Abs(float64(n)))
	return int(abs / (24 * 60 * 60 * 10000000))
}

func filetimeDurationMinutes(value string) int {
	n := parseInt64(value)
	if n == 0 {
		return 0
	}
	abs := int64(math.Abs(float64(n)))
	return int(abs / (60 * 10000000))
}
