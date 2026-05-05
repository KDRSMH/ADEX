package modules

import (
	"fmt"

	cldap "collector/ldap"

	gldap "github.com/go-ldap/ldap/v3"
)

type DelegationResult struct {
	SAMAccountName string
	Type           string
	TargetSPNs     []string
}

func GetDelegationIssues(conn *gldap.Conn, baseDN string) ([]DelegationResult, error) {
	unconstrainedFilter := "(&(|(objectClass=user)(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	constrainedFilter := "(&(|(objectClass=user)(objectClass=computer))(msDS-AllowedToDelegateTo=*))"

	attrs := []string{
		"sAMAccountName",
		"msDS-AllowedToDelegateTo",
	}
	results := make([]DelegationResult, 0)

	unEntries, err := cldap.PagedSearch(conn, baseDN, unconstrainedFilter, attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to search unconstrained delegations: %w", err)
	}
	for _, entry := range unEntries {
		results = append(results, DelegationResult{
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			Type:           "unconstrained",
			TargetSPNs:     nil,
		})
	}

	conEntries, err := cldap.PagedSearch(conn, baseDN, constrainedFilter, attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to search constrained delegations: %w", err)
	}
	for _, entry := range conEntries {
		results = append(results, DelegationResult{
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			Type:           "constrained",
			TargetSPNs:     entry.GetAttributeValues("msDS-AllowedToDelegateTo"),
		})
	}

	return results, nil
}
