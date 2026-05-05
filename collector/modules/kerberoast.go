package modules

import (
	"fmt"

	cldap "collector/ldap"

	gldap "github.com/go-ldap/ldap/v3"
)

type KerberoastResult struct {
	SAMAccountName  string
	SPN             []string
	PasswordLastSet string
	RiskNote        string
}

func GetKerberoastable(conn *gldap.Conn, baseDN string) ([]KerberoastResult, error) {
	filter := "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))"
	attributes := []string{
		"sAMAccountName",
		"servicePrincipalName",
		"pwdLastSet",
	}

	entries, err := cldap.PagedSearch(conn, baseDN, filter, attributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search for kerberoastable accounts: %w", err)
	}

	results := make([]KerberoastResult, 0, len(entries))
	for _, entry := range entries {
		result := KerberoastResult{
			SAMAccountName:  entry.GetAttributeValue("sAMAccountName"),
			SPN:             entry.GetAttributeValues("servicePrincipalName"),
			PasswordLastSet: entry.GetAttributeValue("pwdLastSet"),
			RiskNote:        "SPN is set; account may be vulnerable to Kerberoasting (offline cracking of TGS-REP).",
		}
		results = append(results, result)
	}

	return results, nil
}
