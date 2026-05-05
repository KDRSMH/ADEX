package modules

import (
	"fmt"

	cldap "collector/ldap"

	gldap "github.com/go-ldap/ldap/v3"
)

type ASREPResult struct {
	SAMAccountName    string
	DistinguishedName string
}

func GetASREPRoastable(conn *gldap.Conn, baseDN string) ([]ASREPResult, error) {
	filter := "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
	attributes := []string{
		"sAMAccountName",
		"distinguishedName",
	}

	entries, err := cldap.PagedSearch(conn, baseDN, filter, attributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search for ASREP roastable accounts: %w", err)
	}

	results := make([]ASREPResult, 0, len(entries))
	for _, entry := range entries {
		result := ASREPResult{
			SAMAccountName:    entry.GetAttributeValue("sAMAccountName"),
			DistinguishedName: entry.GetAttributeValue("distinguishedName"),
		}
		results = append(results, result)
	}

	return results, nil
}
