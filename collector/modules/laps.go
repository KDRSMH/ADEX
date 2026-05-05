package modules

import (
	"fmt"

	cldap "collector/ldap"

	gldap "github.com/go-ldap/ldap/v3"
)

type LAPSMissingResult struct {
	ComputerName    string
	OperatingSystem string
}

func GetLAPSMissing(conn *gldap.Conn, baseDN string) ([]LAPSMissingResult, error) {
	filter := "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	attributes := []string{
		"cn",
		"operatingSystem",
		"ms-Mcs-AdmPwd",
	}

	entries, err := cldap.PagedSearch(conn, baseDN, filter, attributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search LAPS status: %w", err)
	}

	results := make([]LAPSMissingResult, 0, len(entries))
	for _, entry := range entries {
		admPwd := entry.GetAttributeValue("ms-Mcs-AdmPwd")
		if admPwd != "" {
			continue
		}

		results = append(results, LAPSMissingResult{
			ComputerName:    entry.GetAttributeValue("cn"),
			OperatingSystem: entry.GetAttributeValue("operatingSystem"),
		})
	}

	return results, nil
}
