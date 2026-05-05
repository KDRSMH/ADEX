package modules

import (
	"fmt"
	"strings"

	cldap "collector/ldap"

	gldap "github.com/go-ldap/ldap/v3"
)

type AdminSDHolderResult struct {
	SAMAccountName string
	AdminCount     int
	MemberOfAdmin  bool
}

var adminGroups = []string{
	"Domain Admins",
	"Enterprise Admins",
	"Schema Admins",
	"Administrators",
	"Account Operators",
	"Backup Operators",
	"Print Operators",
	"Server Operators",
}

func GetAdminSDHolderAnomalies(conn *gldap.Conn, baseDN string) ([]AdminSDHolderResult, error) {
	filter := "(&(objectClass=user)(adminCount=1))"
	attributes := []string{
		"sAMAccountName",
		"adminCount",
		"memberOf",
	}

	entries, err := cldap.PagedSearch(conn, baseDN, filter, attributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search  AdminSDHolder anomalies: %w", err)
	}
	results := make([]AdminSDHolderResult, 0, len(entries))
	for _, entry := range entries {
		memberOf := entry.GetAttributeValues("memberOf")
		isAdmin := isMemberOfAdminGroup(memberOf)

		if isAdmin {
			continue
		}

		results = append(results, AdminSDHolderResult{
			SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
			AdminCount:     1,
			MemberOfAdmin:  false,
		})
	}

	return results, nil

}

func isMemberOfAdminGroup(memberOf []string) bool {
	for _, dn := range memberOf {
		for _, group := range adminGroups {
			if strings.Contains(dn, "CN="+group+",") {
				return true
			}
		}
	}
	return false
}
