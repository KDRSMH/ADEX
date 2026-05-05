package modules

import (
	cldap "collector/ldap"
	"fmt"

	gldap "github.com/go-ldap/ldap/v3"
)

type Group struct {
	Name       string
	DN         string
	Member     []string
	IsCritical bool
}

var criticalGroups = map[string]struct{}{
	"Domain Admins":     {},
	"Enterprise Admins": {},
	"Administrators":    {},
	"Schema Admins":     {},
	"Account Operators": {},
	"Backup Operators":  {},
}

func GetGroups(conn *gldap.Conn, baseDN string) ([]Group, error) {
	filter := "(objectClass=group)"
	attributes := []string{
		"cn",
		"distinguishedName",
		"member",
	}

	entries, err := cldap.PagedSearch(conn, baseDN, filter, attributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search for groups: %w", err)
	}

	groups := make([]Group, 0, len(entries))
	for _, entry := range entries {
		name := entry.GetAttributeValue("cn")

		_, isCritical := criticalGroups[name]

		group := Group{
			Name:       name,
			DN:         entry.GetAttributeValue("distinguishedName"),
			Member:     entry.GetAttributeValues("member"),
			IsCritical: isCritical,
		}
		groups = append(groups, group)
	}

	return groups, nil
}
