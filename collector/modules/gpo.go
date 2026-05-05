package modules

import (
	"fmt"
	"strings"

	cldap "collector/ldap"

	gldap "github.com/go-ldap/ldap/v3"
)

type GPOResult struct {
	Name            string
	GUID            string
	LinkedTo        []string
	UserEnabled     bool
	ComputerEnabled bool
}

func GetGPOs(conn *gldap.Conn, baseDN string) ([]GPOResult, error) {
	policiesBase := "CN=Policies,CN=System," + baseDN
	filter := "(objectClass=groupPolicyContainer)"
	attributes := []string{
		"displayName",
		"cn",
		"gPCUserExtensionNames",
		"gPCMachineExtensionNames",
		"flags",
	}

	gpoEntries, err := cldap.PagedSearch(conn, policiesBase, filter, attributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search GPOs: %w", err)
	}

	ouFilter := "(gPLink=*)"
	ouAttrs := []string{"distinguishedName", "gPLink"}
	ouEntries, err := cldap.PagedSearch(conn, baseDN, ouFilter, ouAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to search OU links: %w", err)
	}

	linkMap := buildGPOLinks(ouEntries)

	results := make([]GPOResult, 0, len(gpoEntries))
	for _, entry := range gpoEntries {
		name := entry.GetAttributeValue("displayName")
		guid := entry.GetAttributeValue("cn")
		flags := entry.GetAttributeValue("flags")

		userEnabled, computerEnabled := parseGPOFlags(flags)

		results = append(results, GPOResult{
			Name:            name,
			GUID:            guid,
			LinkedTo:        linkMap[strings.ToLower(guid)],
			UserEnabled:     userEnabled,
			ComputerEnabled: computerEnabled,
		})
	}

	return results, nil
}

func parseGPOFlags(flags string) (bool, bool) {
	switch strings.TrimSpace(flags) {
	case "1":
		return false, true
	case "2":
		return true, false
	case "3":
		return false, false
	default:
		return true, true
	}
}

func buildGPOLinks(ouEntries []*gldap.Entry) map[string][]string {
	linkMap := make(map[string][]string)

	for _, entry := range ouEntries {
		dn := entry.GetAttributeValue("distinguishedName")
		gpLink := entry.GetAttributeValue("gPLink")

		for _, guid := range extractGUIDsFromGPLink(gpLink) {
			key := strings.ToLower(guid)
			linkMap[key] = append(linkMap[key], dn)
		}
	}

	return linkMap
}

func extractGUIDsFromGPLink(gpLink string) []string {
	parts := strings.Split(gpLink, "[")
	guids := make([]string, 0)

	for _, p := range parts {
		start := strings.Index(p, "cn={")
		end := strings.Index(p, "},cn=policies")
		if start == -1 || end == -1 || end <= start {
			continue
		}
		guid := p[start+3 : end+1]
		guids = append(guids, guid)
	}

	return guids
}
