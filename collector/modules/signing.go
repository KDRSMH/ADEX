package modules

import (
	"fmt"

	gldap "github.com/go-ldap/ldap/v3"
)

type SigningResult struct {
	LDAPSigning  string
	LDAPSChannel bool
	SMBSigning   bool
}

func GetSigningStatus(conn *gldap.Conn) (*SigningResult, error) {
	req := gldap.NewSearchRequest(
		"",
		gldap.ScopeBaseObject,
		gldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"supportedLDAPPolicies", "supportedSASLMechanisms"},
		nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query rootDSE: %w", err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("rootDSE not found")
	}

	entry := res.Entries[0]
	policies := entry.GetAttributeValues("supportedLDAPPolicies")

	signing := "unknown"
	for _, p := range policies {
		if p == "LDAP_POLICY_BIND_SIGN" {
			signing = "required"
			break
		}
	}
	if signing == "unknown" {
		signing = "optional"
	}

	result := &SigningResult{
		LDAPSigning:  signing,
		LDAPSChannel: false,
	}

	return result, nil
}
