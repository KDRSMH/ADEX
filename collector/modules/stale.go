package modules

import (
	cldap "collector/ldap"
	"fmt"
	"strconv"
	"time"

	gldap "github.com/go-ldap/ldap/v3"
)

const (
	fileTimeEpochDiff int64 = 116444736000000000
	fileTimeTick      int64 = 10000000
)

type StaleAccount struct {
	SAMAccountName string
	LastLogon      string
	DaysSinceLogin int
}

func GetStaleAccounts(conn *gldap.Conn, baseDN string) ([]StaleAccount, error) {
	trheshold := time.Now().AddDate(0, 0, -90)
	windowsTime := trheshold.Unix()*fileTimeTick + fileTimeEpochDiff

	filter := fmt.Sprintf(
		"(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogon<=%d))",
		windowsTime,
	)

	attributes := []string{
		"sAMAccountName",
		"lastLogon",
	}

	entries, err := cldap.PagedSearch(conn, baseDN, filter, attributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search for stale accounts: %w", err)
	}

	now := time.Now()
	results := make([]StaleAccount, 0, len(entries))

	for _, entry := range entries {
		sam := entry.GetAttributeValue("sAMAccountName")
		lastLogonRaw := entry.GetAttributeValue("lastLogon")

		if lastLogonRaw == "" || lastLogonRaw == "0" {
			results = append(results, StaleAccount{
				SAMAccountName: sam,
				LastLogon:      "Never logged in",
				DaysSinceLogin: 0,
			})
			continue
		}

		ft, err := strconv.ParseInt(lastLogonRaw, 10, 64)
		if err != nil || ft <= 0 {
			results = append(results, StaleAccount{
				SAMAccountName: sam,
				LastLogon:      "Unknown",
				DaysSinceLogin: 0,
			})
			continue
		}

		unixSec := (ft - fileTimeEpochDiff) / fileTimeTick
		lastLoginTime := time.Unix(unixSec, 0).UTC()
		days := int(now.Sub(lastLoginTime).Hours() / 24)

		results = append(results, StaleAccount{
			SAMAccountName: sam,
			LastLogon:      lastLoginTime.Format(time.RFC3339),
			DaysSinceLogin: days,
		})
	}

	return results, nil
}
