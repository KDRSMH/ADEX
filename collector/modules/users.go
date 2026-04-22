package modules

import (
	"fmt"
	"strconv"
	"time"

	cldap "collector/ldap"

	gldap "github.com/go-ldap/ldap/v3"
)

const (
	uacAccountDisableFlag int64 = 2
	windowsEpochDiff      int64 = 116444736000000000
	ticksPerSecond        int64 = 10000000
)

type User struct {
	SAMAccountName  string
	DisplayName     string
	Email           string
	Enabled         bool
	LastLogon       time.Time
	PasswordLastSet time.Time
	MemberOf        []string
}

func GetUsers(conn *gldap.Conn, baseDN string) ([]User, error) {
	filter := "(&(objectClass=user)(!(objectClass=computer)))"
	attributes := []string{
		"sAMAccountName",
		"displayName",
		"mail",
		"userAccountControl",
		"lastLogon",
		"pwdLastSet",
		"memberOf",
	}

	entries, err := cldap.PagedSearch(conn, baseDN, filter, attributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search for users: %w", err)
	}

	users := make([]User, 0, len(entries))
	for _, entry := range entries {
		uac := parseInt64(entry.GetAttributeValue("userAccountControl"))
		enabled := (uac & uacAccountDisableFlag) == 0

		user := User{
			SAMAccountName:  entry.GetAttributeValue("sAMAccountName"),
			DisplayName:     entry.GetAttributeValue("displayName"),
			Email:           entry.GetAttributeValue("mail"),
			Enabled:         enabled,
			LastLogon:       fileTimeToTime(entry.GetAttributeValue("lastLogon")),
			PasswordLastSet: fileTimeToTime(entry.GetAttributeValue("pwdLastSet")),
			MemberOf:        entry.GetAttributeValues("memberOf"),
		}

		users = append(users, user)
	}

	return users, nil
}

func parseInt64(value string) int64 {
	if value == "" {
		return 0
	}

	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}

	return n
}

func fileTimeToTime(value string) time.Time {
	ft := parseInt64(value)
	if ft <= 0 {
		return time.Time{}
	}

	unix := (ft - windowsEpochDiff) / ticksPerSecond
	if unix <= 0 {
		return time.Time{}
	}

	return time.Unix(unix, 0).UTC()
}
