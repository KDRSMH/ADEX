package ldap

import (
	"fmt"

	gldap "github.com/go-ldap/ldap/v3"
)

func PagedSearch(conn *gldap.Conn, baseDN, filter string, attributes []string) ([]*gldap.Entry, error) {
	const pageSize uint32 = 1000

	allEntries := make([]*gldap.Entry, 0)
	pagingControl := gldap.NewControlPaging(pageSize)

	for {
		searchRequest := gldap.NewSearchRequest(
			baseDN,
			gldap.ScopeWholeSubtree,
			gldap.NeverDerefAliases,
			0,
			0,
			false,
			filter,
			attributes,
			[]gldap.Control{pagingControl},
		)

		searchResult, err := conn.Search(searchRequest)
		if err != nil {
			return nil, fmt.Errorf("ldap search failed: %w", err)
		}

		allEntries = append(allEntries, searchResult.Entries...)

		control := gldap.FindControl(searchResult.Controls, gldap.ControlTypePaging)
		if control == nil {
			break
		}

		pagingResponse, ok := control.(*gldap.ControlPaging)
		if !ok {
			return nil, fmt.Errorf("unexpected paging control type: %T", control)
		}

		if len(pagingResponse.Cookie) == 0 {
			break
		}
		pagingControl.SetCookie(pagingResponse.Cookie)
	}

	return allEntries, nil
}
