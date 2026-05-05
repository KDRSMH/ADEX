package main

import (
	"log"
	"time"

	"collector/config"
	"collector/ldap"
	"collector/modules"
	"collector/output"
)

func main() {
	cfg := config.NewConfig()
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}

	conn, err := ldap.Connect(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer ldap.Disconnect(conn)

	users, err := modules.GetUsers(conn, cfg.BaseDN)
	if err != nil {
		log.Fatal(err)
	}

	groups, err := modules.GetGroups(conn, cfg.BaseDN)
	if err != nil {
		log.Fatal(err)
	}

	kerberoastable, err := modules.GetKerberoastable(conn, cfg.BaseDN)
	if err != nil {
		log.Fatal(err)
	}

	asrepRoastable, err := modules.GetASREPRoastable(conn, cfg.BaseDN)
	if err != nil {
		log.Fatal(err)
	}

	staleAccounts, err := modules.GetStaleAccounts(conn, cfg.BaseDN)
	if err != nil {
		log.Fatal(err)
	}

	passwordPolicy, err := modules.GetPasswordPolicy(conn, cfg.BaseDN)
	if err != nil {
		log.Fatal(err)
	}

	delegationIssues, err := modules.GetDelegationIssues(conn, cfg.BaseDN)
	if err != nil {
		log.Fatal(err)
	}

	adminSDHolder, err := modules.GetAdminSDHolderAnomalies(conn, cfg.BaseDN)
	if err != nil {
		log.Fatal(err)
	}

	lapsMissing, err := modules.GetLAPSMissing(conn, cfg.BaseDN)
	if err != nil {
		log.Fatal(err)
	}

	signingStatus, err := modules.GetSigningStatus(conn)
	if err != nil {
		log.Fatal(err)
	}

	gpos, err := modules.GetGPOs(conn, cfg.BaseDN)
	if err != nil {
		log.Fatal(err)
	}

	result := output.ScanResult{
		ScanTime:               time.Now(),
		Domain:                 cfg.Host,
		CollectorVer:           "v0.1.0",
		Users:                  users,
		Groups:                 groups,
		Kerberoastable:         kerberoastable,
		ASREPRoastable:         asrepRoastable,
		StaleAccounts:          staleAccounts,
		PasswordPolicy:         passwordPolicy,
		DelegationIssues:       delegationIssues,
		AdminSDHolderAnomalies: adminSDHolder,
		LAPSMissing:            lapsMissing,
		SigningStatus:          signingStatus,
		GPOs:                   gpos,
	}

	if err := output.WriteJSON(result, cfg.Output); err != nil {
		log.Fatal(err)
	}

	log.Printf("scan completed: users=%d groups=%d output=%s", len(users), len(groups), cfg.Output)
}
