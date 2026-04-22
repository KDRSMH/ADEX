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

	result := output.ScanResult{
		ScanTime:     time.Now(),
		Domain:       cfg.Host,
		CollectorVer: "v0.1.0",
		Users:        users,
		Groups:       groups,
	}

	if err := output.WriteJSON(result, cfg.Output); err != nil {
		log.Fatal(err)
	}

	log.Printf("scan completed: users=%d groups=%d output=%s", len(users), len(groups), cfg.Output)
}
