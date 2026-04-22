package config

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"strings"
)

type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	BaseDN   string
	UseSSL   bool
	Output   string
}

func NewConfig() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.Host, "Host", "", "LDAP server hostname or IP address")
	flag.IntVar(&cfg.Port, "Port", 389, "LDAP server port")
	flag.StringVar(&cfg.Username, "Username", "", "LDAP username")
	flag.StringVar(&cfg.Password, "Password", "", "LDAP password")
	flag.StringVar(&cfg.BaseDN, "BaseDN", "", "LDAP base distinguished name")
	flag.BoolVar(&cfg.UseSSL, "UseSSL", false, "Use SSL connection")
	flag.StringVar(&cfg.Output, "Output", "corvus_raw.json", "Output file for results")

	flag.Parse()
	return cfg
}

func (c *Config) Validate() error {
	if strings.TrimSpace(c.Host) == "" {
		return errors.New("Host is required")
	}
	if strings.TrimSpace(c.Username) == "" {
		return errors.New("Username is required")
	}
	if strings.TrimSpace(c.Password) == "" {
		return errors.New("Password is required")
	}

	if strings.TrimSpace(c.BaseDN) == "" {
		dn, err := deriveBaseDNFromHost(c.Host)
		if err != nil {
			return fmt.Errorf("BaseDN is required and could not be derived from Host: %v", err)
		}
		c.BaseDN = dn
	}

	if strings.TrimSpace(c.Output) == "" {
		c.Output = "corvus_raw.json"
	}

	return nil
}

func deriveBaseDNFromHost(host string) (string, error) {
	h := strings.TrimSpace(strings.ToLower(host))

	if h == "" {
		return "", errors.New("The host was empty, so it could not be derived from the base.")
	}

	if ip := net.ParseIP(h); ip != nil {
		return "", fmt.Errorf("the host is an IP address (%s), BaseDN could not be derived automatically; please provide -basedn", host)
	}

	parts := strings.Split(h, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("the host (%s) is not a valid domain name, BaseDN could not be derived automatically; please provide -basedn", host)
	}

	dnparts := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		dnparts = append(dnparts, "DC="+p)
	}

	if len(dnparts) < 2 {

		return "", fmt.Errorf("The host was not generated from the specified base (%s), please provide the base", host)
	}

	return strings.Join(dnparts, ","), nil
}
