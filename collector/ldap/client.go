package ldap

import (
	"crypto/tls"
	"fmt"

	"collector/config"

	gldap "github.com/go-ldap/ldap/v3"
)

func Connect(cfg *config.Config) (*gldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	var (
		conn *gldap.Conn
		err  error
	)

	if cfg.UseSSL {
		conn, err = gldap.DialTLS("tcp", address, &tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		conn, err = gldap.Dial("tcp", address)
	}
	if err != nil {
		return nil, fmt.Errorf("ldap connection failed: %w", err)
	}

	if err = conn.Bind(cfg.Username, cfg.Password); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ldap bind failed: %w", err)
	}

	return conn, nil
}

func Disconnect(conn *gldap.Conn) {
	if conn != nil {
		conn.Close()
	}
}
