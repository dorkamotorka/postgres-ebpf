package main

import (
	"fmt"
	"bytes"
	"strings"
)

// Order is important
const (
	BPF_L7_PROTOCOL_UNKNOWN = iota
	BPF_L7_PROTOCOL_POSTGRES
)

const (
	L7_PROTOCOL_POSTGRES = "POSTGRES"
	L7_PROTOCOL_UNKNOWN  = "UNKNOWN"
)

// for postgres, user space nice printing
const (
	SIMPLE_QUERY   = "SIMPLE_QUERY"
	EXTENDED_QUERY = "EXTENDED_QUERY"
)
const (
	POSTGRES_MESSAGE_SIMPLE_QUERY = "SIMPLE_QUERY"
	POSTGRES_MESSAGE_PARSE        = "EXTENDED_QUERY"
	POSTGRES_MESSAGE_BIND         = "EXTENDED_QUERY"
)

// Custom types for the enumeration
type L7ProtocolConversion uint32

// String representation of the enumeration values
func (e L7ProtocolConversion) String() string {
	switch e {
	case BPF_L7_PROTOCOL_POSTGRES:
		return L7_PROTOCOL_POSTGRES
	default:
		return L7_PROTOCOL_UNKNOWN
	}
}

// String representation of the enumeration values
func PostgresRequestConversion(requestType string) string {
	switch requestType {
	case "Q":
		return POSTGRES_MESSAGE_SIMPLE_QUERY
	case "P":
		return POSTGRES_MESSAGE_PARSE
	case "B":
		return POSTGRES_MESSAGE_BIND
	default:
		return "Unknown"
	}
}

func getKey(pid uint32, fd uint64, stmtName string) string {
	return fmt.Sprintf("%d-%d-%s", pid, fd, stmtName)
}

// Check if a string contains SQL keywords
func containsSQLKeywords(input string) bool {
	return re.MatchString(strings.ToUpper(input))
}

func parseSqlCommand(d *postgresL7Event, pgStatements *map[string]string) (string, error) {
	r := d.Payload[:d.PayloadSize]
	var sqlCommand string
	requestType := PostgresRequestConversion(string(d.RequestType))
	if (requestType == SIMPLE_QUERY) {
		// SIMPLE_QUERY -> Q, 4 bytes of length, SQL command
		// Skip Q, (simple query)
		r = r[1:]

		// Skip 4 bytes of length field
		r = r[4:]

		// Get sql command
		sqlCommand = string(r)

		// Garbage data can come for Postgres that we need to filter out
		// Search statement inside SQL keywords
		if !containsSQLKeywords(sqlCommand) {
			return "", nil
		}
	} else if (requestType == EXTENDED_QUERY) {
		id := r[0]
		switch id {
		case 'P':
			// EXTENDED_QUERY -> P, 4 bytes len, prepared statement name(str) (null terminated), query(str) (null terminated), parameters
			var stmtName string
			var query string
			vars := bytes.Split(r[5:], []byte{0})
			if len(vars) >= 3 {
				stmtName = string(vars[0])
				query = string(vars[1])
			} else if len(vars) == 2 { // query too long for our buffer
				stmtName = string(vars[0])
				query = string(vars[1]) + "..."
			} else {
				return "", fmt.Errorf("could not parse 'parse' frame for postgres")
			}
			
			(*pgStatements)[getKey(d.Pid, d.Fd, stmtName)] = query
			return fmt.Sprintf("PREPARE %s AS %s", stmtName, query), nil
		case 'B':
			// EXTENDED_QUERY -> B, 4 bytes len, portal str (null terminated), prepared statement name str (null terminated)
			var stmtName string
			vars := bytes.Split(r[5:], []byte{0})
			if len(vars) >= 2 {
				stmtName = string(vars[1])
			} else {
				return "", fmt.Errorf("could not parse bind frame for postgres")
			}

			query, ok := (*pgStatements)[getKey(d.Pid, d.Fd, stmtName)]
			if !ok || query == "" { // we don't have the query for the prepared statement
				// Execute (name of prepared statement) [(parameter)]
				return fmt.Sprintf("EXECUTE %s *values*", stmtName), nil
			}
			return query, nil
		default:
			return "", fmt.Errorf("could not parse extended query for postgres")
		}
	}

	return sqlCommand, nil
}
