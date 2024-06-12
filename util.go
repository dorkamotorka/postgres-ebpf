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

// Order is important
const (
	BPF_POSTGRES_METHOD_UNKNOWN = iota
	BPF_POSTGRES_METHOD_STATEMENT_CLOSE_OR_CONN_TERMINATE
	BPF_POSTGRES_METHOD_SIMPLE_QUERY
	BPF_POSTGRES_METHOD_EXTENDED_QUERY
)

// for postgres, user space
const (
	CLOSE_OR_TERMINATE = "CLOSE_OR_TERMINATE"
	SIMPLE_QUERY       = "SIMPLE_QUERY"
	EXTENDED_QUERY     = "EXTENDED_QUERY"
)

type L7Event struct {
	Fd                  uint64
	Pid                 uint32
	Status              uint32
	Duration            uint64
	Protocol            string // L7_PROTOCOL_HTTP
	Tls                 bool   // Whether request was encrypted
	Method              string
	Payload             [1024]uint8
	PayloadSize         uint32 // How much of the payload was copied
	PayloadReadComplete bool   // Whether the payload was copied completely
	Failed              bool   // Request failed
	WriteTimeNs         uint64 // start time of write syscall
	Tid                 uint32
	Seq                 uint32 // tcp seq num
	EventReadTime       int64
}

type bpfL7Event struct {
	Fd                  uint64
	WriteTimeNs         uint64
	Pid                 uint32
	Status              uint32
	Duration            uint64
	Protocol            uint8
	Method              uint8
	Padding             uint16
	Payload             [1024]uint8
	PayloadSize         uint32
	PayloadReadComplete uint8
	Failed              uint8
	IsTls               uint8
	_                   [1]byte
	Seq                 uint32
	Tid                 uint32
	_                   [4]byte
}

// Custom types for the enumeration
type L7ProtocolConversion uint32
type PostgresMethodConversion uint32

// String representation of the enumeration values
func (e L7ProtocolConversion) String() string {
	switch e {
	case BPF_L7_PROTOCOL_POSTGRES:
		return L7_PROTOCOL_POSTGRES
	case BPF_L7_PROTOCOL_UNKNOWN:
		return L7_PROTOCOL_UNKNOWN
	default:
		return "Unknown"
	}
}

// String representation of the enumeration values
func (e PostgresMethodConversion) String() string {
	switch e {
	case BPF_POSTGRES_METHOD_STATEMENT_CLOSE_OR_CONN_TERMINATE:
		return CLOSE_OR_TERMINATE
	case BPF_POSTGRES_METHOD_SIMPLE_QUERY:
		return SIMPLE_QUERY
	case BPF_POSTGRES_METHOD_EXTENDED_QUERY:
		return EXTENDED_QUERY
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

func parseSqlCommand(d *bpfL7Event, pgStatements *map[string]string) (string, error) {
	r := d.Payload[:d.PayloadSize]
	var sqlCommand string
	if PostgresMethodConversion(d.Method).String() == SIMPLE_QUERY {
		// SIMPLE_QUERY -> Q, 4 bytes of length, SQL command
		// Skip Q, (simple query)
		r = r[1:]

		// Skip 4 bytes of length
		r = r[4:]

		// Get sql command
		sqlCommand = string(r)

		// Garbage data can come for Postgres, we need to filter out
		// Search statement inside SQL keywords
		if !containsSQLKeywords(sqlCommand) {
			return "", fmt.Errorf("no sql command found")
		}
	} else if PostgresMethodConversion(d.Method).String() == EXTENDED_QUERY {
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
	} else if PostgresMethodConversion(d.Method).String() == CLOSE_OR_TERMINATE {
		sqlCommand = string(r)
	}

	return sqlCommand, nil
}