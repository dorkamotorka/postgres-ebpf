package main

import (
	"os"
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
)

const (
    host     = "localhost"
    port     = 5432
    user     = "postgres"
    password = "mysecretpassword"
    dbname   = "mydb"
)

func main() {
    // Connection string
    psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
        host, port, user, password, dbname)

    // Connect to the PostgreSQL database
    db, err := sql.Open("postgres", psqlInfo)
    if err != nil {
        panic(err)
    }
    defer db.Close()

    fmt.Println("Successfully connected to the database!")

    // Insert data into the table
	// This uses Extended Query Syntax (combination of Parse and Bind packets)
    insertSQL := `
    INSERT INTO test_table (name)
    VALUES ($1)
    RETURNING id`
    var id int
    err = db.QueryRow(insertSQL, "Test Name from Go").Scan(&id)
    if err != nil {
        panic(err)
    }
    fmt.Println("New record ID is:", id)

    // This uses Extended Query Syntax as well (combination of Parse and Bind packets)
    var name string
    querySQL := `SELECT name FROM test_table WHERE id = $1`
    err = db.QueryRow(querySQL, id).Scan(&name)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Queried name from the database: %s\n", name)
		fmt.Printf("Client PID is %d\n", os.Getpid())
}