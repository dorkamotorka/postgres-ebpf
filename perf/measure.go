package main

import (
    "fmt"
    "time"
    "database/sql"
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
    CheckError(err)
    defer db.Close()

		// Create table
		createTable := `CREATE TABLE IF NOT EXISTS "Students" ("id" serial primary key, "Name" TEXT, "Roll" INTEGER)`
		_, err = db.Exec(createTable)
		CheckError(err)

    const repeat = 1000
    var totalInsertTime, totalUpdateTime, totalDeleteTime, totalQueryTime time.Duration

    for i := 0; i < repeat; i++ {
        start := time.Now()
        // Insert data into the table
        insertStmt := `INSERT INTO "Students"("Name", "Roll") VALUES('John', 1)`
        _, err = db.Exec(insertStmt)
        elapsed := time.Since(start)
        totalInsertTime += elapsed
        CheckError(err)

        start = time.Now()
        // Insert data into the table using dynamic SQL
        insertDynStmt := `INSERT INTO "Students"("Name", "Roll") VALUES($1, $2)`
        _, err = db.Exec(insertDynStmt, "Jane", 2)
        elapsed = time.Since(start)
        totalInsertTime += elapsed
        CheckError(err)

        start = time.Now()
        // Update data in the table
        updateStmt := `UPDATE "Students" SET "Name"=$1, "Roll"=$2 WHERE "id"=$3`
        _, err = db.Exec(updateStmt, "Mary", 3, 2)
        elapsed = time.Since(start)
        totalUpdateTime += elapsed
        CheckError(err)

        start = time.Now()
        // Delete data from the table
        deleteStmt := `DELETE FROM "Students" WHERE id=$1`
        _, err = db.Exec(deleteStmt, 1)
        elapsed = time.Since(start)
        totalDeleteTime += elapsed
        CheckError(err)

        start = time.Now()
        rows, err := db.Query(`SELECT "Name", "Roll" FROM "Students"`)
        elapsed = time.Since(start)
        totalQueryTime += elapsed
        CheckError(err)

        defer rows.Close()
        for rows.Next() {
            var name string
            var roll int
            err = rows.Scan(&name, &roll)
            CheckError(err)
        }
        CheckError(rows.Err())

        // Clean up table for next iteration
        _, err = db.Exec(`TRUNCATE "Students" RESTART IDENTITY`)
        CheckError(err)
    }

    fmt.Printf("Average INSERT latency: %v\n", totalInsertTime/(2*time.Duration(repeat)))
    fmt.Printf("Average UPDATE latency: %v\n", totalUpdateTime/time.Duration(repeat))
    fmt.Printf("Average DELETE latency: %v\n", totalDeleteTime/time.Duration(repeat))
    fmt.Printf("Average QUERY latency: %v\n", totalQueryTime/time.Duration(repeat))
    fmt.Println("Perfomance test finished successfully.")
}

func CheckError(err error) {
    if err != nil {
        panic(err)
    }
}
