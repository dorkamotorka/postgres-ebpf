package main

import (
    "fmt"
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
    createTable := `CREATE TABLE "Students" ("id" serial primary key, "Name" TEXT, "Roll" INTEGER)`
    _, err = db.Exec(createTable)
    if err != nil {
        //fmt.Println(err)
    } else {
        fmt.Println("Students table created successfully")
    }

    // Insert data into the table
    insertStmt := `INSERT INTO "Students"("Name", "Roll") VALUES('John', 1)`
    _, err = db.Exec(insertStmt)
    CheckError(err)

    // Insert data into the table using dynamic SQL
    insertDynStmt := `INSERT INTO "Students"("Name", "Roll") VALUES($1, $2)`
    _, err = db.Exec(insertDynStmt, "Jane", 2)
    CheckError(err)

    // Update data in the table
    updateStmt := `UPDATE "Students" SET "Name"=$1, "Roll"=$2 WHERE "id"=$3`
    _, err = db.Exec(updateStmt, "Mary", 3, 2)
    CheckError(err)

    // Delete data from the table
    deleteStmt := `DELETE FROM "Students" WHERE id=$1`
    _, err = db.Exec(deleteStmt, 1)
    CheckError(err)

    rows, err := db.Query(`SELECT "Name", "Roll" FROM "Students"`)
    CheckError(err)
     
    defer rows.Close()
    for rows.Next() {
        var name string
        var roll int
     
        err = rows.Scan(&name, &roll)
        CheckError(err)
    }
     
    CheckError(err)
    fmt.Println("Client finished successfully.")
}

func CheckError(err error) {
    if err != nil {
        panic(err)
    }
}