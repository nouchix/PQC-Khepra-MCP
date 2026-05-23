// SQL injection vulnerabilities - should FAIL validation
package database

import (
	"database/sql"
	"fmt"
)

// ❌ FAIL: String concatenation in SQL query (SQL injection risk)
func GetUserByEmailUnsafe(db *sql.DB, email string) (*User, error) {
	// VULNERABLE: User input directly concatenated into query
	query := fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", email)

	var user User
	err := db.QueryRow(query).Scan(&user.ID, &user.Email, &user.Name)
	return &user, err
}

// ❌ FAIL: Another SQL injection vulnerability
func UpdateUserUnsafe(db *sql.DB, userID string, newName string) error {
	// VULNERABLE: Using fmt.Sprintf to build UPDATE query
	query := fmt.Sprintf("UPDATE users SET name = '%s' WHERE id = %s", newName, userID)
	_, err := db.Exec(query)
	return err
}

// ❌ FAIL: INSERT with string concatenation
func InsertLogUnsafe(db *sql.DB, message string) error {
	// VULNERABLE: Direct string concatenation in INSERT
	query := fmt.Sprintf("INSERT INTO logs (message, created_at) VALUES ('%s', NOW())", message)
	_, err := db.Exec(query)
	return err
}

type User struct {
	ID    string
	Email string
	Name  string
}
