// Safe database queries - should PASS validation
package database

import (
	"context"
	"database/sql"
)

// GetUserByID retrieves a user using parameterized queries (safe)
func GetUserByID(ctx context.Context, db *sql.DB, userID string) (*User, error) {
	// ✅ CORRECT: Parameterized query prevents SQL injection
	query := `SELECT id, email, name FROM users WHERE id = $1`

	var user User
	err := db.QueryRowContext(ctx, query, userID).Scan(&user.ID, &user.Email, &user.Name)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// SearchUsers performs a safe search with parameterized queries
func SearchUsers(ctx context.Context, db *sql.DB, searchTerm string) ([]User, error) {
	// ✅ CORRECT: Using placeholders for user input
	query := `
		SELECT id, email, name
		FROM users
		WHERE name ILIKE $1
		ORDER BY created_at DESC
		LIMIT 100
	`

	rows, err := db.QueryContext(ctx, query, "%"+searchTerm+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Email, &user.Name); err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, rows.Err()
}

type User struct {
	ID    string
	Email string
	Name  string
}
