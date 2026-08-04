package waf

import (
	"database/sql"
	"fmt"
	"sync"

	_ "modernc.org/sqlite"
)

var (
	dbInstance *sql.DB
	dbOnce     sync.Once
)

// InitDB initializes the SQLite database and ensures the schema exists.
func InitDB(dbPath string) (*sql.DB, error) {
	var err error
	dbOnce.Do(func() {
		// Use WAL mode for better concurrency and write performance
		dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)", dbPath)
		dbInstance, err = sql.Open("sqlite", dsn)
		if err != nil {
			return
		}

		// Ensure tables exist
		err = createSchema(dbInstance)
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to initialize sqlite db: %w", err)
	}

	return dbInstance, nil
}

func createSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS rules (
		id TEXT PRIMARY KEY,
		action TEXT NOT NULL,
		phase TEXT NOT NULL,
		expression TEXT NOT NULL,
		rate_limit INTEGER DEFAULT 0,
		rate_window INTEGER DEFAULT 0,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS rate_limits (
		key TEXT PRIMARY KEY,
		count INTEGER NOT NULL,
		reset_time INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS request_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id TEXT,
		action TEXT,
		phase TEXT,
		ip TEXT,
		path TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`
	_, err := db.Exec(schema)
	return err
}

// LoadRulesFromDB loads the current WAF rules from the SQLite database.
func LoadRulesFromDB(db *sql.DB) ([]Rule, error) {
	rows, err := db.Query("SELECT id, action, phase, expression, rate_limit, rate_window FROM rules")
	if err != nil {
		return nil, fmt.Errorf("failed to query rules: %w", err)
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.Action, &r.Phase, &r.Expression, &r.Limit, &r.Window); err != nil {
			return nil, fmt.Errorf("failed to scan rule: %w", err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}
