package waf

import (
	"database/sql"
	"log"
	"time"
)

type LogEvent struct {
	RuleID string
	Action string
	Phase  string
	IP     string
	Path   string
}

var logChan chan LogEvent

func InitLogger(db *sql.DB) {
	logChan = make(chan LogEvent, 10000)
	go processLogs(db)
}

func LogRequest(event LogEvent) {
	if logChan != nil {
		select {
		case logChan <- event:
		default:
			// Buffer full, drop log to avoid blocking
			log.Println("Log buffer full, dropping event")
		}
	}
}

func processLogs(db *sql.DB) {
	var batch []LogEvent
	ticker := time.NewTicker(1 * time.Second)

	for {
		select {
		case event := <-logChan:
			batch = append(batch, event)
			if len(batch) >= 100 {
				flushLogs(db, batch)
				batch = nil
			}
		case <-ticker.C:
			if len(batch) > 0 {
				flushLogs(db, batch)
				batch = nil
			}
		}
	}
}

func flushLogs(db *sql.DB, batch []LogEvent) {
	tx, err := db.Begin()
	if err != nil {
		log.Println("Failed to begin tx for logs:", err)
		return
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT INTO request_logs (rule_id, action, phase, ip, path) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		log.Println("Failed to prepare stmt for logs:", err)
		return
	}
	defer stmt.Close()

	for _, e := range batch {
		_, err := stmt.Exec(e.RuleID, e.Action, e.Phase, e.IP, e.Path)
		if err != nil {
			log.Println("Failed to exec log insert:", err)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Println("Failed to commit log batch:", err)
	}
}
