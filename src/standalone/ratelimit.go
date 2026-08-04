package waf

import (
	"database/sql"
	"log"
	"sync"
	"time"
)

type RateLimiter struct {
	mu     sync.RWMutex
	counts map[string]int
	db     *sql.DB
}

var globalLimiter *RateLimiter

func InitRateLimiter(db *sql.DB) {
	globalLimiter = &RateLimiter{
		counts: make(map[string]int),
		db:     db,
	}
	go globalLimiter.syncToDB()
}

// Allow checks if the given key has exceeded the limit.
// A true value means the request is allowed. A false means rate limited.
func AllowRequest(key string, limit int, window int) bool {
	if globalLimiter == nil {
		return true
	}
	return globalLimiter.Allow(key, limit, window)
}

func (rl *RateLimiter) Allow(key string, limit int, window int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	current := rl.counts[key]
	if current >= limit {
		return false
	}
	rl.counts[key] = current + 1
	return true
}

func (rl *RateLimiter) syncToDB() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		rl.mu.Lock()
		snap := rl.counts
		rl.counts = make(map[string]int)
		rl.mu.Unlock()

		if len(snap) == 0 {
			continue
		}

		tx, err := rl.db.Begin()
		if err != nil {
			log.Println("RateLimiter: failed to start tx:", err)
			continue
		}

		stmt, err := tx.Prepare("INSERT INTO rate_limits (key, count, reset_time) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET count = count + ?")
		if err != nil {
			log.Println("RateLimiter: failed to prepare stmt:", err)
			tx.Rollback()
			continue
		}

		resetTime := time.Now().Unix() + 10 // using 10 sec window for simplicity
		for k, count := range snap {
			_, err = stmt.Exec(k, count, resetTime, count)
			if err != nil {
				log.Println("RateLimiter: exec error:", err)
			}
		}
		stmt.Close()
		
		_, err = tx.Exec("DELETE FROM rate_limits WHERE reset_time < ?", time.Now().Unix())
		if err != nil {
			log.Println("RateLimiter: cleanup error:", err)
		}

		if err := tx.Commit(); err != nil {
			log.Println("RateLimiter: commit error:", err)
		}
	}
}
