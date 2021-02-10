package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/benbjohnson/wtf"
	//	_ "github.com/mattn/go-sqlite3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Database metrics.
var (
	userCountGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wtf_db_users",
		Help: "The total number of users",
	})

	dialCountGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wtf_db_dials",
		Help: "The total number of dials",
	})

	dialMembershipCountGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "wtf_db_dial_memberships",
		Help: "The total number of dial memberships",
	})
)

const TimeLayout = "2006-01-02 15:04:05-07:00"

//go:embed migration/*.sql
var migrationFS embed.FS

// DB represents the database connection.
type DB struct {
	//db     *sql.DB
	db     *gorm.DB
	ctx    context.Context // background context
	cancel func()          // cancel background context

	// Datasource name.
	DSN    string
	DBType string

	// Destination for events to be published.
	EventService wtf.EventService

	// Returns the current time. Defaults to time.Now().
	// Can be mocked for tests.
	Now func() time.Time
}

// NewDB returns a new instance of DB associated with the given datasource name.
func NewDB(dsn string, dbType string) *DB {
	db := &DB{
		DSN:    dsn,
		DBType: dbType,
		Now:    time.Now,

		EventService: wtf.NopEventService(),
	}
	db.ctx, db.cancel = context.WithCancel(context.Background())
	return db
}

// Open opens the database connection.
func (db *DB) Open() (err error) {
	// Ensure a DSN is set before attempting to open the database.
	if db.DSN == "" {
		return fmt.Errorf("dsn required")
	}

	if db.DBType == "sqlite" {
		// Make the parent directory unless using an in-memory db.
		if db.DSN != ":memory:" {
			if err := os.MkdirAll(filepath.Dir(db.DSN), 0700); err != nil {
				return err
			}
		}

		// Connect to the database.
		if db.db, err = gorm.Open(sqlite.Open(db.DSN), &gorm.Config{}); err != nil {
			return err
		}

		// Enable WAL. SQLite performs better with the WAL  because it allows
		// multiple readers to operate while data is being written.
		if result := db.db.Exec(`PRAGMA journal_mode = wal;`); result.Error != nil {
			return fmt.Errorf("enable wal: %w", result.Error)
		}

		// Enable foreign key checks. For historical reasons, SQLite does not check
		// foreign key constraints by default... which is kinda insane. There's some
		// overhead on inserts to verify foreign key integrity but it's definitely
		// worth it.
		if result := db.db.Exec(`PRAGMA foreign_keys = ON;`); result.Error != nil {
			return fmt.Errorf("foreign keys pragma: %w", result.Error)
		}

		if err := db.migrate(); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	} else if db.DBType == "postgres" {
		// Connect to the database.
		if db.db, err = gorm.Open(postgres.Open(db.DSN), &gorm.Config{}); err != nil {
			return err
		}
	}

	// Monitor stats in background goroutine.
	go db.monitor()

	return nil
}

// migrate sets up migration tracking and executes pending migration files.
//
// Migration files are embedded in the sqlite/migration folder and are executed
// in lexigraphical order.
//
// Once a migration is run, its name is stored in the 'migrations' table so it
// is not re-executed. Migrations run in a transaction to prevent partial
// migrations.
func (db *DB) migrate() error {
	// Ensure the 'migrations' table exists so we don't duplicate migrations.
	if result := db.db.Exec(`CREATE TABLE IF NOT EXISTS migrations (name TEXT PRIMARY KEY);`); result.Error != nil {
		return fmt.Errorf("cannot create migrations table: %w", result.Error)
	}

	// Read migration files from our embedded file system.
	// This uses Go 1.16's 'embed' package.
	names, err := fs.Glob(migrationFS, "migration/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)

	// Loop over all migration files and execute them in order.
	for _, name := range names {
		if err := db.migrateFile(name); err != nil {
			return fmt.Errorf("migration error: name=%q err=%w", name, err)
		}
	}
	return nil
}

// migrate runs a single migration file within a transaction. On success, the
// migration file name is saved to the "migrations" table to prevent re-running.
func (db *DB) migrateFile(name string) error {
	tx := db.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Ensure migration has not already been run.
	var n int
	if err := tx.Raw(`SELECT COUNT(*) FROM migrations WHERE name = ?`, name).Scan(&n); err.Error != nil {
		return err.Error
	} else if n != 0 {
		return nil // already run migration, skip
	}

	// Read and execute migration file.
	if buf, err := fs.ReadFile(migrationFS, name); err != nil {
		return err
	} else if result := tx.Exec(string(buf)); result.Error != nil {
		return result.Error
	}

	// Insert record into migrations to prevent re-running migration.
	if result := tx.Exec(`INSERT INTO migrations (name) VALUES (?)`, name); result.Error != nil {
		return result.Error
	}

	return tx.Commit().Error
}

// Close closes the database connection.
func (db *DB) Close() error {
	// Cancel background context.
	db.cancel()

	// Close database.  Not needed with gorm
	if db.db != nil {
		testDB, err := db.db.DB()
		if err != nil {
			return FormatError(err)
		}
		return testDB.Close()
	}
	return nil
}

// BeginTx starts a transaction and returns a wrapper Tx type. This type
// provides a reference to the database and a fixed timestamp at the start of
// the transaction. The timestamp allows us to mock time during tests as well.
func (db *DB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error) {
	tx := db.db.Begin(opts)
	if tx.Error != nil {
		return nil, tx.Error
	}

	// Return wrapper Tx that includes the transaction start time.
	return &Tx{
		Tx:  tx,
		db:  db,
		now: db.Now().UTC().Truncate(time.Second),
	}, nil
}

// monitor runs in a goroutine and periodically calculates internal stats.
func (db *DB) monitor() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-db.ctx.Done():
			return
		case <-ticker.C:
		}

		if err := db.updateStats(db.ctx); err != nil {
			log.Printf("stats error: %s", err)
		}
	}
}

// updateStats updates the metrics for the database.
func (db *DB) updateStats(ctx context.Context) error {
	//can't assume the database is available, need to check and open if needed.
	if db.db == nil {
		if err := db.Open(); err != nil {
			return err
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Tx.Rollback()

	var n int64

	userCount := tx.Tx.Table("users").Count(&n)
	if userCount.Error != nil {
		return fmt.Errorf("user count: %v", userCount.Error)
	}
	//if err := tx.Tx.Raw(`SELECT COUNT(*) FROM users;`).Scan(&n); err != nil {
	//	return fmt.Errorf("user count: %v", err)
	//}
	userCountGauge.Set(float64(n))

	dialCount := tx.Tx.Table("dials").Count(&n)
	if dialCount.Error != nil {
		return fmt.Errorf("dial count: %v", dialCount.Error)
	}
	//if err := tx.Tx.Raw(`SELECT COUNT(*) FROM dials;`).Scan(&n); err != nil {
	//	return fmt.Errorf("dial count: %v", err)
	//}
	dialCountGauge.Set(float64(n))

	membershipCount := tx.Tx.Table("dial_memberships").Count(&n)
	if membershipCount.Error != nil {
		return fmt.Errorf("dial_membership count: %v", membershipCount.Error)
	}
	//if err := tx.Tx.Raw(`SELECT COUNT(*) FROM dial_memberships;`).Scan(&n); err != nil {
	//	return fmt.Errorf("dial membership count: %v", err)
	//}
	dialMembershipCountGauge.Set(float64(n))

	return nil
}

// Tx wraps the SQL Tx object to provide a timestamp at the start of the transaction.
type Tx struct {
	Tx  *gorm.DB
	db  *DB
	now time.Time
}

// lastInsertID is a helper function for reading the last inserted ID as an int.
func lastInsertID(result sql.Result) (int, error) {
	id, err := result.LastInsertId()
	return int(id), err
}

// NullTime represents a helper wrapper for time.Time. It automatically converts
// time fields to/from RFC 3339 format. Also supports NULL for zero time.
type NullTime time.Time

// Scan reads a time value from the database.
func (n *NullTime) Scan(value interface{}) error {
	if value == nil {
		*(*time.Time)(n) = time.Time{}
		return nil
	} else if value, ok := value.(string); ok {
		*(*time.Time)(n), _ = time.Parse(time.RFC3339, value)
		return nil
	}
	return fmt.Errorf("NullTime: cannot scan to time.Time: %T", value)
}

// Value formats a time value for the database.
func (n *NullTime) Value() (driver.Value, error) {
	if n == nil || (*time.Time)(n).IsZero() {
		return nil, nil
	}
	return (*time.Time)(n).UTC().Format(time.RFC3339), nil
}

// FormatLimitOffset returns a SQL string for a given limit & offset.
// Clauses are only added if limit and/or offset are greater than zero.
func FormatLimitOffset(limit, offset int) string {
	if limit > 0 && offset > 0 {
		return fmt.Sprintf(`LIMIT %d OFFSET %d`, limit, offset)
	} else if limit > 0 {
		return fmt.Sprintf(`LIMIT %d`, limit)
	} else if offset > 0 {
		return fmt.Sprintf(`OFFSET %d`, offset)
	}
	return ""
}

// FormatError returns err as a WTF error, if possible.
// Otherwise returns the original error.
func FormatError(err error) error {
	if err == nil {
		return nil
	}

	switch err.Error() {
	case "UNIQUE constraint failed: dial_memberships.dial_id, dial_memberships.user_id":
		return wtf.Errorf(wtf.ECONFLICT, "Dial membership already exists.")
	default:
		return err
	}
}

// logstr is a helper function for printing and returning a string.
// It can be useful for printing out query text.
func logstr(s string) string {
	println(s)
	return s
}
