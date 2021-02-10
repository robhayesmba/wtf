package sqlite

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/benbjohnson/wtf"
	"io"
	"time"
)

// Ensure service implements interface.
var _ wtf.UserService = (*UserService)(nil)

// UserService represents a service for managing users.
type UserService struct {
	db *DB
}

// NewUserService returns a new instance of UserService.
func NewUserService(db *DB) *UserService {
	return &UserService{db: db}
}

type SqliteUser struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	APIKey string `json:"-"`

	// Timestamps for user creation & last update.
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// FindUserByID retrieves a user by ID along with their associated auth objects.
// Returns ENOTFOUND if user does not exist.
func (s *UserService) FindUserByID(ctx context.Context, id int) (*wtf.User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Tx.Rollback()

	// Fetch user and their associated OAuth objects.
	user, err := findUserByID(ctx, tx, id)
	if err != nil {
		return nil, err
	} else if err := attachUserAuths(ctx, tx, user); err != nil {
		return user, err
	}
	return user, nil
}

// FindUsers retrieves a list of users by filter. Also returns total count of
// matching users which may differ from returned results if filter.Limit is specified.
func (s *UserService) FindUsers(ctx context.Context, filter wtf.UserFilter) ([]*wtf.User, int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Tx.Rollback()
	return findUsers(ctx, tx, filter)
}

// CreateUser creates a new user. This is only used for testing since users are
// typically created during the OAuth creation process in AuthService.CreateAuth().
func (s *UserService) CreateUser(ctx context.Context, user *wtf.User) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Tx.Rollback()

	// Create a new user object and attach associated OAuth objects.
	if err := createUser(ctx, tx, user); err != nil {
		return err
	} else if err := attachUserAuths(ctx, tx, user); err != nil {
		return err
	}
	return tx.Tx.Commit().Error
}

// UpdateUser updates a user object. Returns EUNAUTHORIZED if current user is
// not the user that is being updated. Returns ENOTFOUND if user does not exist.
func (s *UserService) UpdateUser(ctx context.Context, id int, upd wtf.UserUpdate) (*wtf.User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Tx.Rollback()

	// Update user & attach associated OAuth objects.
	user, err := updateUser(ctx, tx, id, upd)
	if err != nil {
		return user, err
	} else if err := attachUserAuths(ctx, tx, user); err != nil {
		return user, err
	} else if err := tx.Tx.Commit().Error; err != nil {
		return user, err
	}
	return user, nil
}

// DeleteUser permanently deletes a user and all owned dials.
// Returns EUNAUTHORIZED if current user is not the user being deleted.
// Returns ENOTFOUND if user does not exist.
func (s *UserService) DeleteUser(ctx context.Context, id int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Tx.Rollback()

	if err := deleteUser(ctx, tx, id); err != nil {
		return err
	}
	return tx.Tx.Commit().Error
}

// findUserByID is a helper function to fetch a user by ID.
// Returns ENOTFOUND if user does not exist.
func findUserByID(ctx context.Context, tx *Tx, id int) (*wtf.User, error) {
	a, _, err := findUsers(ctx, tx, wtf.UserFilter{ID: &id})
	if err != nil {
		return nil, err
	} else if len(a) == 0 {
		return nil, &wtf.Error{Code: wtf.ENOTFOUND, Message: "User not found."}
	}
	return a[0], nil
}

// findUserByEmail is a helper function to fetch a user by email.
// Returns ENOTFOUND if user does not exist.
func findUserByEmail(ctx context.Context, tx *Tx, email string) (*wtf.User, error) {
	a, _, err := findUsers(ctx, tx, wtf.UserFilter{Email: &email})
	if err != nil {
		return nil, err
	} else if len(a) == 0 {
		return nil, &wtf.Error{Code: wtf.ENOTFOUND, Message: "User not found."}
	}
	return a[0], nil
}

// findUsers returns a list of users matching a filter. Also returns a count of
// total matching users which may differ if filter.Limit is set.
func findUsers(ctx context.Context, tx *Tx, filter wtf.UserFilter) (_ []*wtf.User, n int, err error) {
	// Build WHERE clause.
	//where, args := []string{"1 = 1"}, []interface{}{}
	//if v := filter.ID; v != nil {
	//	where, args = append(where, "id = ?"), append(args, *v)
	//}
	//if v := filter.Email; v != nil {
	//	where, args = append(where, "email = ?"), append(args, *v)
	//}
	//if v := filter.APIKey; v != nil {
	//	where, args = append(where, "api_key = ?"), append(args, *v)
	//}

	var whereMap map[string]interface{}
	whereMap = make(map[string]interface{})
	if filter.ID != nil {
		whereMap["id"] = filter.ID
	}
	if filter.Email != nil {
		whereMap["email"] = filter.Email
	}
	if filter.APIKey != nil {
		whereMap["api_key"] = filter.APIKey
	}

	if tx.db.DBType == "sqlite" {
		var usersRead []*SqliteUser
		result := tx.Tx.Table("users").Where(whereMap).Find(&usersRead)
		if result.Error != nil {
			return nil, int(result.RowsAffected), FormatError(result.Error)
		}

		users := make([]*wtf.User, 0)
		count := 0
		for _, user := range usersRead {
			//var u wtf.User
			//u.ID = user.ID
			//u.Name = user.Name
			//u.Email = user.Email
			//u.APIKey = user.APIKey
			//ct, err := time.Parse(TimeLayout,user.CreatedAt)
			//if err != nil {
			//	return nil, 0, FormatError(err)
			//}
			//u.CreatedAt = ct.UTC().Truncate(time.Second)
			//ut, err := time.Parse(TimeLayout, user.UpdatedAt)
			//if err != nil {
			//	return nil, 0, FormatError(err)
			//}
			//u.UpdatedAt = ut.UTC().Truncate(time.Second)

			u, err := mapFromDBUser(user)
			if err != nil {
				return nil, 0, FormatError(err)
			}
			users = append(users, u)
			count++
		}
		return users, count, nil
	} else {
		var users []*wtf.User
		result := tx.Tx.Where(whereMap).Find(&users)
		if result.Error != nil {
			return nil, int(result.RowsAffected), FormatError(result.Error)
		}

		return users, int(result.RowsAffected), nil
	}
	// Execute query to fetch user rows.
	//rows, err := tx.QueryContext(ctx, `
	//	SELECT
	//	    id,
	//	    name,
	//	    email,
	//	    api_key,
	//	    created_at,
	//	    updated_at,
	//	    COUNT(*) OVER()
	//	FROM users
	//	WHERE `+strings.Join(where, " AND ")+`
	//	ORDER BY id ASC
	//	`+FormatLimitOffset(filter.Limit, filter.Offset),
	//	args...,
	//).Scan(&users)

	//if err != nil {
	//	return nil, n, err
	//}
	//defer rows.Close()

	// Deserialize rows into User objects.
	//users := make([]*wtf.User, 0)
	//for rows.Next() {
	//	var email sql.NullString
	//	var user wtf.User
	//	if rows.Scan(
	//		&user.ID,
	//		&user.Name,
	//		&email,
	//		&user.APIKey,
	//		(*NullTime)(&user.CreatedAt),
	//		(*NullTime)(&user.UpdatedAt),
	//		&n,
	//	); err != nil {
	//		return nil, 0, err
	//	}
	//
	//	if email.Valid {
	//		user.Email = email.String
	//	}
	//
	//	users = append(users, &user)
	//}
	//if err := rows.Err(); err != nil {
	//	return nil, 0, err
	//}

	//return users, count, nil
}

// createUser creates a new user. Sets the new database ID to user.ID and sets
// the timestamps to the current time.
func createUser(ctx context.Context, tx *Tx, user *wtf.User) error {
	// Set timestamps to the current time.
	if tx.db.DBType == "sqlite" {
		user.CreatedAt = tx.now
		user.UpdatedAt = user.CreatedAt
	}

	// Perform basic field validation.
	if err := user.Validate(); err != nil {
		return err
	}

	// Email is nullable and has a UNIQUE constraint so ensure we store blank
	// fields as NULLs.
	//var email *string
	//if user.Email != "" {
	//	email = &user.Email
	//}

	// Generate random API key.
	apiKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, apiKey); err != nil {
		return err
	}
	user.APIKey = hex.EncodeToString(apiKey)

	if tx.db.DBType == "sqlite" {
		crUser := mapToDBUser(user)
		result := tx.Tx.Table("users").Create(&crUser)

		if result.Error != nil {
			return FormatError(result.Error)
		}

		// set ID to the user ID in the database.
		user.ID = crUser.ID
	} else {
		result := tx.Tx.Create(&user)
		if result.Error != nil {
			return FormatError(result.Error)
		}
	}
	// Execute insertion query.
	//result, err := tx.ExecContext(ctx, `
	//	INSERT INTO users (
	//		name,
	//		email,
	//		api_key,
	//		created_at,
	//		updated_at
	//	)
	//	VALUES (?, ?, ?, ?, ?)
	//`,
	//	user.Name,
	//	email,
	//	user.APIKey,
	//	(*NullTime)(&user.CreatedAt),
	//	(*NullTime)(&user.UpdatedAt),
	//)
	//if err != nil {
	//	return FormatError(err)
	//}
	//
	//if user.ID, err = lastInsertID(result); err != nil {
	//	return err
	//}

	return nil
}

// updateUser updates fields on a user object. Returns EUNAUTHORIZED if current
// user is not the user being updated.
func updateUser(ctx context.Context, tx *Tx, id int, upd wtf.UserUpdate) (*wtf.User, error) {
	// Fetch current object state.
	user, err := findUserByID(ctx, tx, id)
	if err != nil {
		return user, err
	} else if user.ID != wtf.UserIDFromContext(ctx) {
		return nil, wtf.Errorf(wtf.EUNAUTHORIZED, "You are not allowed to update this user.")
	}

	// Update fields.
	if v := upd.Name; v != nil {
		user.Name = *v
	}
	if v := upd.Email; v != nil {
		user.Email = *v
	}

	// Set last updated date to current time.
	if tx.db.DBType == "sqlite" {
		user.UpdatedAt = tx.now
	}

	// Perform basic field validation.
	if err := user.Validate(); err != nil {
		return user, err
	}

	// Email is nullable and has a UNIQUE constraint so ensure we store blank
	// fields as NULLs.
	//var email *string
	//if user.Email != "" {
	//	email = &user.Email
	//}

	if tx.db.DBType == "sqlite" {
		upUser := mapToDBUser(user)
		result := tx.Tx.Table("users").Updates(&upUser)
		if result.Error != nil {
			return user, FormatError(result.Error)
		}
	} else {
		result := tx.Tx.Updates(&user)
		if result.Error != nil {
			return user, FormatError(result.Error)
		}
	}

	// Execute update query.
	//if _, err := tx.ExecContext(ctx, `
	//	UPDATE users
	//	SET name = ?,
	//	    email = ?,
	//	    updated_at = ?
	//	WHERE id = ?
	//`,
	//	user.Name,
	//	email,
	//	(*NullTime)(&user.UpdatedAt),
	//	id,
	//); err != nil {
	//	return user, FormatError(err)
	//}

	return user, nil
}

// deleteUser permanently removes a user by ID. Returns EUNAUTHORIZED if current
// user is not the one being deleted.
func deleteUser(ctx context.Context, tx *Tx, id int) error {
	// Verify object exists.
	if user, err := findUserByID(ctx, tx, id); err != nil {
		return err
	} else if user.ID != wtf.UserIDFromContext(ctx) {
		return wtf.Errorf(wtf.EUNAUTHORIZED, "You are not allowed to delete this user.")
	}

	result := tx.Tx.Delete(&wtf.User{}, id)

	if result.Error != nil {
		return FormatError(result.Error)
	}
	// Remove row from database.
	//if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id); err != nil {
	//	return FormatError(err)
	//}
	return nil
}

// attachUserAuths attaches OAuth objects associated with the user.
func attachUserAuths(ctx context.Context, tx *Tx, user *wtf.User) (err error) {
	if user.Auths, _, err = findAuths(ctx, tx, wtf.AuthFilter{UserID: &user.ID}); err != nil {
		return fmt.Errorf("attach user auths: %w", err)
	}
	return nil
}

func mapFromDBUser(user *SqliteUser) (*wtf.User, error) {
	var u wtf.User
	u.ID = user.ID
	u.Name = user.Name
	u.Email = user.Email
	u.APIKey = user.APIKey
	ct, err := time.Parse(TimeLayout, user.CreatedAt)
	if err != nil {
		return nil, err
	}
	u.CreatedAt = ct.UTC().Truncate(time.Second)
	ut, err := time.Parse(TimeLayout, user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	u.UpdatedAt = ut.UTC().Truncate(time.Second)

	return &u, nil
}

func mapToDBUser(user *wtf.User) SqliteUser {
	var u SqliteUser
	u.ID = user.ID
	u.Name = user.Name
	u.Email = user.Email
	u.APIKey = user.APIKey
	u.CreatedAt = user.CreatedAt.Format(TimeLayout)
	u.UpdatedAt = user.UpdatedAt.Format(TimeLayout)
	return u
}
