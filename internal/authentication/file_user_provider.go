package authentication

import (
	_ "embed" // Embed users_database.template.yml.
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/algorithm/argon2"
	"github.com/go-crypt/crypt/algorithm/bcrypt"
	"github.com/go-crypt/crypt/algorithm/pbkdf2"
	"github.com/go-crypt/crypt/algorithm/scrypt"
	"github.com/go-crypt/crypt/algorithm/shacrypt"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/logging"
)

var _ UserProvider = &FileUserProvider{}

// FileUserProvider is a provider reading details from a file.
type FileUserProvider struct {
	config        *schema.FileAuthenticationBackend
	hash          algorithm.Hash
	database      *FileUserDatabase
	mutex         *sync.Mutex
	timeoutReload time.Time
}

// NewFileUserProvider creates a new instance of FileUserProvider.
func NewFileUserProvider(config *schema.FileAuthenticationBackend) (provider *FileUserProvider) {
	return &FileUserProvider{
		config:        config,
		mutex:         &sync.Mutex{},
		timeoutReload: time.Now().Add(-1 * time.Second),
	}
}

// Reload the database.
func (p *FileUserProvider) Reload() (reloaded bool, err error) {
	now := time.Now()

	p.mutex.Lock()

	defer p.mutex.Unlock()

	if now.Before(p.timeoutReload) {
		return false, nil
	}

	switch err = p.database.Load(); {
	case err == nil:
		p.setTimeoutReload(now)
	case errors.Is(err, ErrNoContent):
		return false, nil
	default:
		return false, fmt.Errorf("failed to reload: %w", err)
	}

	p.setTimeoutReload(now)

	return true, nil
}

// CheckUserPassword checks if provided password matches for the given user.
func (p *FileUserProvider) CheckUserPassword(username string, password string) (match bool, res *ValidResult, err error) {
	var details DatabaseUserDetails

	if details, err = p.database.GetUserDetails(username); err != nil {
		return false, nil, err
	}

	if details.Disabled {
		return false, nil, ErrUserNotFound
	}

	match, err = details.Digest.MatchAdvanced(password)

	return match, nil, err
}

// GetDetails retrieve the groups a user belongs to.
func (p *FileUserProvider) GetDetails(username, _ string) (details *UserDetails, err error) {
	var d DatabaseUserDetails

	if d, err = p.database.GetUserDetails(username); err != nil {
		return nil, err
	}

	if d.Disabled {
		return nil, ErrUserNotFound
	}

	return d.ToUserDetails(), nil
}

// UpdatePassword update the password of the given user.
func (p *FileUserProvider) UpdatePassword(username, _ string, newPassword string) (err error) {
	var details DatabaseUserDetails

	if details, err = p.database.GetUserDetails(username); err != nil {
		return err
	}

	if details.Disabled {
		return ErrUserNotFound
	}

	if details.Digest, err = p.hash.Hash(newPassword); err != nil {
		return err
	}

	p.database.SetUserDetails(details.Username, &details)

	p.mutex.Lock()

	p.setTimeoutReload(time.Now())

	p.mutex.Unlock()

	if err = p.database.Save(); err != nil {
		return err
	}

	return nil
}

func (p *FileUserProvider) Refresh(username, _, _ string) (res *ValidResult, err error) {
	return res, err
}

func (p *FileUserProvider) ResetPassword(_, _, _, _ string, _ bool) (err error) {
	return nil
}

// StartupCheck implements the startup check provider interface.
func (p *FileUserProvider) StartupCheck() (err error) {
	if err = checkDatabase(p.config.Path); err != nil {
		logging.Logger().WithError(err).Errorf("Error checking user authentication YAML database")

		return fmt.Errorf("one or more errors occurred checking the authentication database")
	}

	if p.hash, err = NewFileCryptoHashFromConfig(p.config.Password); err != nil {
		return err
	}

	p.database = NewFileUserDatabase(p.config.Path, p.config.Search.Email, p.config.Search.CaseInsensitive)

	if err = p.database.Load(); err != nil {
		return err
	}

	return nil
}

func (p *FileUserProvider) setTimeoutReload(now time.Time) {
	p.timeoutReload = now.Add(time.Second / 2)
}

// NewFileCryptoHashFromConfig returns a crypt.Hash given a valid configuration.
func NewFileCryptoHashFromConfig(config schema.Password) (hash algorithm.Hash, err error) {
	switch config.Algorithm {
	case hashArgon2, "":
		hash, err = argon2.New(
			argon2.WithVariantName(config.Argon2.Variant),
			argon2.WithT(config.Argon2.Iterations),
			argon2.WithM(uint32(config.Argon2.Memory)),
			argon2.WithP(config.Argon2.Parallelism),
			argon2.WithK(config.Argon2.KeyLength),
			argon2.WithS(config.Argon2.SaltLength),
		)
	case hashSHA2Crypt:
		hash, err = shacrypt.New(
			shacrypt.WithVariantName(config.SHA2Crypt.Variant),
			shacrypt.WithIterations(config.SHA2Crypt.Iterations),
			shacrypt.WithSaltLength(config.SHA2Crypt.SaltLength),
		)
	case hashPBKDF2:
		hash, err = pbkdf2.New(
			pbkdf2.WithVariantName(config.PBKDF2.Variant),
			pbkdf2.WithIterations(config.PBKDF2.Iterations),
			pbkdf2.WithSaltLength(config.PBKDF2.SaltLength),
		)
	case hashSCrypt:
		hash, err = scrypt.New(
			scrypt.WithLN(config.SCrypt.Iterations),
			scrypt.WithP(config.SCrypt.Parallelism),
			scrypt.WithR(config.SCrypt.BlockSize),
			scrypt.WithKeyLength(config.SCrypt.KeyLength),
			scrypt.WithSaltLength(config.SCrypt.SaltLength),
		)
	case hashBCrypt:
		hash, err = bcrypt.New(
			bcrypt.WithVariantName(config.BCrypt.Variant),
			bcrypt.WithIterations(config.BCrypt.Cost),
		)
	default:
		return nil, fmt.Errorf("algorithm '%s' is unknown", config.Algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to initialize hash settings: %w", err)
	}

	if err = hash.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate hash settings: %w", err)
	}

	return hash, nil
}

func checkDatabase(path string) (err error) {
	if _, err = os.Stat(path); os.IsNotExist(err) {
		if err = os.WriteFile(path, userYAMLTemplate, 0600); err != nil {
			return fmt.Errorf("user authentication database file doesn't exist at path '%s' and could not be generated: %w", path, err)
		}

		return fmt.Errorf("user authentication database file doesn't exist at path '%s' and has been generated", path)
	} else if err != nil {
		return fmt.Errorf("error checking user authentication database file: %w", err)
	}

	return nil
}

//go:embed users_database.template.yml
var userYAMLTemplate []byte
