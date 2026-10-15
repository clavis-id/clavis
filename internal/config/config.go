// Package config loads and validates the configuration of the clavis binary.
//
// Configuration is read from an optional YAML file and then overridden by
// environment variables. Every key has an environment variable named after
// its path, upper-cased, with dots replaced by underscores and a CLAVIS_
// prefix: server.read_header_timeout becomes CLAVIS_SERVER_READ_HEADER_TIMEOUT.
//
// Embedders do not use this package; they configure Clavis with Go values
// through the public clavis.Config type.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/v2"

	"clavisid.org/clavis/internal/authn/password"
	"clavisid.org/clavis/internal/issuer"
	"clavisid.org/clavis/internal/keys"
	"clavisid.org/clavis/kek"
)

// EnvPrefix is the prefix of every environment variable read by Load.
const EnvPrefix = "CLAVIS_"

// EnvConfigFile names the environment variable that holds the path of the
// configuration file. It is not a configuration key itself.
const EnvConfigFile = EnvPrefix + "CONFIG"

// Config is the complete configuration of the clavis binary.
type Config struct {
	// Issuer is the base URL that identifies this deployment in tokens and
	// discovery documents.
	Issuer string `koanf:"issuer"`
	// Server configures the HTTP listener.
	Server Server `koanf:"server"`
	// Database configures where Clavis stores its data.
	Database Database `koanf:"database"`
	// Keys configures token signing keys and their encryption at rest.
	Keys Keys `koanf:"keys"`
	// Passwords configures password hashing.
	Passwords Passwords `koanf:"passwords"`
	// Telemetry configures traces and metrics.
	Telemetry Telemetry `koanf:"telemetry"`
	// Log configures structured logging.
	Log Log `koanf:"log"`
}

// Telemetry configures traces and metrics. Both are disabled by default.
type Telemetry struct {
	Tracing Tracing `koanf:"tracing"`
	Metrics Metrics `koanf:"metrics"`
}

// Tracing configures span export over OTLP/HTTP.
type Tracing struct {
	Enabled bool `koanf:"enabled"`
	// Endpoint is the OTLP/HTTP traces URL. When empty, the standard
	// OTEL_EXPORTER_OTLP_* environment variables apply.
	Endpoint string `koanf:"endpoint"`
	// SampleRatio is the fraction of new traces recorded, from 0 to 1.
	SampleRatio float64 `koanf:"sample_ratio"`
}

// Metrics configures the Prometheus scrape endpoint.
type Metrics struct {
	Enabled bool `koanf:"enabled"`
	// Address is the listener of the metrics endpoint, separate from the
	// API listener so metrics are never exposed with the public API.
	Address string `koanf:"address"`
}

// Database drivers accepted in Database.Driver.
const (
	DriverSQLite   = "sqlite"
	DriverPostgres = "postgres"
)

// Database configures where Clavis stores its data.
type Database struct {
	// Driver is "sqlite" or "postgres".
	Driver string `koanf:"driver"`
	// DSN is the database file path for sqlite, or a connection URL for
	// postgres. It may contain a password and is never logged.
	DSN string `koanf:"dsn"`
	// AutoMigrate applies pending schema migrations on startup. Disable it
	// to run `clavis migrate` as a separate deployment step.
	AutoMigrate bool `koanf:"auto_migrate"`
}

// Server configures the HTTP listener.
type Server struct {
	// Address is the TCP address to listen on, for example ":8080".
	Address string `koanf:"address"`
	// ReadHeaderTimeout bounds the time allowed to read request headers.
	ReadHeaderTimeout time.Duration `koanf:"read_header_timeout"`
	// ReadTimeout bounds the time allowed to read an entire request.
	ReadTimeout time.Duration `koanf:"read_timeout"`
	// WriteTimeout bounds the time allowed to write a response.
	WriteTimeout time.Duration `koanf:"write_timeout"`
	// IdleTimeout bounds how long an idle keep-alive connection stays open.
	IdleTimeout time.Duration `koanf:"idle_timeout"`
	// ShutdownTimeout bounds how long in-flight requests may take to finish
	// after a shutdown signal.
	ShutdownTimeout time.Duration `koanf:"shutdown_timeout"`
}

// Keys configures token signing keys and their encryption at rest.
type Keys struct {
	// EncryptionKey is the base64-encoded 32-byte key that encrypts private
	// signing keys before they reach the database. It is required and is
	// never logged. Generate one with `clavis keys new-encryption-key`.
	EncryptionKey string `koanf:"encryption_key"`
	// PreviousEncryptionKeys still decrypt existing keys after
	// EncryptionKey is rotated. In the environment, separate them with
	// commas.
	PreviousEncryptionKeys []string `koanf:"previous_encryption_keys"`
	// Algorithms lists the JWS algorithms used to sign tokens: RS256
	// (required), ES256, EdDSA. In the environment, separate them with
	// commas.
	Algorithms []string `koanf:"algorithms"`
	// RotationPeriod is how long each signing key signs.
	RotationPeriod time.Duration `koanf:"rotation_period"`
	// PublishAhead is how long a new key is published before it signs.
	PublishAhead time.Duration `koanf:"publish_ahead"`
	// Retention is how long a retired key stays published.
	Retention time.Duration `koanf:"retention"`
	// CheckInterval is how often rotation runs.
	CheckInterval time.Duration `koanf:"check_interval"`
}

// Passwords configures password hashing (ADR 0015).
type Passwords struct {
	// MinLength is the minimum number of characters of a new password, at
	// least 8. NIST SP 800-63B-4 asks for 15 when a password is the only
	// authentication factor.
	MinLength int `koanf:"min_length"`
	// Argon2id sets the cost of new argon2id hashes. The defaults are the
	// OWASP baseline, which is also the minimum.
	Argon2id Argon2id `koanf:"argon2id"`
	// PBKDF2Iterations is the iteration count of new PBKDF2-HMAC-SHA-256
	// hashes, which replace argon2id in FIPS mode. At least 600,000.
	PBKDF2Iterations int `koanf:"pbkdf2_iterations"`
	// MaxConcurrentHashes bounds how many hashes are computed at once;
	// further logins wait. 0 uses the number of CPUs. Each argon2id hash
	// uses argon2id.memory_kib of memory.
	MaxConcurrentHashes int `koanf:"max_concurrent_hashes"`
	// FIPSMigrateArgon2id lets FIPS mode verify an argon2id hash created
	// before FIPS mode was enabled, once, so the login replaces it with a
	// PBKDF2 hash. argon2id is not FIPS approved: set it to false to refuse
	// such hashes instead, and have their users reset their passwords.
	FIPSMigrateArgon2id bool `koanf:"fips_migrate_argon2id"`
}

// Argon2id sets the cost of argon2id hashes.
type Argon2id struct {
	// MemoryKiB is the memory of one hash, in KiB.
	MemoryKiB   uint32 `koanf:"memory_kib"`
	Iterations  uint32 `koanf:"iterations"`
	Parallelism uint8  `koanf:"parallelism"`
}

// Policy returns the password policy described by p.
func (p Passwords) Policy() password.Config {
	return password.Config{
		MinLength: p.MinLength,
		Argon2id: password.Argon2idParams{
			MemoryKiB:   p.Argon2id.MemoryKiB,
			Iterations:  p.Argon2id.Iterations,
			Parallelism: p.Argon2id.Parallelism,
		},
		PBKDF2Iterations:    p.PBKDF2Iterations,
		MaxConcurrent:       p.MaxConcurrentHashes,
		FIPSMigrateArgon2id: p.FIPSMigrateArgon2id,
	}
}

// validate reports the problems in the passwords section.
func (p Passwords) validate() []error {
	if err := p.Policy().Validate(); err != nil {
		return []error{fmt.Errorf("passwords: %w", err)}
	}
	return nil
}

// Log configures structured logging.
type Log struct {
	// Level is the minimum level: debug, info, warn or error.
	Level string `koanf:"level"`
	// Format is the output encoding: json or text.
	Format string `koanf:"format"`
}

// Default returns the configuration used when nothing overrides it.
func Default() Config {
	defaultPolicy := keys.DefaultPolicy()
	defaultPasswords := password.DefaultConfig()
	return Config{
		Issuer: "http://localhost:8080",
		Server: Server{
			Address:           ":8080",
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       2 * time.Minute,
			ShutdownTimeout:   30 * time.Second,
		},
		Database: Database{
			Driver:      DriverSQLite,
			DSN:         "clavis.db",
			AutoMigrate: true,
		},
		Keys: Keys{
			Algorithms:     defaultPolicy.Algorithms,
			RotationPeriod: defaultPolicy.RotationPeriod,
			PublishAhead:   defaultPolicy.PublishAhead,
			Retention:      defaultPolicy.Retention,
			CheckInterval:  defaultPolicy.CheckInterval,
		},
		Passwords: Passwords{
			MinLength: defaultPasswords.MinLength,
			Argon2id: Argon2id{
				MemoryKiB:   defaultPasswords.Argon2id.MemoryKiB,
				Iterations:  defaultPasswords.Argon2id.Iterations,
				Parallelism: defaultPasswords.Argon2id.Parallelism,
			},
			PBKDF2Iterations:    defaultPasswords.PBKDF2Iterations,
			MaxConcurrentHashes: defaultPasswords.MaxConcurrent,
			FIPSMigrateArgon2id: defaultPasswords.FIPSMigrateArgon2id,
		},
		Telemetry: Telemetry{
			Tracing: Tracing{SampleRatio: 1},
			Metrics: Metrics{Address: "127.0.0.1:9464"},
		},
		Log: Log{
			Level:  "info",
			Format: "json",
		},
	}
}

// Result is the outcome of Load.
type Result struct {
	// Config is the loaded and validated configuration.
	Config Config
	// IgnoredEnv lists CLAVIS_ environment variables that do not match any
	// configuration key. They are ignored rather than rejected because
	// platforms such as Kubernetes inject variables with the same prefix.
	IgnoredEnv []string
}

// Load reads the YAML file at path, when path is not empty, applies
// overrides from environ (in os.Environ format) and validates the result.
// Unknown keys in the file and invalid values are errors.
func Load(path string, environ []string) (Result, error) {
	return load(path, environ, Config.Validate)
}

// LoadDatabase reads the same sources as Load but validates only the
// database and log sections. Commands such as migrate use it, so they do not
// need secrets they never use, such as the key encryption key.
func LoadDatabase(path string, environ []string) (Result, error) {
	return load(path, environ, Config.validateDatabase)
}

// LoadPasswords reads the same sources as Load but validates only the
// database, log and passwords sections, for commands that manage users and
// their passwords.
func LoadPasswords(path string, environ []string) (Result, error) {
	return load(path, environ, Config.validatePasswords)
}

// load reads the file at path, if any, and builds the configuration checked
// by validate.
func load(path string, environ []string, validate func(Config) error) (Result, error) {
	var data []byte
	if path != "" {
		var err error
		data, err = os.ReadFile(path) //nolint:gosec // The path is chosen by the operator.
		if err != nil {
			return Result{}, fmt.Errorf("reading config file: %w", err)
		}
	}
	res, err := decode(data, environ)
	if err == nil {
		err = validate(res.Config)
	}
	if err != nil {
		if path != "" {
			return Result{}, fmt.Errorf("config file %s: %w", path, err)
		}
		return Result{}, err
	}
	return res, nil
}

// parse builds and fully validates the configuration from YAML data, which
// may be empty, and environ.
func parse(data []byte, environ []string) (Result, error) {
	res, err := decode(data, environ)
	if err != nil {
		return Result{}, err
	}
	if err := res.Config.Validate(); err != nil {
		return Result{}, err
	}
	return res, nil
}

// decode builds the configuration from YAML data, which may be empty, and
// environ, without validating it.
func decode(data []byte, environ []string) (Result, error) {
	k := koanf.New(".")
	if len(data) > 0 {
		if err := k.Load(rawbytes.Provider(data), yaml.Parser()); err != nil {
			return Result{}, fmt.Errorf("parsing config file: %w", err)
		}
	}

	known := envKeys(reflect.TypeFor[Config](), "")
	var ignored []string
	for _, kv := range environ {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(name, EnvPrefix) || name == EnvConfigFile {
			continue
		}
		key, ok := known[name]
		if !ok {
			ignored = append(ignored, name)
			continue
		}
		if err := k.Set(key, value); err != nil {
			return Result{}, fmt.Errorf("applying %s: %w", name, err)
		}
	}
	slices.Sort(ignored)

	cfg := Default()
	err := k.UnmarshalWithConf("", &cfg, koanf.UnmarshalConf{
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				durationHook,
				mapstructure.StringToSliceHookFunc(","),
			),
			ErrorUnused:      true,
			WeaklyTypedInput: true,
			TagName:          "koanf",
			Result:           &cfg,
		},
	})
	if err != nil {
		return Result{}, fmt.Errorf("decoding config: %w", err)
	}
	return Result{Config: cfg, IgnoredEnv: ignored}, nil
}

// Validate reports every problem in c, joined into a single error.
func (c Config) Validate() error {
	var errs []error
	errs = append(errs, c.Database.validate()...)
	errs = append(errs, c.Log.validate()...)
	if _, err := issuer.Parse(c.Issuer); err != nil {
		errs = append(errs, fmt.Errorf("issuer: %w", err))
	}
	if _, _, err := net.SplitHostPort(c.Server.Address); err != nil {
		errs = append(errs, fmt.Errorf("server.address: %w", err))
	}
	for name, d := range map[string]time.Duration{
		"server.read_header_timeout": c.Server.ReadHeaderTimeout,
		"server.read_timeout":        c.Server.ReadTimeout,
		"server.write_timeout":       c.Server.WriteTimeout,
		"server.idle_timeout":        c.Server.IdleTimeout,
		"server.shutdown_timeout":    c.Server.ShutdownTimeout,
	} {
		if d <= 0 {
			errs = append(errs, fmt.Errorf("%s: must be positive, got %s", name, d))
		}
	}
	errs = append(errs, c.Keys.validate()...)
	errs = append(errs, c.Passwords.validate()...)
	errs = append(errs, c.Telemetry.validate()...)
	return joinProblems(errs)
}

// validateDatabase reports the problems in the database and log sections.
func (c Config) validateDatabase() error {
	return joinProblems(append(c.Database.validate(), c.Log.validate()...))
}

// validatePasswords reports the problems in the database, log and passwords
// sections.
func (c Config) validatePasswords() error {
	errs := append(c.Database.validate(), c.Log.validate()...)
	return joinProblems(append(errs, c.Passwords.validate()...))
}

// joinProblems sorts errs for stable output and joins them, or returns nil.
func joinProblems(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	slices.SortFunc(errs, func(a, b error) int { return strings.Compare(a.Error(), b.Error()) })
	return fmt.Errorf("invalid configuration: %w", errors.Join(errs...))
}

// validate reports the problems in the database section.
func (d Database) validate() []error {
	var errs []error
	if !slices.Contains([]string{DriverSQLite, DriverPostgres}, d.Driver) {
		errs = append(errs, fmt.Errorf("database.driver: must be %s or %s, got %q", DriverSQLite, DriverPostgres, d.Driver))
	}
	if d.DSN == "" {
		errs = append(errs, errors.New("database.dsn: must not be empty"))
	}
	return errs
}

// validate reports the problems in the log section.
func (l Log) validate() []error {
	var errs []error
	if !slices.Contains([]string{"debug", "info", "warn", "error"}, l.Level) {
		errs = append(errs, fmt.Errorf("log.level: must be debug, info, warn or error, got %q", l.Level))
	}
	if !slices.Contains([]string{"json", "text"}, l.Format) {
		errs = append(errs, fmt.Errorf("log.format: must be json or text, got %q", l.Format))
	}
	return errs
}

// envKeys maps environment variable names to configuration keys for every
// leaf field of t.
func envKeys(t reflect.Type, prefix string) map[string]string {
	out := make(map[string]string)
	for f := range t.Fields() {
		tag := f.Tag.Get("koanf")
		if tag == "" || tag == "-" {
			continue
		}
		key := tag
		if prefix != "" {
			key = prefix + "." + tag
		}
		if f.Type.Kind() == reflect.Struct && f.Type != reflect.TypeFor[time.Duration]() {
			for name, k := range envKeys(f.Type, key) {
				out[name] = k
			}
			continue
		}
		out[EnvPrefix+strings.ToUpper(strings.ReplaceAll(key, ".", "_"))] = key
	}
	return out
}

// validate reports the problems in the keys section. Secret values never
// appear in the messages.
func (k Keys) validate() []error {
	var errs []error
	if k.EncryptionKey == "" {
		errs = append(errs, errors.New("keys.encryption_key: required; generate one with `clavis keys new-encryption-key`"))
	} else if _, err := kek.ParseSecret(k.EncryptionKey); err != nil {
		errs = append(errs, fmt.Errorf("keys.encryption_key: %w", err))
	}
	for i, prev := range k.PreviousEncryptionKeys {
		if _, err := kek.ParseSecret(prev); err != nil {
			errs = append(errs, fmt.Errorf("keys.previous_encryption_keys[%d]: %w", i, err))
		}
	}
	if err := k.Policy().Validate(); err != nil {
		errs = append(errs, fmt.Errorf("keys: %w", err))
	}
	return errs
}

// Policy returns the rotation policy described by k.
func (k Keys) Policy() keys.Policy {
	return keys.Policy{
		Algorithms:     k.Algorithms,
		RotationPeriod: k.RotationPeriod,
		PublishAhead:   k.PublishAhead,
		Retention:      k.Retention,
		CheckInterval:  k.CheckInterval,
	}
}

// validate reports the problems in the telemetry section.
func (t Telemetry) validate() []error {
	var errs []error
	if t.Tracing.SampleRatio < 0 || t.Tracing.SampleRatio > 1 {
		errs = append(errs, fmt.Errorf("telemetry.tracing.sample_ratio: must be between 0 and 1, got %v", t.Tracing.SampleRatio))
	}
	if t.Tracing.Endpoint != "" {
		u, err := url.Parse(t.Tracing.Endpoint)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errs = append(errs, errors.New("telemetry.tracing.endpoint: must be an absolute http or https URL"))
		}
	}
	if t.Metrics.Enabled {
		if _, _, err := net.SplitHostPort(t.Metrics.Address); err != nil {
			errs = append(errs, fmt.Errorf("telemetry.metrics.address: %w", err))
		}
	}
	return errs
}

// durationHook decodes durations from strings with a unit, such as "30s".
// Numbers are rejected: a YAML integer would otherwise be read as
// nanoseconds, so "check_interval: 3600" would mean 3.6 microseconds.
func durationHook(_, to reflect.Type, data any) (any, error) {
	if to != reflect.TypeFor[time.Duration]() {
		return data, nil
	}
	text, ok := data.(string)
	if !ok {
		return nil, fmt.Errorf("duration %v needs a unit, for example \"30s\" or \"24h\"", data)
	}
	d, err := time.ParseDuration(text)
	if err != nil {
		return nil, fmt.Errorf("invalid duration %q: %w", text, err)
	}
	return d, nil
}
