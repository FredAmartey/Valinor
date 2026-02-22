package config

import (
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

type Config struct {
	Server       ServerConfig       `koanf:"server"`
	Database     DatabaseConfig     `koanf:"database"`
	Log          LogConfig          `koanf:"log"`
	Auth         AuthConfig         `koanf:"auth"`
	Orchestrator OrchestratorConfig `koanf:"orchestrator"`
}

type AuthConfig struct {
	DevMode bool       `koanf:"devmode"`
	OIDC    OIDCConfig `koanf:"oidc"`
	JWT     JWTConfig  `koanf:"jwt"`
}

type OIDCConfig struct {
	IssuerURL    string `koanf:"issuerurl"`
	ClientID     string `koanf:"clientid"`
	ClientSecret string `koanf:"clientsecret"`
	RedirectURL  string `koanf:"redirecturl"`
}

type JWTConfig struct {
	SigningKey         string `koanf:"signingkey"`
	Issuer             string `koanf:"issuer"`
	ExpiryHours        int    `koanf:"expiryhours"`
	RefreshExpiryHours int    `koanf:"refreshexpiryhours"`
}

type ServerConfig struct {
	Host       string `koanf:"host"`
	Port       int    `koanf:"port"`
	BaseDomain string `koanf:"base_domain"`
}

type DatabaseConfig struct {
	URL            string `koanf:"url"`
	MigrationsPath string `koanf:"migrations_path"`
	MaxConns       int    `koanf:"max_conns"`
}

type LogConfig struct {
	Level  string `koanf:"level"`
	Format string `koanf:"format"`
}

type OrchestratorConfig struct {
	Driver                 string            `koanf:"driver"`
	WarmPoolSize           int               `koanf:"warm_pool_size"`
	HealthIntervalSecs     int               `koanf:"health_interval_secs"`
	ReconcileIntervalSecs  int               `koanf:"reconcile_interval_secs"`
	MaxConsecutiveFailures int               `koanf:"max_consecutive_failures"`
	Firecracker            FirecrackerConfig `koanf:"firecracker"`
	Docker                 DockerConfig      `koanf:"docker"`
}

type FirecrackerConfig struct {
	KernelPath string `koanf:"kernel_path"`
	RootDrive  string `koanf:"root_drive"`
	JailerPath string `koanf:"jailer_path"`
}

type DockerConfig struct {
	Image string `koanf:"image"`
}

func Load(configPaths ...string) (*Config, error) {
	k := koanf.New(".")

	// Defaults
	_ = k.Load(confmap.Provider(map[string]any{
		"server.port":                           8080,
		"server.host":                           "0.0.0.0",
		"server.base_domain":                    "localhost",
		"database.max_conns":                    25,
		"database.migrations_path":              "migrations",
		"log.level":                             "info",
		"log.format":                            "json",
		"auth.devmode":                          false,
		"auth.jwt.issuer":                       "valinor",
		"auth.jwt.expiryhours":                  24,
		"auth.jwt.refreshexpiryhours":           168,
		"auth.oidc.redirecturl":                 "http://localhost:8080/auth/callback",
		"orchestrator.driver":                   "mock",
		"orchestrator.warm_pool_size":           2,
		"orchestrator.health_interval_secs":     10,
		"orchestrator.reconcile_interval_secs":  30,
		"orchestrator.max_consecutive_failures": 3,
		"orchestrator.docker.image":             "valinor-agent:latest",
	}, "."), nil)

	// YAML file (optional)
	for _, path := range configPaths {
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
			// Config file is optional, skip if not found
			continue
		}
	}

	// Environment variables override everything
	// VALINOR_SERVER_PORT -> server.port
	_ = k.Load(env.Provider("VALINOR_", ".", func(s string) string {
		return strings.ReplaceAll(
			strings.ToLower(strings.TrimPrefix(s, "VALINOR_")),
			"_", ".",
		)
	}), nil)

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
