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
	Server   ServerConfig   `koanf:"server"`
	Database DatabaseConfig `koanf:"database"`
	Log      LogConfig      `koanf:"log"`
}

type ServerConfig struct {
	Port int    `koanf:"port"`
	Host string `koanf:"host"`
}

type DatabaseConfig struct {
	URL            string `koanf:"url"`
	MaxConns       int    `koanf:"max_conns"`
	MigrationsPath string `koanf:"migrations_path"`
}

type LogConfig struct {
	Level  string `koanf:"level"`
	Format string `koanf:"format"`
}

func Load(configPaths ...string) (*Config, error) {
	k := koanf.New(".")

	// Defaults
	_ = k.Load(confmap.Provider(map[string]interface{}{
		"server.port":              8080,
		"server.host":              "0.0.0.0",
		"database.max_conns":       25,
		"database.migrations_path": "migrations",
		"log.level":                "info",
		"log.format":               "json",
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
		return strings.Replace(
			strings.ToLower(strings.TrimPrefix(s, "VALINOR_")),
			"_", ".", -1,
		)
	}), nil)

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
