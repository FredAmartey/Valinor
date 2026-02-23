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
	Proxy        ProxyConfig        `koanf:"proxy"`
	Sentinel     SentinelConfig     `koanf:"sentinel"`
	Audit        AuditConfig        `koanf:"audit"`
	Channels     ChannelsConfig     `koanf:"channels"`
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
	KernelPath string       `koanf:"kernel_path"`
	RootDrive  string       `koanf:"root_drive"`
	JailerPath string       `koanf:"jailer_path"`
	Jailer     JailerConfig `koanf:"jailer"`
}

type JailerConfig struct {
	Enabled       bool   `koanf:"enabled"`
	BinaryPath    string `koanf:"binary_path"`
	ChrootBaseDir string `koanf:"chroot_base_dir"`
	UID           int    `koanf:"uid"`
	GID           int    `koanf:"gid"`
	NetNSPath     string `koanf:"netns_path"`
	Daemonize     bool   `koanf:"daemonize"`
}

type DockerConfig struct {
	Image string `koanf:"image"`
}

type ProxyConfig struct {
	Transport      string `koanf:"transport"`       // "tcp" or "vsock"
	TCPBasePort    int    `koanf:"tcp_base_port"`   // base port for TCP transport (dev)
	MessageTimeout int    `koanf:"message_timeout"` // seconds, default 60
	ConfigTimeout  int    `koanf:"config_timeout"`  // seconds, default 5
	PingTimeout    int    `koanf:"ping_timeout"`    // seconds, default 3
}

// SentinelConfig configures the input sentinel scanner.
type SentinelConfig struct {
	Enabled        bool    `koanf:"enabled"`
	LLMEnabled     bool    `koanf:"llm_enabled"`
	AnthropicKey   string  `koanf:"anthropic_key"`
	BlockThreshold float64 `koanf:"block_threshold"`
}

// AuditConfig configures the async audit logger.
type AuditConfig struct {
	BufferSize    int `koanf:"buffer_size"`
	BatchSize     int `koanf:"batch_size"`
	FlushInterval int `koanf:"flush_interval_ms"`
}

// ChannelsConfig configures inbound messaging channel controls.
type ChannelsConfig struct {
	Ingress   ChannelsIngressConfig   `koanf:"ingress"`
	Providers ChannelsProvidersConfig `koanf:"providers"`
	Outbox    ChannelsOutboxConfig    `koanf:"outbox"`
}

// ChannelsIngressConfig controls global channel ingress behavior.
type ChannelsIngressConfig struct {
	Enabled             bool `koanf:"enabled"`
	ReplayWindowSeconds int  `koanf:"replaywindowseconds"`
}

// ChannelsProvidersConfig controls per-provider channel settings.
type ChannelsProvidersConfig struct {
	Slack    ChannelProviderConfig `koanf:"slack"`
	WhatsApp ChannelProviderConfig `koanf:"whatsapp"`
	Telegram ChannelProviderConfig `koanf:"telegram"`
}

// ChannelProviderConfig stores provider enablement, verification secrets, and outbound API settings.
type ChannelProviderConfig struct {
	Enabled       bool   `koanf:"enabled"`
	SigningSecret string `koanf:"signingsecret"`
	SecretToken   string `koanf:"secrettoken"`
	APIBaseURL    string `koanf:"apibaseurl"`
	APIVersion    string `koanf:"apiversion"`
	AccessToken   string `koanf:"accesstoken"`
	PhoneNumberID string `koanf:"phonenumberid"`
}

// ChannelsOutboxConfig controls background outbox worker behavior.
type ChannelsOutboxConfig struct {
	Enabled             bool    `koanf:"enabled"`
	PollIntervalSeconds int     `koanf:"pollintervalseconds"`
	ClaimBatchSize      int     `koanf:"claimbatchsize"`
	RecoveryBatchSize   int     `koanf:"recoverybatchsize"`
	LockTimeoutSeconds  int     `koanf:"locktimeoutseconds"`
	MaxAttempts         int     `koanf:"maxattempts"`
	BaseRetrySeconds    int     `koanf:"baseretryseconds"`
	MaxRetrySeconds     int     `koanf:"maxretryseconds"`
	JitterFraction      float64 `koanf:"jitterfraction"`
}

func Load(configPaths ...string) (*Config, error) {
	k := koanf.New(".")

	// Defaults
	_ = k.Load(confmap.Provider(map[string]any{
		"server.port":                               8080,
		"server.host":                               "0.0.0.0",
		"server.base_domain":                        "localhost",
		"database.max_conns":                        25,
		"database.migrations_path":                  "migrations",
		"log.level":                                 "info",
		"log.format":                                "json",
		"auth.devmode":                              false,
		"auth.jwt.issuer":                           "valinor",
		"auth.jwt.expiryhours":                      24,
		"auth.jwt.refreshexpiryhours":               168,
		"auth.oidc.redirecturl":                     "http://localhost:8080/auth/callback",
		"orchestrator.driver":                       "mock",
		"orchestrator.warm_pool_size":               2,
		"orchestrator.health_interval_secs":         10,
		"orchestrator.reconcile_interval_secs":      30,
		"orchestrator.max_consecutive_failures":     3,
		"orchestrator.docker.image":                 "valinor-agent:latest",
		"orchestrator.firecracker.jailer.enabled":   false,
		"orchestrator.firecracker.jailer.daemonize": false,
		"proxy.transport":                           "tcp",
		"proxy.tcp_base_port":                       9100,
		"proxy.message_timeout":                     60,
		"proxy.config_timeout":                      5,
		"proxy.ping_timeout":                        3,
		"sentinel.enabled":                          true,
		"sentinel.llm_enabled":                      false,
		"sentinel.block_threshold":                  0.85,
		"audit.buffer_size":                         4096,
		"audit.batch_size":                          100,
		"audit.flush_interval_ms":                   500,
		"channels.ingress.enabled":                  false,
		"channels.ingress.replaywindowseconds":      86400,
		"channels.providers.slack.enabled":          false,
		"channels.providers.slack.apibaseurl":       "https://slack.com",
		"channels.providers.whatsapp.enabled":       false,
		"channels.providers.whatsapp.apibaseurl":    "https://graph.facebook.com",
		"channels.providers.whatsapp.apiversion":    "v22.0",
		"channels.providers.telegram.enabled":       false,
		"channels.providers.telegram.apibaseurl":    "https://api.telegram.org",
		"channels.outbox.enabled":                   true,
		"channels.outbox.pollintervalseconds":       2,
		"channels.outbox.claimbatchsize":            10,
		"channels.outbox.recoverybatchsize":         10,
		"channels.outbox.locktimeoutseconds":        30,
		"channels.outbox.maxattempts":               5,
		"channels.outbox.baseretryseconds":          5,
		"channels.outbox.maxretryseconds":           120,
		"channels.outbox.jitterfraction":            0.2,
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
