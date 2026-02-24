package orchestrator

// FirecrackerJailerConfig controls jailer-mode execution for Firecracker.
type FirecrackerJailerConfig struct {
	Enabled       bool
	BinaryPath    string
	ChrootBaseDir string
	UID           int
	GID           int
	NetNSPath     string
	Daemonize     bool
	NetworkPolicy string
	TapDevice     string
	GuestMAC      string
}
