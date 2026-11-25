package uptime

import (
	"sync"

	"github.com/TheTractorHacker/dunree/mod/info/logger"
	"github.com/TheTractorHacker/dunree/mod/wirecompat"
)

const (
	LOG_MODULE_NAME = "uptime-monitor"
)

type Record struct {
	Timestamp  int64
	ID         string
	Name       string
	URL        string
	Protocol   string
	Online     bool
	StatusCode int
	Latency    int64
}

type ProxyType string

const (
	ProxyType_Host ProxyType = "Origin Server"
	ProxyType_Vdir ProxyType = "Virtual Directory"
)

type Target struct {
	ID                string
	Name              string
	URL               string
	Protocol          string
	ProxyType         ProxyType
	SkipTlsValidation bool
	HealthCheckURI    string //Optional URI path appended to URL for the health check. If empty, "/" is used.
	HealthyStatus     string //Optional status code list that counts as up (see statusspec.go). Empty = global setting
}

type Config struct {
	Targets              []*Target
	Interval             int //Check interval for online targets in seconds (default 300)
	MaxRecordsStore      int
	OnlineStateNotify    func(upstreamIP string, isOnline bool)
	Logger               *logger.Logger
	Verbal               bool
	OfflineCheckInterval int //Check interval for offline targets in seconds (default 30)
	OfflineCheckTimeout  int //HTTP timeout for offline target checks in seconds (default 10)

	// Observer, when set, is called after every individual health check (any goroutine, may be
	// concurrent). It feeds the notification centre; it must not block.
	Observer func(target *Target, rec Record)
}

type Monitor struct {
	Config          *Config
	OnlineStatusLog map[string][]*Record
	logMutex        sync.RWMutex //Mutex for OnlineStatusLog map access

	// Separate lists for online and offline targets with dedicated tickers
	onlineTargets  []*Target
	offlineTargets []*Target
	targetMutex    sync.Mutex //Mutex for online/offline target list access
}

// Default configs
var exampleTarget = Target{
	ID:       "example",
	Name:     "Example",
	URL:      "example.com",
	Protocol: "https",
}

func defaultNotify(upstreamIP string, isOnline bool) {
	// Do nothing
}

// uptimeUserAgent is the User-Agent of uptime probes: "dunree-uptime/1.4", with the inherited token
// appended while the legacy names are on (plan row 13)
func uptimeUserAgent() string { return wirecompat.UserAgent("dunree-uptime/1.4", "zoraxy-uptime/1.4") }
