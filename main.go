package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	BaseDir       = "/data/adb/modules/passwall-android"
	XrayBin       = BaseDir + "/bin/xray"
	BaseConfig    = BaseDir + "/config/config.json"
	StateFile     = BaseDir + "/config/state.json"
	RuntimeConfig = "/dev/passwall-xray.json"
	AssetDir      = BaseDir + "/bin"
	LogFile       = "/data/adb/passwall-android.log"
	PidFile       = "/dev/passwall-droid.pid"
	PackagesFile  = "/data/system/packages.list"
	WebListenAddr = "0.0.0.0:9090"
	AppVersion    = "v1.2.6"

	PersistDir        = "/data/adb/passwall"
	PersistBaseConfig = PersistDir + "/config.json"
	PersistStateFile  = PersistDir + "/state.json"
)

const (
	TproxyPort  = 12345
	XrayGID     = 23333
	FwMark      = "0x01000000" // Bit 24: TPROXY route-to-lo mark
	FwMask      = "0x01000000"
	BypassMark  = 0x02000000   // Bit 25: Direct WAN bypass mark for sub updater & latency tests
	BypassHex   = "0x02000000"
	soMarkOpt   = 36           // Linux SOL_SOCKET SO_MARK
	RouteTable  = 100
	RulePref    = 100
	BlockQUIC   = true
	DisableIPv6 = true
	MaxLogBytes = 512 * 1024
)

const DefaultBaseConfigJSON = `{
  "log": {
    "loglevel": "warning"
  },
  "dns": {
    "servers": [
      {
        "address": "223.5.5.5",
        "port": 53,
        "domains": [
          "geosite:cn",
          "domain:ir",
          "geosite:ir"
        ],
        "skipFallback": false
      },
      "1.1.1.1",
      "8.8.8.8"
    ],
    "queryStrategy": "UseIPv4"
  },
  "inbounds": [
    {
      "tag": "dns-in",
      "listen": "0.0.0.0",
      "port": 1053,
      "protocol": "dokodemo-door",
      "settings": {
        "network": "tcp,udp",
        "address": "1.1.1.1",
        "port": 53
      }
    },
    {
      "tag": "tproxy-in",
      "listen": "0.0.0.0",
      "port": 12345,
      "protocol": "dokodemo-door",
      "settings": {
        "network": "tcp,udp",
        "followRedirect": true
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ],
        "routeOnly": true
      },
      "streamSettings": {
        "sockopt": {
          "tproxy": "tproxy"
        }
      }
    },
    {
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "port": 10808,
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ],
        "routeOnly": true
      }
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "YOUR_SERVER_DOMAIN_OR_IP",
            "port": 443,
            "users": [
              {
                "id": "YOUR-UUID-HERE",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "tls",
        "tlsSettings": {
          "serverName": "YOUR_SERVER_DOMAIN"
        }
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {},
      "streamSettings": {
        "sockopt": {
          "mark": 33554432,
          "domainStrategy": "UseIPv4"
        }
      }
    },
    {
      "tag": "block",
      "protocol": "blackhole"
    },
    {
      "tag": "dns-out",
      "protocol": "dns"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": []
  }
}`

var bypassCIDRsV4 = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
}

type NodeProfile struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Group     string                 `json:"group"` // "manual" or "sub"
	Protocol  string                 `json:"protocol"`
	Address   string                 `json:"address"`
	Port      int                    `json:"port"`
	LatencyMs int                    `json:"latency_ms"` // 0 = untested, -1 = timeout/error, >0 = RTT ms
	Outbound  map[string]interface{} `json:"outbound"`
}

type DNSConfig struct {
	RemoteDNS           string `json:"remote_dns"`                      // e.g. "tcp://1.1.1.1", "tcp://8.8.8.8", "https://dns.google/dns-query"
	DirectDNS           string `json:"direct_dns"`                      // e.g. "223.5.5.5", "10.202.10.202", "77.88.8.8"
	QueryStrategy       string `json:"query_strategy"`                  // Legacy/combined strategy: "UseIPv4", "UseIP", "UseIPv6"
	DirectQueryStrategy string `json:"direct_query_strategy,omitempty"` // "UseIP", "UseIPv4", "UseIPv6"
	RemoteQueryStrategy string `json:"remote_query_strategy,omitempty"` // "UseIP", "UseIPv4", "UseIPv6"
	DNSRedirect         *bool  `json:"dns_redirect,omitempty"`          // Redirect port 53 DNS and reject DoT port 853
}

func isValidQueryStrategy(s string) bool {
	switch strings.TrimSpace(s) {
	case "UseIP", "UseIPv4", "UseIPv6":
		return true
	}
	return false
}

func normalizeQueryStrategy(s, fallback string) string {
	trimmed := strings.TrimSpace(s)
	if isValidQueryStrategy(trimmed) {
		return trimmed
	}
	return fallback
}

// EffectiveDirectQueryStrategy returns the normalized direct DNS query strategy,
// falling back to legacy QueryStrategy and then UseIPv4.
func (d DNSConfig) EffectiveDirectQueryStrategy() string {
	return normalizeQueryStrategy(d.DirectQueryStrategy, normalizeQueryStrategy(d.QueryStrategy, "UseIPv4"))
}

// EffectiveRemoteQueryStrategy returns the normalized remote DNS query strategy,
// falling back to legacy QueryStrategy and then UseIPv4.
func (d DNSConfig) EffectiveRemoteQueryStrategy() string {
	return normalizeQueryStrategy(d.RemoteQueryStrategy, normalizeQueryStrategy(d.QueryStrategy, "UseIPv4"))
}

// IsDNSRedirect reports whether port 53 DNS hijacking (and DoT port 853 blocking) is enabled.
func (d DNSConfig) IsDNSRedirect() bool {
	if d.DNSRedirect == nil {
		return true
	}
	return *d.DNSRedirect
}

func combinedTopLevelQueryStrategy(directQS, remoteQS string) string {
	d := normalizeQueryStrategy(directQS, "UseIPv4")
	r := normalizeQueryStrategy(remoteQS, "UseIPv4")
	if d == r {
		return d
	}
	// Xray intersects each server's queryStrategy with top-level dns.queryStrategy;
	// UseIP keeps both IPv4 and IPv6 permitted so per-server strategies never conflict.
	return "UseIP"
}

type GeoConfig struct {
	BypassIran     *bool    `json:"bypass_iran,omitempty"`
	BypassCN       *bool    `json:"bypass_cn,omitempty"`
	BlockAds       *bool    `json:"block_ads,omitempty"`
	DomainStrategy string   `json:"domain_strategy,omitempty"` // "AsIs", "IPIfNonMatch", "IPOnDemand"
	DomainMatcher  string   `json:"domain_matcher,omitempty"`  // "hybrid", "linear"
	DirectDomains  []string `json:"direct_domains"`
	DirectIPs      []string `json:"direct_ips"`
	ProxyDomains   []string `json:"proxy_domains"`
	ProxyIPs       []string `json:"proxy_ips"`
	BlockDomains   []string `json:"block_domains"`
	BlockIPs       []string `json:"block_ips"`
	GeoIPURL       string   `json:"geoip_url"`
	GeoSiteURL     string   `json:"geosite_url"`
	LastGeoUpdate  string   `json:"last_geo_update"`
}

func isValidDomainStrategy(s string) bool {
	switch strings.TrimSpace(s) {
	case "AsIs", "IPIfNonMatch", "IPOnDemand":
		return true
	}
	return false
}

func normalizeDomainStrategy(s string) string {
	trimmed := strings.TrimSpace(s)
	if isValidDomainStrategy(trimmed) {
		return trimmed
	}
	return "IPIfNonMatch"
}

func isValidDomainMatcher(s string) bool {
	switch strings.TrimSpace(s) {
	case "hybrid", "linear":
		return true
	}
	return false
}

func normalizeDomainMatcher(s string) string {
	trimmed := strings.TrimSpace(s)
	if isValidDomainMatcher(trimmed) {
		return trimmed
	}
	return "hybrid"
}

// EffectiveDomainStrategy returns the routing domainStrategy ("AsIs", "IPIfNonMatch", or "IPOnDemand").
func (g GeoConfig) EffectiveDomainStrategy() string {
	return normalizeDomainStrategy(g.DomainStrategy)
}

// EffectiveDomainMatcher returns the routing domainMatcher ("hybrid" or "linear").
func (g GeoConfig) EffectiveDomainMatcher() string {
	return normalizeDomainMatcher(g.DomainMatcher)
}

func (g GeoConfig) IsBypassIran() bool {
	if g.BypassIran == nil {
		return true
	}
	return *g.BypassIran
}

func (g GeoConfig) IsBypassCN() bool {
	if g.BypassCN == nil {
		return true
	}
	return *g.BypassCN
}

func (g GeoConfig) IsBlockAds() bool {
	if g.BlockAds == nil {
		return true
	}
	return *g.BlockAds
}

type GeoAssetFile struct {
	Name          string `json:"name"`
	Path          string `json:"path"`
	Exists        bool   `json:"exists"`
	SizeBytes     int64  `json:"size_bytes"`
	SizeFormatted string `json:"size_formatted"`
	ModTime       string `json:"mod_time"`
}

type GeoAssetsStatus struct {
	AssetDir string       `json:"asset_dir"`
	GeoIP    GeoAssetFile `json:"geoip"`
	GeoSite  GeoAssetFile `json:"geosite"`
}

type PanelState struct {
	ProxyMode          string        `json:"proxy_mode"`        // "rule", "global", "direct"
	ActiveNode         string        `json:"active_node"`
	SubURL             string        `json:"sub_url"`
	SubInsecure        bool          `json:"sub_insecure"`      // Ignore SSL/TLS cert errors
	AutoUpdateHours    int           `json:"auto_update_hours"` // 0 = disabled
	LastSubUpdate      string        `json:"last_sub_update"`
	AppFilterMode      string        `json:"app_filter_mode"` // "bypass" or "proxy"
	SelectedUIDs       []int         `json:"selected_uids"`
	LocalhostProxy     bool          `json:"localhost_proxy"`      // Proxy local device (default true)
	AllowInsecureVless bool          `json:"allow_insecure_vless"` // Ignore Xray VLESS without TLS/encryption error via local bridge
	DNS                DNSConfig     `json:"dns"`
	Geo                GeoConfig     `json:"geo"`
	Nodes              []NodeProfile `json:"nodes"`
}

type BackupBundle struct {
	Format        string          `json:"format"`
	Version       int             `json:"version"`
	CreatedAt     string          `json:"created_at"`
	ModuleVersion string          `json:"module_version,omitempty"`
	State         *PanelState     `json:"state,omitempty"`
	Config        json.RawMessage `json:"config,omitempty"`
}

type NodeEditRequest struct {
	Action        string                 `json:"action"` // "import", "select", "delete", "edit", "update", "create", "add", "parse_uri", "export_uri"
	URI           string                 `json:"uri"`
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Protocol      string                 `json:"protocol"`
	Address       string                 `json:"address"`
	Port          int                    `json:"port"`
	UUID          string                 `json:"uuid"`
	Flow          string                 `json:"flow"`
	Encryption    string                 `json:"encryption"`
	AlterID       int                    `json:"alter_id"`
	VmessSecurity string                 `json:"vmess_security"`
	Password      string                 `json:"password"`
	SSMethod      string                 `json:"ss_method"`
	Network       string                 `json:"network"`
	Host          string                 `json:"host"`
	Path          string                 `json:"path"`
	XhttpMode     string                 `json:"xhttp_mode"`
	ServiceName   string                 `json:"service_name"`
	GrpcMultiMode bool                   `json:"grpc_multi_mode"`
	GrpcAuthority string                 `json:"grpc_authority"`
	TcpHeaderType string                 `json:"tcp_header_type"`
	KcpHeaderType string                 `json:"kcp_header_type"`
	KcpSeed       string                 `json:"kcp_seed"`
	Security      string                 `json:"security"`
	SNI           string                 `json:"sni"`
	Fingerprint   string                 `json:"fp"`
	ALPN          string                 `json:"alpn"`
	AllowInsecure *bool                  `json:"allow_insecure,omitempty"`
	PinnedSha256  string                 `json:"pinned_sha256"`
	RealityPBK    string                 `json:"pbk"`
	RealitySID    string                 `json:"sid"`
	RealitySPX    string                 `json:"spx"`
	HyUp          string                 `json:"hy_up"`
	HyDown        string                 `json:"hy_down"`
	HyObfsType            string                 `json:"obfs_type"`
	HyObfsPass            string                 `json:"obfs_password"`
	SockoptDomainStrategy *string                `json:"sockopt_domain_strategy,omitempty"`
	Activate              bool                   `json:"activate"`
	FullEdit              bool                   `json:"full_edit"`
	Outbound              map[string]interface{} `json:"outbound,omitempty"`
}

type TargetStatus struct {
	Reachable bool   `json:"reachable"`
	LatencyMs int    `json:"latency_ms"`
	Status    string `json:"status,omitempty"`
}

type ConnectivityStatus struct {
	Google TargetStatus `json:"google"`
	Github TargetStatus `json:"github"`
}

type AndroidApp struct {
	Package string `json:"package"`
	UID     int    `json:"uid"`
}

type CappedLogWriter struct {
	mu   sync.Mutex
	path string
}

func (w *CappedLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if info, err := os.Stat(w.path); err == nil && info.Size() > MaxLogBytes {
		if data, readErr := os.ReadFile(w.path); readErr == nil && len(data) > MaxLogBytes/2 {
			_ = os.WriteFile(w.path, data[len(data)-MaxLogBytes/2:], 0644)
		}
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.Write(p)
}

var (
	logSink                = &CappedLogWriter{path: LogFile}
	stateMu                sync.Mutex
	engineMu               sync.Mutex
	engineActive           bool
	useTproxy              bool
	xrayStopCh             chan struct{}
	xrayDoneCh             chan struct{}
	portHopRe              = regexp.MustCompile(`:(\d+)[-,][0-9,-]*([/?#].*|$)`)
	dotlessPrivateDomainRe = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %v (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runCmdIgnoreErr(name string, args ...string) {
	_ = exec.Command(name, args...).Run()
}

func writeSysctl(path, val string) {
	if data, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(data)) == strings.TrimSpace(val) {
		return
	}
	_ = os.WriteFile(path, []byte(val), 0644)
}

var (
	xrayVerMu         sync.Mutex
	cachedXrayVer     string
	modVerMu          sync.Mutex
	cachedModVer      string
	lastModPropPath   string
	lastModPropTime   time.Time
	lastModPropAppVer string
	xrayPidMu         sync.Mutex
	xrayPid           int
)

func setXrayPID(pid int) {
	xrayPidMu.Lock()
	xrayPid = pid
	xrayPidMu.Unlock()
}

func getXrayPID() int {
	xrayPidMu.Lock()
	defer xrayPidMu.Unlock()
	return xrayPid
}

func getModuleVersion() string {
	modVerMu.Lock()
	defer modVerMu.Unlock()

	propFile := filepath.Join(BaseDir, "module.prop")
	stat, err := os.Stat(propFile)

	if cachedModVer != "" && lastModPropPath == propFile && lastModPropAppVer == AppVersion {
		if (err != nil && lastModPropTime.IsZero()) || (err == nil && stat.ModTime().Equal(lastModPropTime)) {
			return cachedModVer
		}
	}

	lastModPropPath = propFile
	lastModPropAppVer = AppVersion
	if err == nil {
		lastModPropTime = stat.ModTime()
		if data, err := os.ReadFile(propFile); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "version=") {
					ver := strings.TrimPrefix(line, "version=")
					if ver != "" {
						cachedModVer = ver
						return cachedModVer
					}
				}
			}
		}
	} else {
		lastModPropTime = time.Time{}
	}

	if AppVersion != "" {
		cachedModVer = AppVersion
		return cachedModVer
	}
	cachedModVer = "v1.2.1"
	return cachedModVer
}

func invalidateModuleVersion() {
	modVerMu.Lock()
	cachedModVer = ""
	lastModPropTime = time.Time{}
	modVerMu.Unlock()
}

func getBatteryStatus() (int, string) {
	paths := []string{
		"/sys/class/power_supply/battery",
		"/sys/class/power_supply/bms",
	}
	if matches, err := filepath.Glob("/sys/class/power_supply/*"); err == nil {
		for _, m := range matches {
			found := false
			for _, p := range paths {
				if p == m {
					found = true
					break
				}
			}
			if !found {
				paths = append(paths, m)
			}
		}
	}

	for _, p := range paths {
		capFile := filepath.Join(p, "capacity")
		if data, err := os.ReadFile(capFile); err == nil {
			trimmed := strings.TrimSpace(string(data))
			if val, err := strconv.Atoi(trimmed); err == nil && val >= 0 && val <= 100 {
				status := ""
				if statData, err := os.ReadFile(filepath.Join(p, "status")); err == nil {
					status = strings.TrimSpace(string(statData))
				}
				return val, status
			}
		}
	}
	return -1, ""
}

func getProcessRAM(pid int) (int64, string) {
	if pid <= 0 {
		return 0, "0 B"
	}
	statmPath := fmt.Sprintf("/proc/%d/statm", pid)
	if data, err := os.ReadFile(statmPath); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 2 {
			if pages, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				b := pages * int64(os.Getpagesize())
				return b, formatBytes(b)
			}
		}
	}
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	if data, err := os.ReadFile(statusPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "VmRSS:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
						b := kb * 1024
						return b, formatBytes(b)
					}
				}
			}
		}
	}
	return 0, "0 B"
}

type procCPUSample struct {
	utime uint64
	stime uint64
	sys   uint64
	time  time.Time
}

var (
	cpuSampleMu    sync.Mutex
	lastCPUSamples = make(map[int]procCPUSample)
)

func getProcessCPU(pid int) float64 {
	if pid <= 0 {
		return 0.0
	}
	statData, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0.0
	}
	statStr := string(statData)
	lastRP := strings.LastIndex(statStr, ")")
	if lastRP == -1 || lastRP+2 >= len(statStr) {
		return 0.0
	}
	fields := strings.Fields(statStr[lastRP+2:])
	if len(fields) < 13 {
		return 0.0
	}
	utime, err1 := strconv.ParseUint(fields[11], 10, 64)
	stime, err2 := strconv.ParseUint(fields[12], 10, 64)
	if err1 != nil || err2 != nil {
		return 0.0
	}

	var totalSys uint64
	if sysData, err := os.ReadFile("/proc/stat"); err == nil {
		lines := strings.Split(string(sysData), "\n")
		for _, l := range lines {
			if strings.HasPrefix(l, "cpu ") {
				nums := strings.Fields(l)[1:]
				for _, nStr := range nums {
					if nVal, err := strconv.ParseUint(nStr, 10, 64); err == nil {
						totalSys += nVal
					}
				}
				break
			}
		}
	}

	now := time.Now()
	cpuSampleMu.Lock()
	defer cpuSampleMu.Unlock()

	prev, exists := lastCPUSamples[pid]
	lastCPUSamples[pid] = procCPUSample{
		utime: utime,
		stime: stime,
		sys:   totalSys,
		time:  now,
	}

	if !exists {
		return 0.0
	}

	procDelta := float64((utime + stime) - (prev.utime + prev.stime))
	if procDelta < 0 {
		procDelta = 0
	}

	if totalSys > prev.sys && prev.sys > 0 {
		sysDelta := float64(totalSys - prev.sys)
		if sysDelta > 0 {
			pct := (procDelta / sysDelta) * 100.0
			return math.Round(pct*10) / 10
		}
	}

	elapsed := now.Sub(prev.time).Seconds()
	if elapsed > 0.1 {
		pct := (procDelta / 100.0 / elapsed) * 100.0
		if pct > 100.0 {
			pct = 100.0
		}
		return math.Round(pct*10) / 10
	}

	return 0.0
}

func deepCloneValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		return deepCloneMap(val)
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, item := range val {
			out[i] = deepCloneValue(item)
		}
		return out
	case []string:
		out := make([]string, len(val))
		copy(out, val)
		return out
	default:
		return val
	}
}

func deepCloneMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = deepCloneValue(v)
	}
	return out
}

func jsonIntValue(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		p, _ := strconv.Atoi(strings.TrimSpace(n))
		return p
	default:
		return 0
	}
}

// isPrivateOrLocalAddress mirrors Xray-core's requiresTransportSecurity check:
// returns true if addr is a private/loopback/link-local IP or a recognized private/local domain.
func isPrivateOrLocalAddress(addr string) bool {
	clean := strings.TrimSpace(addr)
	clean = strings.TrimPrefix(clean, "[")
	clean = strings.TrimSuffix(clean, "]")
	if clean == "" {
		return false
	}
	if ip := net.ParseIP(clean); ip != nil {
		return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
	}
	domain := strings.TrimSuffix(strings.ToLower(clean), ".")
	if domain == "" {
		return false
	}
	privateSuffixes := []string{
		"lan", "localdomain", "example", "invalid",
		"localhost", "test", "local", "home.arpa", "internal",
	}
	for _, s := range privateSuffixes {
		if domain == s || strings.HasSuffix(domain, "."+s) {
			return true
		}
	}
	if !strings.Contains(domain, ".") && dotlessPrivateDomainRe.MatchString(domain) {
		return true
	}
	return false
}

// vlessOutboundNeedsSecurityBypass reports whether an outbound triggers Xray-core's
// "vless without TLS or other encryption is prohibited unless the server address is a private IP or domain" check.
func vlessOutboundNeedsSecurityBypass(ob map[string]interface{}) (checkAddr string, dialAddr string, dialPort int, needs bool) {
	if ob == nil {
		return "", "", 0, false
	}
	proto, _ := ob["protocol"].(string)
	if !strings.EqualFold(strings.TrimSpace(proto), "vless") {
		return "", "", 0, false
	}

	ss, _ := ob["streamSettings"].(map[string]interface{})
	if ss != nil {
		sec, _ := ss["security"].(string)
		secLower := strings.ToLower(strings.TrimSpace(sec))
		if secLower != "" && secLower != "none" {
			return "", "", 0, false
		}
	}

	settings, _ := ob["settings"].(map[string]interface{})
	if settings == nil {
		return "", "", 0, false
	}

	var addr, enc string
	var port int
	if vnext, ok := settings["vnext"].([]interface{}); ok && len(vnext) > 0 {
		if vObj, ok := vnext[0].(map[string]interface{}); ok {
			addr, _ = vObj["address"].(string)
			port = jsonIntValue(vObj["port"])
			if users, ok := vObj["users"].([]interface{}); ok && len(users) > 0 {
				if uObj, ok := users[0].(map[string]interface{}); ok {
					enc, _ = uObj["encryption"].(string)
				}
			}
		}
	} else {
		addr, _ = settings["address"].(string)
		port = jsonIntValue(settings["port"])
		enc, _ = settings["encryption"].(string)
	}

	addr = strings.TrimSpace(addr)
	if addr == "" || port <= 0 {
		return "", "", 0, false
	}
	encLower := strings.ToLower(strings.TrimSpace(enc))
	if encLower != "" && encLower != "none" {
		return "", "", 0, false
	}
	if isPrivateOrLocalAddress(addr) {
		return "", "", 0, false
	}

	dialAddr = addr
	dialPort = port
	if ss != nil {
		if ssAddr, _ := ss["address"].(string); strings.TrimSpace(ssAddr) != "" {
			dialAddr = strings.TrimSpace(ssAddr)
		}
		if ssPort := jsonIntValue(ss["port"]); ssPort > 0 {
			dialPort = ssPort
		}
	}
	return addr, dialAddr, dialPort, true
}

func activeNodeNeedsVlessSecurityBypass(st PanelState) bool {
	if st.ActiveNode == "" {
		return false
	}
	for _, n := range st.Nodes {
		if n.ID == st.ActiveNode {
			_, _, _, needs := vlessOutboundNeedsSecurityBypass(n.Outbound)
			return needs
		}
	}
	return false
}

func preserveVlessTransportHost(ob map[string]interface{}, origHost string) {
	if ob == nil || strings.TrimSpace(origHost) == "" {
		return
	}
	ss, _ := ob["streamSettings"].(map[string]interface{})
	if ss == nil {
		return
	}
	netName, _ := ss["network"].(string)
	switch strings.ToLower(strings.TrimSpace(netName)) {
	case "ws", "websocket":
		ws, _ := ss["wsSettings"].(map[string]interface{})
		if ws == nil {
			ws = map[string]interface{}{}
			ss["wsSettings"] = ws
		}
		curHost, _ := ws["host"].(string)
		headers, _ := ws["headers"].(map[string]interface{})
		hdrHost := ""
		if headers != nil {
			hdrHost, _ = headers["Host"].(string)
		}
		if strings.TrimSpace(curHost) == "" && strings.TrimSpace(hdrHost) == "" {
			ws["host"] = origHost
		}
	case "xhttp", "splithttp":
		key := "xhttpSettings"
		xh, _ := ss[key].(map[string]interface{})
		if xh == nil {
			if sh, ok := ss["splithttpSettings"].(map[string]interface{}); ok && sh != nil {
				key = "splithttpSettings"
				xh = sh
			} else {
				xh = map[string]interface{}{}
				ss[key] = xh
			}
		}
		if curHost, _ := xh["host"].(string); strings.TrimSpace(curHost) == "" {
			xh["host"] = origHost
		}
	case "httpupgrade":
		hu, _ := ss["httpupgradeSettings"].(map[string]interface{})
		if hu == nil {
			hu = map[string]interface{}{}
			ss["httpupgradeSettings"] = hu
		}
		if curHost, _ := hu["host"].(string); strings.TrimSpace(curHost) == "" {
			hu["host"] = origHost
		}
	case "grpc":
		if net.ParseIP(origHost) == nil {
			gs, _ := ss["grpcSettings"].(map[string]interface{})
			if gs == nil {
				gs = map[string]interface{}{}
				ss["grpcSettings"] = gs
			}
			if auth, _ := gs["authority"].(string); strings.TrimSpace(auth) == "" {
				gs["authority"] = origHost
			}
		}
	}
}

func rewriteVlessOutboundTarget(ob map[string]interface{}, newAddr string, newPort int) {
	if ob == nil {
		return
	}
	if settings, ok := ob["settings"].(map[string]interface{}); ok && settings != nil {
		if vnext, ok := settings["vnext"].([]interface{}); ok && len(vnext) > 0 {
			if vObj, ok := vnext[0].(map[string]interface{}); ok {
				vObj["address"] = newAddr
				vObj["port"] = newPort
			}
		} else if _, hasAddr := settings["address"]; hasAddr {
			settings["address"] = newAddr
			settings["port"] = newPort
		}
	}
	if ss, ok := ob["streamSettings"].(map[string]interface{}); ok && ss != nil {
		delete(ss, "address")
		delete(ss, "port")
	}
}

func allocateFreeLoopbackPort(start int, used map[int]bool) int {
	for p := start; p < 65000; p++ {
		if used[p] {
			continue
		}
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			continue
		}
		_ = ln.Close()
		pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			continue
		}
		_ = pc.Close()
		return p
	}
	return start
}

func normalizeNodeProtocol(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "hy2", "hysteria", "hysteria2":
		return "hysteria2"
	case "ss", "shadowsocks":
		return "shadowsocks"
	case "vless":
		return "vless"
	case "vmess":
		return "vmess"
	case "trojan":
		return "trojan"
	default:
		return strings.ToLower(strings.TrimSpace(p))
	}
}

func outboundProtocolForNode(p string) string {
	norm := normalizeNodeProtocol(p)
	if norm == "hysteria2" {
		return "hysteria"
	}
	return norm
}

func syncNodeProfileFromOutbound(node *NodeProfile) {
	if node == nil || node.Outbound == nil {
		return
	}
	if proto, _ := node.Outbound["protocol"].(string); proto != "" {
		node.Protocol = normalizeNodeProtocol(proto)
	}
	if settings, ok := node.Outbound["settings"].(map[string]interface{}); ok && settings != nil {
		if vnext, ok := settings["vnext"].([]interface{}); ok && len(vnext) > 0 {
			if vObj, ok := vnext[0].(map[string]interface{}); ok {
				if addr, _ := vObj["address"].(string); addr != "" {
					node.Address = addr
				}
				if port := jsonIntValue(vObj["port"]); port > 0 {
					node.Port = port
				}
				return
			}
		}
		if servers, ok := settings["servers"].([]interface{}); ok && len(servers) > 0 {
			if sObj, ok := servers[0].(map[string]interface{}); ok {
				if addr, _ := sObj["address"].(string); addr != "" {
					node.Address = addr
				}
				if port := jsonIntValue(sObj["port"]); port > 0 {
					node.Port = port
				}
				return
			}
		}
		if addr, _ := settings["address"].(string); addr != "" {
			node.Address = addr
		}
		if port := jsonIntValue(settings["port"]); port > 0 {
			node.Port = port
		}
	}
}

func parseALPNList(raw string) []interface{} {
	var out []interface{}
	for _, part := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func applyNodeEditRequest(node *NodeProfile, req NodeEditRequest) error {
	proto := normalizeNodeProtocol(req.Protocol)
	if proto == "" {
		proto = normalizeNodeProtocol(node.Protocol)
	}
	switch proto {
	case "vless", "vmess", "trojan", "shadowsocks", "hysteria2":
	default:
		return fmt.Errorf("unsupported protocol %q", proto)
	}

	addr := strings.TrimSpace(req.Address)
	if addr == "" {
		addr = strings.TrimSpace(node.Address)
	}
	if addr == "" {
		return fmt.Errorf("server address cannot be empty")
	}

	port := req.Port
	if port <= 0 {
		port = node.Port
	}
	if port <= 0 || port > 65535 {
		if proto == "shadowsocks" && port == 0 {
			port = 8388
		} else if port == 0 {
			port = 443
		} else {
			return fmt.Errorf("port must be between 1 and 65535")
		}
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		if strings.TrimSpace(node.Name) != "" {
			name = strings.TrimSpace(node.Name)
		} else {
			name = fmt.Sprintf("%s-%s:%d", proto, addr, port)
		}
	}

	node.Name = name
	node.Protocol = proto
	node.Address = addr
	node.Port = port

	var ob map[string]interface{}
	if node.Outbound != nil && strings.EqualFold(outboundProtocolForNode(proto), fmt.Sprintf("%v", node.Outbound["protocol"])) {
		ob = deepCloneMap(node.Outbound)
	} else {
		ob = map[string]interface{}{}
	}
	ob["tag"] = "proxy"
	ob["protocol"] = outboundProtocolForNode(proto)

	settings, _ := ob["settings"].(map[string]interface{})
	if settings == nil {
		settings = map[string]interface{}{}
	}

	switch proto {
	case "vless":
		delete(settings, "servers")
		delete(settings, "address")
		delete(settings, "port")
		delete(settings, "id")
		delete(settings, "encryption")
		delete(settings, "flow")
		delete(settings, "version")

		var vObj map[string]interface{}
		if vnext, ok := settings["vnext"].([]interface{}); ok && len(vnext) > 0 {
			vObj, _ = vnext[0].(map[string]interface{})
		}
		if vObj == nil {
			vObj = map[string]interface{}{}
		}
		var uObj map[string]interface{}
		if users, ok := vObj["users"].([]interface{}); ok && len(users) > 0 {
			uObj, _ = users[0].(map[string]interface{})
		}
		if uObj == nil {
			uObj = map[string]interface{}{}
		}
		uuidVal := strings.TrimSpace(req.UUID)
		if uuidVal == "" {
			uuidVal, _ = uObj["id"].(string)
		}
		if uuidVal == "" {
			return fmt.Errorf("VLESS UUID is required")
		}
		uObj["id"] = uuidVal
		enc := strings.TrimSpace(req.Encryption)
		if enc == "" {
			enc = "none"
		}
		uObj["encryption"] = enc
		if flow := strings.TrimSpace(req.Flow); flow != "" {
			uObj["flow"] = flow
		} else {
			delete(uObj, "flow")
		}
		vObj["address"] = addr
		vObj["port"] = port
		vObj["users"] = []interface{}{uObj}
		settings["vnext"] = []interface{}{vObj}

	case "vmess":
		delete(settings, "servers")
		delete(settings, "address")
		delete(settings, "port")
		delete(settings, "version")

		var vObj map[string]interface{}
		if vnext, ok := settings["vnext"].([]interface{}); ok && len(vnext) > 0 {
			vObj, _ = vnext[0].(map[string]interface{})
		}
		if vObj == nil {
			vObj = map[string]interface{}{}
		}
		var uObj map[string]interface{}
		if users, ok := vObj["users"].([]interface{}); ok && len(users) > 0 {
			uObj, _ = users[0].(map[string]interface{})
		}
		if uObj == nil {
			uObj = map[string]interface{}{}
		}
		uuidVal := strings.TrimSpace(req.UUID)
		if uuidVal == "" {
			uuidVal, _ = uObj["id"].(string)
		}
		if uuidVal == "" {
			return fmt.Errorf("VMess UUID is required")
		}
		uObj["id"] = uuidVal
		aid := req.AlterID
		if aid < 0 {
			aid = 0
		}
		uObj["alterId"] = aid
		vmSec := strings.TrimSpace(req.VmessSecurity)
		if vmSec == "" {
			vmSec = "auto"
		}
		uObj["security"] = vmSec
		vObj["address"] = addr
		vObj["port"] = port
		vObj["users"] = []interface{}{uObj}
		settings["vnext"] = []interface{}{vObj}

	case "trojan":
		delete(settings, "vnext")
		delete(settings, "address")
		delete(settings, "port")
		delete(settings, "version")

		var sObj map[string]interface{}
		if servers, ok := settings["servers"].([]interface{}); ok && len(servers) > 0 {
			sObj, _ = servers[0].(map[string]interface{})
		}
		if sObj == nil {
			sObj = map[string]interface{}{}
		}
		pw := req.Password
		if pw == "" {
			pw, _ = sObj["password"].(string)
		}
		if pw == "" {
			return fmt.Errorf("Trojan password is required")
		}
		delete(sObj, "method")
		sObj["address"] = addr
		sObj["port"] = port
		sObj["password"] = pw
		settings["servers"] = []interface{}{sObj}

	case "shadowsocks":
		delete(settings, "vnext")
		delete(settings, "address")
		delete(settings, "port")
		delete(settings, "version")

		var sObj map[string]interface{}
		if servers, ok := settings["servers"].([]interface{}); ok && len(servers) > 0 {
			sObj, _ = servers[0].(map[string]interface{})
		}
		if sObj == nil {
			sObj = map[string]interface{}{}
		}
		method := strings.TrimSpace(req.SSMethod)
		if method == "" {
			method, _ = sObj["method"].(string)
		}
		if method == "" {
			method = "aes-256-gcm"
		}
		pw := req.Password
		if pw == "" && req.SSMethod == "" {
			pw, _ = sObj["password"].(string)
		}
		sObj["address"] = addr
		sObj["port"] = port
		sObj["method"] = method
		sObj["password"] = pw
		settings["servers"] = []interface{}{sObj}

	case "hysteria2":
		delete(settings, "vnext")
		delete(settings, "servers")
		settings["version"] = 2
		settings["address"] = addr
		settings["port"] = port
	}
	ob["settings"] = settings

	ss, _ := ob["streamSettings"].(map[string]interface{})
	if ss == nil {
		ss = map[string]interface{}{}
	}

	if proto == "hysteria2" {
		for _, k := range []string{"wsSettings", "xhttpSettings", "splithttpSettings", "httpupgradeSettings", "grpcSettings", "kcpSettings", "tcpSettings", "realitySettings"} {
			delete(ss, k)
		}
		ss["network"] = "hysteria"
		ss["security"] = "tls"

		hySet, _ := ss["hysteriaSettings"].(map[string]interface{})
		if hySet == nil {
			hySet = map[string]interface{}{}
		}
		hySet["version"] = 2
		hySet["auth"] = req.Password
		if jsonIntValue(hySet["udpIdleTimeout"]) <= 0 {
			hySet["udpIdleTimeout"] = 60
		}
		if up := strings.TrimSpace(req.HyUp); up != "" {
			if !strings.Contains(up, " ") {
				up += " mbps"
			}
			hySet["up"] = up
		} else {
			delete(hySet, "up")
		}
		if down := strings.TrimSpace(req.HyDown); down != "" {
			if !strings.Contains(down, " ") {
				down += " mbps"
			}
			hySet["down"] = down
		} else {
			delete(hySet, "down")
		}
		ss["hysteriaSettings"] = hySet

		obfsType := strings.TrimSpace(req.HyObfsType)
		obfsPass := req.HyObfsPass
		if obfsType != "" && obfsPass != "" {
			maskObj := []interface{}{
				map[string]interface{}{
					"type": obfsType,
					"settings": map[string]interface{}{
						"password": obfsPass,
					},
				},
			}
			ss["finalmask"] = map[string]interface{}{"udp": maskObj}
			ss["udpmasks"] = maskObj
		} else {
			delete(ss, "finalmask")
			delete(ss, "udpmasks")
		}

		tlsSet, _ := ss["tlsSettings"].(map[string]interface{})
		if tlsSet == nil {
			tlsSet = map[string]interface{}{}
		}
		sni := strings.TrimSpace(req.SNI)
		if sni == "" {
			sni = addr
		}
		tlsSet["serverName"] = sni
		fp := strings.TrimSpace(req.Fingerprint)
		if fp == "" {
			fp = "chrome"
		}
		tlsSet["fingerprint"] = fp
		alpnList := parseALPNList(req.ALPN)
		if len(alpnList) == 0 {
			alpnList = []interface{}{"h3"}
		}
		tlsSet["alpn"] = alpnList
		if req.AllowInsecure != nil {
			tlsSet["allowInsecure"] = *req.AllowInsecure
		} else {
			tlsSet["allowInsecure"] = false
		}
		if pin := strings.TrimSpace(req.PinnedSha256); pin != "" {
			tlsSet["pinnedPeerCertificateSha256"] = pin
		} else {
			delete(tlsSet, "pinnedPeerCertificateSha256")
		}
		ss["tlsSettings"] = tlsSet
		ob["streamSettings"] = ss
	} else {
		delete(ss, "hysteriaSettings")
		delete(ss, "finalmask")
		delete(ss, "udpmasks")

		netType := strings.ToLower(strings.TrimSpace(req.Network))
		if netType == "splithttp" {
			netType = "xhttp"
		}
		sec := strings.ToLower(strings.TrimSpace(req.Security))

		if proto == "shadowsocks" && (netType == "" || netType == "tcp") && (sec == "" || sec == "none") && strings.TrimSpace(req.TcpHeaderType) != "http" {
			delete(ob, "streamSettings")
		} else {
			if netType == "" {
				netType = "tcp"
			}
			ss["network"] = netType

			for _, k := range []string{"wsSettings", "xhttpSettings", "splithttpSettings", "httpupgradeSettings", "grpcSettings", "kcpSettings", "tcpSettings"} {
				if (netType == "ws" && k == "wsSettings") ||
					(netType == "xhttp" && k == "xhttpSettings") ||
					(netType == "httpupgrade" && k == "httpupgradeSettings") ||
					(netType == "grpc" && k == "grpcSettings") ||
					(netType == "kcp" && k == "kcpSettings") ||
					((netType == "tcp" || netType == "raw") && k == "tcpSettings") {
					continue
				}
				delete(ss, k)
			}

			path := strings.TrimSpace(req.Path)
			host := strings.TrimSpace(req.Host)

			switch netType {
			case "tcp", "raw":
				if strings.ToLower(strings.TrimSpace(req.TcpHeaderType)) == "http" {
					if path == "" {
						path = "/"
					}
					reqHdr := map[string]interface{}{
						"version": "1.1",
						"method":  "GET",
						"path":    []interface{}{path},
					}
					if host != "" {
						reqHdr["headers"] = map[string]interface{}{
							"Host": []interface{}{host},
						}
					}
					ss["tcpSettings"] = map[string]interface{}{
						"header": map[string]interface{}{
							"type":    "http",
							"request": reqHdr,
						},
					}
				} else {
					delete(ss, "tcpSettings")
				}
			case "ws":
				if path == "" {
					path = "/"
				}
				ws := map[string]interface{}{"path": path}
				if host != "" {
					ws["host"] = host
					ws["headers"] = map[string]interface{}{"Host": host}
				}
				ss["wsSettings"] = ws
			case "xhttp":
				if path == "" {
					path = "/"
				}
				xh, _ := ss["xhttpSettings"].(map[string]interface{})
				if xh == nil {
					xh = map[string]interface{}{}
				}
				xh["path"] = path
				if host != "" {
					xh["host"] = host
				} else {
					delete(xh, "host")
				}
				if mode := strings.TrimSpace(req.XhttpMode); mode != "" {
					xh["mode"] = mode
				} else {
					delete(xh, "mode")
				}
				ss["xhttpSettings"] = xh
			case "httpupgrade":
				if path == "" {
					path = "/"
				}
				hu := map[string]interface{}{"path": path}
				if host != "" {
					hu["host"] = host
				}
				ss["httpupgradeSettings"] = hu
			case "grpc":
				gs := map[string]interface{}{
					"serviceName": strings.TrimSpace(req.ServiceName),
				}
				if req.GrpcMultiMode {
					gs["multiMode"] = true
				}
				if auth := strings.TrimSpace(req.GrpcAuthority); auth != "" {
					gs["authority"] = auth
				}
				ss["grpcSettings"] = gs
			case "kcp":
				ks := map[string]interface{}{}
				hdrType := strings.TrimSpace(req.KcpHeaderType)
				if hdrType != "" && hdrType != "none" {
					ks["header"] = map[string]interface{}{"type": hdrType}
				}
				if seed := strings.TrimSpace(req.KcpSeed); seed != "" {
					ks["seed"] = seed
				}
				ss["kcpSettings"] = ks
			}

			switch sec {
			case "tls":
				ss["security"] = "tls"
				delete(ss, "realitySettings")
				tlsSet, _ := ss["tlsSettings"].(map[string]interface{})
				if tlsSet == nil {
					tlsSet = map[string]interface{}{}
				}
				if sni := strings.TrimSpace(req.SNI); sni != "" {
					tlsSet["serverName"] = sni
				} else {
					delete(tlsSet, "serverName")
				}
				if fp := strings.TrimSpace(req.Fingerprint); fp != "" {
					tlsSet["fingerprint"] = fp
				} else {
					delete(tlsSet, "fingerprint")
				}
				if alpn := parseALPNList(req.ALPN); len(alpn) > 0 {
					tlsSet["alpn"] = alpn
				} else {
					delete(tlsSet, "alpn")
				}
				if req.AllowInsecure != nil && *req.AllowInsecure {
					tlsSet["allowInsecure"] = true
				} else {
					delete(tlsSet, "allowInsecure")
				}
				if pin := strings.TrimSpace(req.PinnedSha256); pin != "" {
					tlsSet["pinnedPeerCertificateSha256"] = pin
				} else {
					delete(tlsSet, "pinnedPeerCertificateSha256")
				}
				ss["tlsSettings"] = tlsSet
			case "reality":
				ss["security"] = "reality"
				delete(ss, "tlsSettings")
				fp := strings.TrimSpace(req.Fingerprint)
				if fp == "" {
					fp = "chrome"
				}
				ss["realitySettings"] = map[string]interface{}{
					"serverName":  strings.TrimSpace(req.SNI),
					"fingerprint": fp,
					"publicKey":   strings.TrimSpace(req.RealityPBK),
					"shortId":     strings.TrimSpace(req.RealitySID),
					"spiderX":     strings.TrimSpace(req.RealitySPX),
				}
			default:
				delete(ss, "security")
				delete(ss, "tlsSettings")
				delete(ss, "realitySettings")
			}

			ob["streamSettings"] = ss
		}
	}

	if req.SockoptDomainStrategy != nil {
		ds := strings.TrimSpace(*req.SockoptDomainStrategy)
		if ds != "" {
			switch ds {
			case "AsIs", "UseIP", "UseIPv4", "UseIPv6", "UseIPv4v6", "UseIPv6v4", "ForceIP", "ForceIPv4", "ForceIPv6", "ForceIPv4v6", "ForceIPv6v4":
			default:
				return fmt.Errorf("unsupported sockopt domainStrategy %q", ds)
			}
			curSS, _ := ob["streamSettings"].(map[string]interface{})
			if curSS == nil {
				curSS = map[string]interface{}{}
			}
			sockopt, _ := curSS["sockopt"].(map[string]interface{})
			if sockopt == nil {
				sockopt = map[string]interface{}{}
			}
			sockopt["domainStrategy"] = ds
			curSS["sockopt"] = sockopt
			ob["streamSettings"] = curSS
		} else if curSS, ok := ob["streamSettings"].(map[string]interface{}); ok {
			if sockopt, ok := curSS["sockopt"].(map[string]interface{}); ok {
				delete(sockopt, "domainStrategy")
				if len(sockopt) == 0 {
					delete(curSS, "sockopt")
				}
			}
			if len(curSS) == 0 {
				delete(ob, "streamSettings")
			}
		}
	}

	node.Outbound = ob
	return nil
}

func buildShareURI(node NodeProfile) string {
	proto := normalizeNodeProtocol(node.Protocol)
	ob := node.Outbound
	if ob == nil {
		return ""
	}
	settings, _ := ob["settings"].(map[string]interface{})
	ss, _ := ob["streamSettings"].(map[string]interface{})

	getFirstVnext := func() (string, int, map[string]interface{}) {
		if settings == nil {
			return node.Address, node.Port, nil
		}
		if vnext, ok := settings["vnext"].([]interface{}); ok && len(vnext) > 0 {
			if vObj, ok := vnext[0].(map[string]interface{}); ok {
				a, _ := vObj["address"].(string)
				p := jsonIntValue(vObj["port"])
				var uObj map[string]interface{}
				if users, ok := vObj["users"].([]interface{}); ok && len(users) > 0 {
					uObj, _ = users[0].(map[string]interface{})
				}
				return a, p, uObj
			}
		}
		return node.Address, node.Port, nil
	}
	getFirstServer := func() (string, int, map[string]interface{}) {
		if settings == nil {
			return node.Address, node.Port, nil
		}
		if servers, ok := settings["servers"].([]interface{}); ok && len(servers) > 0 {
			if sObj, ok := servers[0].(map[string]interface{}); ok {
				a, _ := sObj["address"].(string)
				p := jsonIntValue(sObj["port"])
				return a, p, sObj
			}
		}
		return node.Address, node.Port, nil
	}

	switch proto {
	case "shadowsocks":
		addr, port, srv := getFirstServer()
		method, _ := srv["method"].(string)
		pw, _ := srv["password"].(string)
		if addr == "" || port <= 0 {
			return ""
		}
		creds := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + pw))
		u := url.URL{
			Scheme:   "ss",
			User:     url.User(creds),
			Host:     net.JoinHostPort(addr, strconv.Itoa(port)),
			Fragment: node.Name,
		}
		return u.String()

	case "vmess":
		addr, port, uObj := getFirstVnext()
		if addr == "" || port <= 0 {
			return ""
		}
		uuidVal, _ := uObj["id"].(string)
		vmSec, _ := uObj["security"].(string)
		aid := jsonIntValue(uObj["alterId"])
		payload := map[string]interface{}{
			"v":    "2",
			"ps":   node.Name,
			"add":  addr,
			"port": port,
			"id":   uuidVal,
			"aid":  aid,
			"scy":  vmSec,
			"net":  "tcp",
			"type": "none",
		}
		if ss != nil {
			if netType, _ := ss["network"].(string); netType != "" {
				payload["net"] = netType
			}
			if sec, _ := ss["security"].(string); sec == "tls" {
				payload["tls"] = "tls"
				if tlsSet, _ := ss["tlsSettings"].(map[string]interface{}); tlsSet != nil {
					if sni, _ := tlsSet["serverName"].(string); sni != "" {
						payload["sni"] = sni
					}
					if fp, _ := tlsSet["fingerprint"].(string); fp != "" {
						payload["fp"] = fp
					}
					if alpnArr, ok := tlsSet["alpn"].([]interface{}); ok && len(alpnArr) > 0 {
						var parts []string
						for _, a := range alpnArr {
							parts = append(parts, fmt.Sprintf("%v", a))
						}
						payload["alpn"] = strings.Join(parts, ",")
					}
					if allow, ok := tlsSet["allowInsecure"].(bool); ok && allow {
						payload["allowInsecure"] = true
					}
				}
			}
			switch payload["net"] {
			case "ws":
				if ws, _ := ss["wsSettings"].(map[string]interface{}); ws != nil {
					payload["path"], _ = ws["path"].(string)
					if h, _ := ws["host"].(string); h != "" {
						payload["host"] = h
					} else if hdrs, _ := ws["headers"].(map[string]interface{}); hdrs != nil {
						payload["host"], _ = hdrs["Host"].(string)
					}
				}
			case "xhttp", "splithttp":
				if xh, _ := ss["xhttpSettings"].(map[string]interface{}); xh != nil {
					payload["path"], _ = xh["path"].(string)
					payload["host"], _ = xh["host"].(string)
				}
			case "httpupgrade":
				if hu, _ := ss["httpupgradeSettings"].(map[string]interface{}); hu != nil {
					payload["path"], _ = hu["path"].(string)
					payload["host"], _ = hu["host"].(string)
				}
			case "grpc":
				if gs, _ := ss["grpcSettings"].(map[string]interface{}); gs != nil {
					payload["path"], _ = gs["serviceName"].(string)
					if mm, _ := gs["multiMode"].(bool); mm {
						payload["type"] = "multi"
					}
				}
			}
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return ""
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(raw)

	case "hysteria2":
		addr, _ := settings["address"].(string)
		port := jsonIntValue(settings["port"])
		if addr == "" {
			addr = node.Address
		}
		if port <= 0 {
			port = node.Port
		}
		if addr == "" || port <= 0 {
			return ""
		}
		q := url.Values{}
		var auth string
		if ss != nil {
			if hySet, _ := ss["hysteriaSettings"].(map[string]interface{}); hySet != nil {
				auth, _ = hySet["auth"].(string)
				if up, _ := hySet["up"].(string); up != "" {
					q.Set("up", strings.TrimSuffix(up, " mbps"))
				}
				if down, _ := hySet["down"].(string); down != "" {
					q.Set("down", strings.TrimSuffix(down, " mbps"))
				}
			}
			if tlsSet, _ := ss["tlsSettings"].(map[string]interface{}); tlsSet != nil {
				if sni, _ := tlsSet["serverName"].(string); sni != "" {
					q.Set("sni", sni)
				}
				if fp, _ := tlsSet["fingerprint"].(string); fp != "" {
					q.Set("fp", fp)
				}
				if allow, _ := tlsSet["allowInsecure"].(bool); allow {
					q.Set("insecure", "1")
				}
				if pin, _ := tlsSet["pinnedPeerCertificateSha256"].(string); pin != "" {
					q.Set("pinSHA256", pin)
				}
				if alpnArr, ok := tlsSet["alpn"].([]interface{}); ok && len(alpnArr) > 0 {
					var parts []string
					for _, a := range alpnArr {
						parts = append(parts, fmt.Sprintf("%v", a))
					}
					q.Set("alpn", strings.Join(parts, ","))
				}
			}
			if fm, _ := ss["finalmask"].(map[string]interface{}); fm != nil {
				if udpArr, ok := fm["udp"].([]interface{}); ok && len(udpArr) > 0 {
					if mObj, ok := udpArr[0].(map[string]interface{}); ok {
						if t, _ := mObj["type"].(string); t != "" {
							q.Set("obfs", t)
						}
						if mSet, _ := mObj["settings"].(map[string]interface{}); mSet != nil {
							if op, _ := mSet["password"].(string); op != "" {
								q.Set("obfs-password", op)
							}
						}
					}
				}
			}
		}
		u := url.URL{
			Scheme:   "hysteria2",
			User:     url.User(auth),
			Host:     net.JoinHostPort(addr, strconv.Itoa(port)),
			RawQuery: q.Encode(),
			Fragment: node.Name,
		}
		return u.String()

	case "vless", "trojan":
		var addr, userCred string
		var port int
		q := url.Values{}
		if proto == "vless" {
			var uObj map[string]interface{}
			addr, port, uObj = getFirstVnext()
			userCred, _ = uObj["id"].(string)
			enc, _ := uObj["encryption"].(string)
			if enc == "" {
				enc = "none"
			}
			q.Set("encryption", enc)
			if flow, _ := uObj["flow"].(string); flow != "" {
				q.Set("flow", flow)
			}
		} else {
			var sObj map[string]interface{}
			addr, port, sObj = getFirstServer()
			userCred, _ = sObj["password"].(string)
		}
		if addr == "" || port <= 0 {
			return ""
		}

		netType := "tcp"
		if ss != nil {
			if nt, _ := ss["network"].(string); nt != "" {
				netType = nt
			}
			q.Set("type", netType)

			sec, _ := ss["security"].(string)
			if sec == "" {
				sec = "none"
			}
			q.Set("security", sec)

			if sec == "tls" {
				if tlsSet, _ := ss["tlsSettings"].(map[string]interface{}); tlsSet != nil {
					if sni, _ := tlsSet["serverName"].(string); sni != "" {
						q.Set("sni", sni)
					}
					if fp, _ := tlsSet["fingerprint"].(string); fp != "" {
						q.Set("fp", fp)
					}
					if allow, _ := tlsSet["allowInsecure"].(bool); allow {
						q.Set("allowInsecure", "1")
					}
					if alpnArr, ok := tlsSet["alpn"].([]interface{}); ok && len(alpnArr) > 0 {
						var parts []string
						for _, a := range alpnArr {
							parts = append(parts, fmt.Sprintf("%v", a))
						}
						q.Set("alpn", strings.Join(parts, ","))
					}
				}
			} else if sec == "reality" {
				if rs, _ := ss["realitySettings"].(map[string]interface{}); rs != nil {
					if sni, _ := rs["serverName"].(string); sni != "" {
						q.Set("sni", sni)
					}
					if fp, _ := rs["fingerprint"].(string); fp != "" {
						q.Set("fp", fp)
					}
					if pbk, _ := rs["publicKey"].(string); pbk != "" {
						q.Set("pbk", pbk)
					}
					if sid, _ := rs["shortId"].(string); sid != "" {
						q.Set("sid", sid)
					}
					if spx, _ := rs["spiderX"].(string); spx != "" {
						q.Set("spx", spx)
					}
				}
			}

			switch netType {
			case "ws":
				if ws, _ := ss["wsSettings"].(map[string]interface{}); ws != nil {
					if p, _ := ws["path"].(string); p != "" {
						q.Set("path", p)
					}
					if h, _ := ws["host"].(string); h != "" {
						q.Set("host", h)
					} else if hdrs, _ := ws["headers"].(map[string]interface{}); hdrs != nil {
						if h, _ := hdrs["Host"].(string); h != "" {
							q.Set("host", h)
						}
					}
				}
			case "xhttp", "splithttp":
				if xh, _ := ss["xhttpSettings"].(map[string]interface{}); xh != nil {
					if p, _ := xh["path"].(string); p != "" {
						q.Set("path", p)
					}
					if h, _ := xh["host"].(string); h != "" {
						q.Set("host", h)
					}
					if m, _ := xh["mode"].(string); m != "" {
						q.Set("mode", m)
					}
				}
			case "httpupgrade":
				if hu, _ := ss["httpupgradeSettings"].(map[string]interface{}); hu != nil {
					if p, _ := hu["path"].(string); p != "" {
						q.Set("path", p)
					}
					if h, _ := hu["host"].(string); h != "" {
						q.Set("host", h)
					}
				}
			case "grpc":
				if gs, _ := ss["grpcSettings"].(map[string]interface{}); gs != nil {
					if sn, _ := gs["serviceName"].(string); sn != "" {
						q.Set("serviceName", sn)
					}
					if mm, _ := gs["multiMode"].(bool); mm {
						q.Set("mode", "multi")
					}
					if auth, _ := gs["authority"].(string); auth != "" {
						q.Set("authority", auth)
					}
				}
			case "tcp", "raw":
				if ts, _ := ss["tcpSettings"].(map[string]interface{}); ts != nil {
					if hdr, _ := ts["header"].(map[string]interface{}); hdr != nil {
						if ht, _ := hdr["type"].(string); ht == "http" {
							q.Set("headerType", "http")
							if rObj, _ := hdr["request"].(map[string]interface{}); rObj != nil {
								if pArr, ok := rObj["path"].([]interface{}); ok && len(pArr) > 0 {
									q.Set("path", fmt.Sprintf("%v", pArr[0]))
								}
								if hMap, _ := rObj["headers"].(map[string]interface{}); hMap != nil {
									if hArr, ok := hMap["Host"].([]interface{}); ok && len(hArr) > 0 {
										q.Set("host", fmt.Sprintf("%v", hArr[0]))
									}
								}
							}
						}
					}
				}
			case "kcp":
				if ks, _ := ss["kcpSettings"].(map[string]interface{}); ks != nil {
					if hdr, _ := ks["header"].(map[string]interface{}); hdr != nil {
						if ht, _ := hdr["type"].(string); ht != "" {
							q.Set("headerType", ht)
						}
					}
					if seed, _ := ks["seed"].(string); seed != "" {
						q.Set("seed", seed)
					}
				}
			}
		}
		u := url.URL{
			Scheme:   proto,
			User:     url.User(userCred),
			Host:     net.JoinHostPort(addr, strconv.Itoa(port)),
			RawQuery: q.Encode(),
			Fragment: node.Name,
		}
		return u.String()
	}
	return ""
}

func updateNodeOutboundAddressAndPort(node *NodeProfile, newAddr string, newPort int, newSNI string) {
	if node.Outbound == nil {
		node.Outbound = make(map[string]interface{})
	}
	settings, ok := node.Outbound["settings"].(map[string]interface{})
	if ok && settings != nil {
		if vnext, ok := settings["vnext"].([]interface{}); ok && len(vnext) > 0 {
			if vObj, ok := vnext[0].(map[string]interface{}); ok {
				if newAddr != "" {
					vObj["address"] = newAddr
				}
				if newPort > 0 {
					vObj["port"] = newPort
				}
			}
		} else if servers, ok := settings["servers"].([]interface{}); ok && len(servers) > 0 {
			if sObj, ok := servers[0].(map[string]interface{}); ok {
				if newAddr != "" {
					sObj["address"] = newAddr
				}
				if newPort > 0 {
					sObj["port"] = newPort
				}
			}
		} else {
			if newAddr != "" {
				settings["address"] = newAddr
			}
			if newPort > 0 {
				settings["port"] = newPort
			}
		}
	}
	if newSNI != "" {
		if ss, ok := node.Outbound["streamSettings"].(map[string]interface{}); ok && ss != nil {
			if tlsSettings, ok := ss["tlsSettings"].(map[string]interface{}); ok && tlsSettings != nil {
				tlsSettings["serverName"] = newSNI
			}
			if realitySettings, ok := ss["realitySettings"].(map[string]interface{}); ok && realitySettings != nil {
				realitySettings["serverName"] = newSNI
			}
		}
	}
}

func getXrayVersion() string {
	xrayVerMu.Lock()
	defer xrayVerMu.Unlock()
	if cachedXrayVer != "" && cachedXrayVer != "Unknown" {
		return cachedXrayVer
	}

	cmd := exec.Command(XrayBin, "version")
	out, err := cmd.Output()
	if err != nil {
		cmd = exec.Command(XrayBin, "-version")
		out, err = cmd.Output()
	}
	if err != nil {
		cachedXrayVer = "Unknown"
		return cachedXrayVer
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > 0 {
		firstLine := strings.TrimSpace(lines[0])
		fields := strings.Fields(firstLine)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "Xray") {
			cachedXrayVer = "v" + strings.TrimPrefix(fields[1], "v")
		} else if firstLine != "" {
			if len(firstLine) > 36 {
				firstLine = firstLine[:36]
			}
			cachedXrayVer = firstLine
		} else {
			cachedXrayVer = "Unknown"
		}
	} else {
		cachedXrayVer = "Unknown"
	}
	return cachedXrayVer
}

func invalidateXrayVersion() {
	xrayVerMu.Lock()
	cachedXrayVer = ""
	xrayVerMu.Unlock()
}

func directDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			_ = c.Control(func(fd uintptr) {
				sockErr = setSocketMark(fd, BypassMark)
			})
			return sockErr
		},
	}
}

func detectTproxy() bool {
	if data, err := os.ReadFile("/proc/net/ip_tables_targets"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == "TPROXY" {
				return true
			}
		}
	}
	if err := runCmd("iptables", "-t", "mangle", "-N", "PW_PROBE"); err != nil {
		return false
	}
	defer func() {
		runCmdIgnoreErr("iptables", "-t", "mangle", "-F", "PW_PROBE")
		runCmdIgnoreErr("iptables", "-t", "mangle", "-X", "PW_PROBE")
	}()
	return runCmd("iptables", "-t", "mangle", "-A", "PW_PROBE",
		"-p", "tcp", "-j", "TPROXY", "--on-port", strconv.Itoa(TproxyPort), "--on-ip", "127.0.0.1") == nil
}

func writeSyncedFile(path string, data []byte) error {
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

func syncPersistentConfigs() {
	_ = os.MkdirAll(PersistDir, 0755)
	_ = os.MkdirAll(filepath.Dir(BaseConfig), 0755)

	// Sync BaseConfig and PersistBaseConfig
	statBase, errBase := os.Stat(BaseConfig)
	statPersistBase, errPersistBase := os.Stat(PersistBaseConfig)
	if errBase != nil && errPersistBase == nil {
		if data, err := os.ReadFile(PersistBaseConfig); err == nil && len(data) > 0 {
			_ = writeSyncedFile(BaseConfig, data)
		}
	} else if errBase == nil && errPersistBase != nil {
		if data, err := os.ReadFile(BaseConfig); err == nil && len(data) > 0 {
			_ = writeSyncedFile(PersistBaseConfig, data)
		}
	} else if errBase == nil && errPersistBase == nil {
		if statPersistBase.ModTime().After(statBase.ModTime()) {
			if data, err := os.ReadFile(PersistBaseConfig); err == nil && len(data) > 0 {
				_ = writeSyncedFile(BaseConfig, data)
			}
		} else if statBase.ModTime().After(statPersistBase.ModTime()) {
			if data, err := os.ReadFile(BaseConfig); err == nil && len(data) > 0 {
				_ = writeSyncedFile(PersistBaseConfig, data)
			}
		}
	}

	// Sync StateFile and PersistStateFile
	statState, errState := os.Stat(StateFile)
	statPersistState, errPersistState := os.Stat(PersistStateFile)
	if errState != nil && errPersistState == nil {
		if data, err := os.ReadFile(PersistStateFile); err == nil && len(data) > 0 {
			_ = writeSyncedFile(StateFile, data)
		}
	} else if errState == nil && errPersistState != nil {
		if data, err := os.ReadFile(StateFile); err == nil && len(data) > 0 {
			_ = writeSyncedFile(PersistStateFile, data)
		}
	} else if errState == nil && errPersistState == nil {
		var stState, stPersist PanelState
		dataState, _ := os.ReadFile(StateFile)
		dataPersist, _ := os.ReadFile(PersistStateFile)
		_ = json.Unmarshal(dataState, &stState)
		_ = json.Unmarshal(dataPersist, &stPersist)

		if len(stPersist.Nodes) > 0 && len(stState.Nodes) == 0 {
			_ = writeSyncedFile(StateFile, dataPersist)
		} else if len(stState.Nodes) > 0 && len(stPersist.Nodes) == 0 {
			_ = writeSyncedFile(PersistStateFile, dataState)
		} else if statPersistState.ModTime().After(statState.ModTime()) {
			_ = writeSyncedFile(StateFile, dataPersist)
		} else if statState.ModTime().After(statPersistState.ModTime()) {
			_ = writeSyncedFile(PersistStateFile, dataState)
		}
	}
}

func resetBaseConfig() error {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, []byte(DefaultBaseConfigJSON), "", "  "); err != nil {
		return err
	}
	_ = os.MkdirAll(filepath.Dir(BaseConfig), 0755)
	if err := writeSyncedFile(BaseConfig, pretty.Bytes()); err != nil {
		return err
	}
	if errDir := os.MkdirAll(PersistDir, 0755); errDir == nil {
		_ = writeSyncedFile(PersistBaseConfig, pretty.Bytes())
	}
	st := loadState()
	st.ActiveNode = ""
	_ = saveState(st)
	log.Println("[passwall-droid] base config.json reset to factory default")
	return nil
}

var (
	cachedState        PanelState
	cachedStateValid   bool
	lastStateModTime   time.Time
	lastPersistModTime time.Time
	lastStatePath      string
	lastPersistPath    string
)

func invalidateStateCache() {
	stateMu.Lock()
	cachedStateValid = false
	stateMu.Unlock()
}

func sanitizePanelState(st *PanelState) {
	if st.ProxyMode != "rule" && st.ProxyMode != "global" && st.ProxyMode != "direct" {
		st.ProxyMode = "rule"
	}
	if st.AppFilterMode != "bypass" && st.AppFilterMode != "proxy" {
		st.AppFilterMode = "bypass"
	}
	if st.SelectedUIDs == nil {
		st.SelectedUIDs = []int{}
	}
	if st.Nodes == nil {
		st.Nodes = []NodeProfile{}
	}
	for i := range st.Nodes {
		if strings.TrimSpace(st.Nodes[i].ID) == "" {
			st.Nodes[i].ID = fmt.Sprintf("restored-%d-%d", time.Now().UnixNano(), i)
		}
		if st.Nodes[i].Outbound != nil {
			syncNodeProfileFromOutbound(&st.Nodes[i])
		}
	}

	if st.DNS.RemoteDNS == "" {
		st.DNS.RemoteDNS = "tcp://1.1.1.1"
	}
	if st.DNS.DirectDNS == "" {
		st.DNS.DirectDNS = "1.1.1.1"
	}
	baseQS := normalizeQueryStrategy(st.DNS.QueryStrategy, "UseIPv4")
	st.DNS.DirectQueryStrategy = normalizeQueryStrategy(st.DNS.DirectQueryStrategy, baseQS)
	st.DNS.RemoteQueryStrategy = normalizeQueryStrategy(st.DNS.RemoteQueryStrategy, baseQS)
	st.DNS.QueryStrategy = combinedTopLevelQueryStrategy(st.DNS.DirectQueryStrategy, st.DNS.RemoteQueryStrategy)

	boolTrue := true
	if st.DNS.DNSRedirect == nil {
		boolTrueDNS := true
		st.DNS.DNSRedirect = &boolTrueDNS
	}
	if st.Geo.BypassIran == nil {
		st.Geo.BypassIran = &boolTrue
	}
	if st.Geo.BypassCN == nil {
		boolTrueCN := true
		st.Geo.BypassCN = &boolTrueCN
	}
	if st.Geo.BlockAds == nil {
		boolTrueAds := true
		st.Geo.BlockAds = &boolTrueAds
	}
	st.Geo.DomainStrategy = normalizeDomainStrategy(st.Geo.DomainStrategy)
	st.Geo.DomainMatcher = normalizeDomainMatcher(st.Geo.DomainMatcher)
	if st.Geo.DirectDomains == nil {
		st.Geo.DirectDomains = []string{}
	}
	if st.Geo.DirectIPs == nil {
		st.Geo.DirectIPs = []string{}
	}
	if st.Geo.ProxyDomains == nil {
		st.Geo.ProxyDomains = []string{}
	}
	if st.Geo.ProxyIPs == nil {
		st.Geo.ProxyIPs = []string{}
	}
	if st.Geo.BlockDomains == nil {
		st.Geo.BlockDomains = []string{}
	}
	if st.Geo.BlockIPs == nil {
		st.Geo.BlockIPs = []string{}
	}
	if st.Geo.GeoIPURL == "" {
		st.Geo.GeoIPURL = "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geoip.dat"
	}
	if st.Geo.GeoSiteURL == "" {
		st.Geo.GeoSiteURL = "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geosite.dat"
	}
}

func loadState() PanelState {
	stateMu.Lock()
	defer stateMu.Unlock()

	statState, errState := os.Stat(StateFile)
	statPersist, errPersist := os.Stat(PersistStateFile)

	if cachedStateValid && lastStatePath == StateFile && lastPersistPath == PersistStateFile {
		stateUnchanged := (errState != nil && lastStateModTime.IsZero()) || (errState == nil && statState.ModTime().Equal(lastStateModTime))
		persistUnchanged := (errPersist != nil && lastPersistModTime.IsZero()) || (errPersist == nil && statPersist.ModTime().Equal(lastPersistModTime))
		if stateUnchanged && persistUnchanged {
			return cachedState
		}
	}

	st := PanelState{
		ProxyMode:      "rule",
		AppFilterMode:  "bypass",
		LocalhostProxy: true,
		SelectedUIDs:   []int{},
		Nodes:          []NodeProfile{},
	}
	var stFromState, stFromPersist PanelState
	hasState := false
	hasPersist := false

	if data, err := os.ReadFile(StateFile); err == nil && len(data) > 0 {
		if err := json.Unmarshal(data, &stFromState); err == nil {
			hasState = true
		}
	}
	if data, err := os.ReadFile(PersistStateFile); err == nil && len(data) > 0 {
		if err := json.Unmarshal(data, &stFromPersist); err == nil {
			hasPersist = true
		}
	}

	if hasState && hasPersist {
		if len(stFromPersist.Nodes) > 0 && len(stFromState.Nodes) == 0 {
			st = stFromPersist
		} else if len(stFromState.Nodes) > 0 && len(stFromPersist.Nodes) == 0 {
			st = stFromState
		} else {
			statState, err1 := os.Stat(StateFile)
			statPersist, err2 := os.Stat(PersistStateFile)
			if err1 == nil && err2 == nil && statPersist.ModTime().After(statState.ModTime()) {
				st = stFromPersist
			} else {
				st = stFromState
			}
		}
	} else if hasState {
		st = stFromState
	} else if hasPersist {
		st = stFromPersist
		if data, err := os.ReadFile(PersistStateFile); err == nil && len(data) > 0 {
			_ = writeSyncedFile(StateFile, data)
		}
	}

	sanitizePanelState(&st)

	// Validate ActiveNode: ensure active node exists in nodes list, or fallback to first node
	activeExists := false
	if st.ActiveNode != "" {
		for _, n := range st.Nodes {
			if n.ID == st.ActiveNode {
				activeExists = true
				break
			}
		}
	}
	if !activeExists && len(st.Nodes) > 0 {
		st.ActiveNode = st.Nodes[0].ID
		if data, err := json.MarshalIndent(st, "", "  "); err == nil {
			_ = writeSyncedFile(StateFile, data)
			_ = writeSyncedFile(PersistStateFile, data)
		}
	} else if !activeExists {
		st.ActiveNode = ""
	}

	cachedState = st
	cachedStateValid = true
	lastStatePath = StateFile
	lastPersistPath = PersistStateFile
	if errState == nil && statState != nil {
		lastStateModTime = statState.ModTime()
	} else {
		lastStateModTime = time.Time{}
	}
	if errPersist == nil && statPersist != nil {
		lastPersistModTime = statPersist.ModTime()
	} else {
		lastPersistModTime = time.Time{}
	}

	return st
}

func saveState(st PanelState) error {
	stateMu.Lock()
	defer stateMu.Unlock()

	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	err1 := writeSyncedFile(StateFile, data)
	err2 := writeSyncedFile(PersistStateFile, data)
	if err1 != nil && err2 != nil {
		return err1
	}

	cachedState = st
	cachedStateValid = true
	lastStatePath = StateFile
	lastPersistPath = PersistStateFile
	if s, err := os.Stat(StateFile); err == nil {
		lastStateModTime = s.ModTime()
	} else {
		lastStateModTime = time.Time{}
	}
	if s, err := os.Stat(PersistStateFile); err == nil {
		lastPersistModTime = s.ModTime()
	} else {
		lastPersistModTime = time.Time{}
	}

	return nil
}

func createBackupBundle() ([]byte, error) {
	st := loadState()

	rawCfg, err := os.ReadFile(BaseConfig)
	if err != nil || len(bytes.TrimSpace(rawCfg)) == 0 {
		rawCfg, err = os.ReadFile(PersistBaseConfig)
	}
	if err != nil || len(bytes.TrimSpace(rawCfg)) == 0 {
		rawCfg = []byte(DefaultBaseConfigJSON)
	}

	var cfgObj map[string]interface{}
	if err := json.Unmarshal(rawCfg, &cfgObj); err != nil {
		return nil, fmt.Errorf("invalid base config.json: %w", err)
	}
	compactCfg, err := json.Marshal(cfgObj)
	if err != nil {
		return nil, err
	}

	bundle := BackupBundle{
		Format:        "passwall-android-backup",
		Version:       1,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		ModuleVersion: getModuleVersion(),
		State:         &st,
		Config:        json.RawMessage(compactCfg),
	}
	return json.MarshalIndent(bundle, "", "  ")
}

func restoreBackupBundle(raw []byte) (PanelState, bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return PanelState{}, false, fmt.Errorf("backup file is empty")
	}

	// Support optional wrapper {"backup_json": "..."}
	var wrapper struct {
		BackupJSON string `json:"backup_json"`
	}
	if err := json.Unmarshal(trimmed, &wrapper); err == nil && strings.TrimSpace(wrapper.BackupJSON) != "" {
		trimmed = bytes.TrimSpace([]byte(wrapper.BackupJSON))
	}

	var topObj map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &topObj); err != nil || topObj == nil {
		return PanelState{}, false, fmt.Errorf("invalid backup JSON: %v", err)
	}

	var bundle BackupBundle
	if err := json.Unmarshal(trimmed, &bundle); err != nil {
		return PanelState{}, false, fmt.Errorf("malformed backup structure: %v", err)
	}

	if bundle.Format != "" && bundle.Format != "passwall-android-backup" {
		return PanelState{}, false, fmt.Errorf("unsupported backup format %q", bundle.Format)
	}
	if bundle.Version > 1 {
		return PanelState{}, false, fmt.Errorf("unsupported backup version %d", bundle.Version)
	}

	restoredState := PanelState{
		ProxyMode:      "rule",
		AppFilterMode:  "bypass",
		LocalhostProxy: true,
		SelectedUIDs:   []int{},
		Nodes:          []NodeProfile{},
	}

	hasState := false
	if rawState, ok := topObj["state"]; ok && len(bytes.TrimSpace(rawState)) > 0 && string(bytes.TrimSpace(rawState)) != "null" {
		if err := json.Unmarshal(rawState, &restoredState); err != nil {
			return PanelState{}, false, fmt.Errorf("invalid backup state payload: %v", err)
		}
		hasState = true
	} else if _, hasNodes := topObj["nodes"]; hasNodes || topObj["proxy_mode"] != nil || topObj["dns"] != nil || topObj["geo"] != nil {
		// Also accept a raw state.json directly
		if err := json.Unmarshal(trimmed, &restoredState); err != nil {
			return PanelState{}, false, fmt.Errorf("invalid state JSON: %v", err)
		}
		hasState = true
	}

	var prettyConfig []byte
	hasConfig := false
	if len(bytes.TrimSpace(bundle.Config)) > 0 && string(bytes.TrimSpace(bundle.Config)) != "null" {
		var cfgObj map[string]interface{}
		if err := json.Unmarshal(bundle.Config, &cfgObj); err != nil || cfgObj == nil {
			return PanelState{}, false, fmt.Errorf("invalid backup config.json payload")
		}
		var err error
		prettyConfig, err = json.MarshalIndent(cfgObj, "", "  ")
		if err != nil {
			return PanelState{}, false, err
		}
		hasConfig = true
	} else if !hasState && topObj["inbounds"] != nil && topObj["outbounds"] != nil {
		var cfgObj map[string]interface{}
		if err := json.Unmarshal(trimmed, &cfgObj); err != nil || cfgObj == nil {
			return PanelState{}, false, fmt.Errorf("invalid config.json payload")
		}
		var err error
		prettyConfig, err = json.MarshalIndent(cfgObj, "", "  ")
		if err != nil {
			return PanelState{}, false, err
		}
		hasConfig = true
	}

	if !hasState && !hasConfig {
		return PanelState{}, false, fmt.Errorf("unrecognized backup file: missing state or config")
	}

	if hasConfig {
		_ = os.MkdirAll(filepath.Dir(BaseConfig), 0755)
		if err := writeSyncedFile(BaseConfig, prettyConfig); err != nil {
			return PanelState{}, false, fmt.Errorf("failed writing base config: %w", err)
		}
		if errDir := os.MkdirAll(PersistDir, 0755); errDir == nil {
			_ = writeSyncedFile(PersistBaseConfig, prettyConfig)
		}
	}

	if hasState {
		sanitizePanelState(&restoredState)
		activeExists := false
		for _, n := range restoredState.Nodes {
			if n.ID == restoredState.ActiveNode {
				activeExists = true
				break
			}
		}
		if !activeExists {
			if len(restoredState.Nodes) > 0 {
				restoredState.ActiveNode = restoredState.Nodes[0].ID
			} else {
				restoredState.ActiveNode = ""
			}
		}
		if err := saveState(restoredState); err != nil {
			return PanelState{}, hasConfig, fmt.Errorf("failed saving restored state: %w", err)
		}
	} else {
		restoredState = loadState()
	}

	log.Printf("[passwall-droid] backup restored (state=%v, config=%v, nodes=%d)", hasState, hasConfig, len(restoredState.Nodes))
	return restoredState, hasConfig, nil
}

func listInstalledApps() []AndroidApp {
	data, err := os.ReadFile(PackagesFile)
	if err != nil {
		return []AndroidApp{}
	}
	seenUID := map[int]bool{}
	var apps []AndroidApp
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		uid, err := strconv.Atoi(fields[1])
		if err != nil || uid < 10000 || seenUID[uid] {
			continue
		}
		seenUID[uid] = true
		apps = append(apps, AndroidApp{
			Package: fields[0],
			UID:     uid,
		})
	}
	sort.Slice(apps, func(i, j int) bool {
		return apps[i].Package < apps[j].Package
	})
	return apps
}

func extractHost(target string) string {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "://") {
		parts := strings.SplitN(target, "://", 2)
		target = parts[1]
	}
	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}
	if h, _, err := net.SplitHostPort(target); err == nil {
		return h
	}
	return target
}

func prepareRuntimeConfig(tproxySupported bool) error {
	raw, err := os.ReadFile(BaseConfig)
	if err != nil {
		raw, err = os.ReadFile(PersistBaseConfig)
	}
	if err != nil {
		return fmt.Errorf("read base config: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("invalid base config.json: %v", err)
	}

	st := loadState()

	remoteDNS := strings.TrimSpace(st.DNS.RemoteDNS)
	if remoteDNS == "" {
		remoteDNS = "tcp://1.1.1.1"
	}
	directDNS := strings.TrimSpace(st.DNS.DirectDNS)
	if directDNS == "" {
		directDNS = "1.1.1.1"
	}
	directQueryStrategy := st.DNS.EffectiveDirectQueryStrategy()
	remoteQueryStrategy := st.DNS.EffectiveRemoteQueryStrategy()
	queryStrategy := combinedTopLevelQueryStrategy(directQueryStrategy, remoteQueryStrategy)

	// Identify active node domain and IP (if any)
	var activeNodeDomain string
	var activeNodeIP string
	for _, n := range st.Nodes {
		if n.ID == st.ActiveNode {
			addr := strings.TrimSpace(n.Address)
			if net.ParseIP(addr) != nil {
				activeNodeIP = addr
			} else if addr != "" {
				activeNodeDomain = addr
			}
			break
		}
	}

	defaultOutbound := "proxy"
	if st.ActiveNode == "" || st.ProxyMode == "direct" {
		defaultOutbound = "direct"
	}

	if st.ActiveNode != "" {
		for _, n := range st.Nodes {
			if n.ID == st.ActiveNode && n.Outbound != nil {
				outCopy := deepCloneMap(n.Outbound)
				outCopy["tag"] = "proxy"
				if outbounds, ok := cfg["outbounds"].([]interface{}); ok {
					replaced := false
					for i, item := range outbounds {
						if ob, ok := item.(map[string]interface{}); ok && ob["tag"] == "proxy" {
							outbounds[i] = outCopy
							replaced = true
							break
						}
					}
					if !replaced {
						cfg["outbounds"] = append([]interface{}{outCopy}, outbounds...)
					}
				} else {
					cfg["outbounds"] = []interface{}{outCopy}
				}
				break
			}
		}
	}

	// Ensure outbounds 'direct' and 'proxy' have mark set so packets never loop into Netfilter
	if outbounds, ok := cfg["outbounds"].([]interface{}); ok {
		for _, item := range outbounds {
			if ob, ok := item.(map[string]interface{}); ok {
				tag, _ := ob["tag"].(string)
				if tag == "direct" || tag == "proxy" {
					ss, _ := ob["streamSettings"].(map[string]interface{})
					if ss == nil {
						ss = map[string]interface{}{}
						ob["streamSettings"] = ss
					}
					sockopt, _ := ss["sockopt"].(map[string]interface{})
					if sockopt == nil {
						sockopt = map[string]interface{}{}
						ss["sockopt"] = sockopt
					}
					sockopt["mark"] = BypassMark

					// Migrate deprecated freedom.domainStrategy to sockopt.domainStrategy
					if proto, _ := ob["protocol"].(string); proto == "freedom" || tag == "direct" {
						if settings, ok := ob["settings"].(map[string]interface{}); ok {
							if ds, ok := settings["domainStrategy"].(string); ok && ds != "" {
								sockopt["domainStrategy"] = ds
								delete(settings, "domainStrategy")
							}
						}
						if tag == "direct" || sockopt["domainStrategy"] == nil || sockopt["domainStrategy"] == "" {
							sockopt["domainStrategy"] = directQueryStrategy
						}
					}
				}
			}
		}
	}

	usedInboundPorts := map[int]bool{1053: true, 12345: true, 10808: true}
	if inbounds, ok := cfg["inbounds"].([]interface{}); ok {
		hasSocks := false
		for _, item := range inbounds {
			inb, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if p := jsonIntValue(inb["port"]); p > 0 {
				usedInboundPorts[p] = true
			}
			if tag, _ := inb["tag"].(string); tag == "socks-in" {
				hasSocks = true
				inb["sniffing"] = map[string]interface{}{
					"enabled":      true,
					"destOverride": []string{"http", "tls", "quic"},
					"metadataOnly": false,
					"routeOnly":    true,
				}
			}
			if tag, _ := inb["tag"].(string); tag == "tproxy-in" {
				inb["listen"] = "0.0.0.0"
				inb["sniffing"] = map[string]interface{}{
					"enabled":      true,
					"destOverride": []string{"http", "tls", "quic"},
					"metadataOnly": false,
					"routeOnly":    true,
				}
				ss, _ := inb["streamSettings"].(map[string]interface{})
				if ss == nil {
					ss = map[string]interface{}{}
					inb["streamSettings"] = ss
				}
				sockopt, _ := ss["sockopt"].(map[string]interface{})
				if sockopt == nil {
					sockopt = map[string]interface{}{}
					ss["sockopt"] = sockopt
				}
				if tproxySupported {
					sockopt["tproxy"] = "tproxy"
				} else {
					sockopt["tproxy"] = "redirect"
				}
			}
		}
		if !hasSocks {
			cfg["inbounds"] = append(inbounds, map[string]interface{}{
				"tag":      "socks-in",
				"listen":   "127.0.0.1",
				"port":     10808,
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  true,
				},
				"sniffing": map[string]interface{}{
					"enabled":      true,
					"destOverride": []string{"http", "tls", "quic"},
					"metadataOnly": false,
					"routeOnly":    true,
				},
			})
		}
		hasDNSIn := false
		if inbList, ok := cfg["inbounds"].([]interface{}); ok {
			for _, item := range inbList {
				if inb, ok := item.(map[string]interface{}); ok {
					if tag, _ := inb["tag"].(string); tag == "dns-in" {
						hasDNSIn = true
						break
					}
				}
			}
		}
		if !hasDNSIn {
			if inbList, ok := cfg["inbounds"].([]interface{}); ok {
				cfg["inbounds"] = append(inbList, map[string]interface{}{
					"tag":      "dns-in",
					"listen":   "0.0.0.0",
					"port":     1053,
					"protocol": "dokodemo-door",
					"settings": map[string]interface{}{
						"network": "tcp,udp",
						"address": "1.1.1.1",
						"port":    53,
					},
				})
			}
		}
	}

	var bridgeInbounds []interface{}
	var bridgeRules []interface{}
	var extraDirectDomains []string
	var extraDirectIPs []string
	if st.AllowInsecureVless {
		nextBridgePort := 10819
		if outbounds, ok := cfg["outbounds"].([]interface{}); ok {
			for _, item := range outbounds {
				ob, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				origHost, dialAddr, dialPort, needs := vlessOutboundNeedsSecurityBypass(ob)
				if !needs {
					continue
				}
				bridgePort := allocateFreeLoopbackPort(nextBridgePort, usedInboundPorts)
				usedInboundPorts[bridgePort] = true
				nextBridgePort = bridgePort + 1

				preserveVlessTransportHost(ob, origHost)
				rewriteVlessOutboundTarget(ob, "127.0.0.1", bridgePort)

				bridgeTag := fmt.Sprintf("vless-plain-bridge-%d", len(bridgeInbounds))
				bridgeInbounds = append(bridgeInbounds, map[string]interface{}{
					"tag":      bridgeTag,
					"listen":   "127.0.0.1",
					"port":     bridgePort,
					"protocol": "dokodemo-door",
					"settings": map[string]interface{}{
						"network": "tcp,udp",
						"address": dialAddr,
						"port":    dialPort,
					},
				})
				bridgeRules = append(bridgeRules, map[string]interface{}{
					"type":        "field",
					"inboundTag":  []string{bridgeTag},
					"outboundTag": "direct",
				})

				if net.ParseIP(dialAddr) == nil {
					if dialAddr != activeNodeDomain {
						extraDirectDomains = append(extraDirectDomains, dialAddr)
					}
				} else if dialAddr != activeNodeIP {
					extraDirectIPs = append(extraDirectIPs, dialAddr)
				}

				tag, _ := ob["tag"].(string)
				log.Printf("[passwall-droid] VLESS TLS/encryption bypass enabled for outbound %q (%s:%d -> 127.0.0.1:%d)", tag, dialAddr, dialPort, bridgePort)
			}
		}
		if len(bridgeInbounds) > 0 {
			if inbList, ok := cfg["inbounds"].([]interface{}); ok {
				cfg["inbounds"] = append(inbList, bridgeInbounds...)
			} else {
				cfg["inbounds"] = bridgeInbounds
			}
		}
	}

	// Prepare direct domains (domestic Iranian/CN domains, custom direct domains, node domain, sub domain)
	var directDomains []string
	if st.Geo.IsBypassIran() {
		directDomains = append(directDomains, "domain:ir", "geosite:ir", "geosite:category-ir")
	}
	if st.Geo.IsBypassCN() {
		directDomains = append(directDomains, "geosite:cn")
	}
	for _, d := range st.Geo.DirectDomains {
		d = strings.TrimSpace(d)
		if d != "" {
			directDomains = append(directDomains, d)
		}
	}
	if activeNodeDomain != "" {
		directDomains = append(directDomains, activeNodeDomain)
	}
	directDomains = append(directDomains, extraDirectDomains...)
	var subHost string
	if st.SubURL != "" {
		if subU, err := url.Parse(st.SubURL); err == nil && subU.Hostname() != "" {
			subHost = subU.Hostname()
			if net.ParseIP(subHost) == nil {
				directDomains = append(directDomains, subHost)
			}
		}
	}

	buildDirectDNSServer := func(addr string, withDomains bool) map[string]interface{} {
		entry := map[string]interface{}{
			"address":       addr,
			"queryStrategy": directQueryStrategy,
		}
		if withDomains {
			entry["domains"] = directDomains
			entry["skipFallback"] = false
		}
		return entry
	}
	buildRemoteDNSServer := func(addr string) map[string]interface{} {
		return map[string]interface{}{
			"address":       addr,
			"queryStrategy": remoteQueryStrategy,
		}
	}

	var dnsServers []interface{}
	switch st.ProxyMode {
	case "rule":
		if defaultOutbound == "direct" {
			dnsServers = []interface{}{
				buildDirectDNSServer(directDNS, false),
				buildDirectDNSServer("1.1.1.1", false),
				"localhost",
			}
		} else {
			dnsServers = []interface{}{
				buildDirectDNSServer(directDNS, true),
				buildRemoteDNSServer(remoteDNS),
				buildDirectDNSServer(directDNS, false),
				"localhost",
			}
		}
	case "global":
		if defaultOutbound == "direct" {
			dnsServers = []interface{}{
				buildDirectDNSServer(directDNS, false),
				buildDirectDNSServer("1.1.1.1", false),
				"localhost",
			}
		} else {
			dnsServers = []interface{}{
				buildDirectDNSServer(directDNS, true),
				buildRemoteDNSServer(remoteDNS),
				"localhost",
			}
		}
	case "direct":
		dnsServers = []interface{}{
			buildDirectDNSServer(directDNS, false),
			buildDirectDNSServer("1.1.1.1", false),
			"localhost",
		}
	}
	cfg["dns"] = map[string]interface{}{
		"servers":       dnsServers,
		"queryStrategy": queryStrategy,
	}

	var rules []interface{}
	if len(bridgeRules) > 0 {
		rules = append(rules, bridgeRules...)
	}
	// 1. Intercept inbound DNS to Xray internal DNS (dns-in port 1053 always; tproxy/socks port 53 when DNS Redirect is enabled)
	rules = append(rules,
		map[string]interface{}{
			"type":        "field",
			"inboundTag":  []string{"dns-in"},
			"outboundTag": "dns-out",
		},
	)
	if st.DNS.IsDNSRedirect() {
		rules = append(rules,
			map[string]interface{}{
				"type":        "field",
				"inboundTag":  []string{"tproxy-in", "socks-in"},
				"port":        "53",
				"outboundTag": "dns-out",
			},
		)
	}

	// 2. Direct DNS server traffic must ALWAYS go to direct outbound (port 53)
	directHost := extractHost(directDNS)
	remoteHost := extractHost(remoteDNS)
	if net.ParseIP(directHost) != nil {
		rule := map[string]interface{}{
			"type":        "field",
			"ip":          []string{directHost},
			"port":        "53",
			"outboundTag": "direct",
		}
		if directHost == remoteHost && strings.HasPrefix(remoteDNS, "tcp://") {
			rule["network"] = "udp"
		}
		rules = append(rules, rule)
	} else if directHost != "" && directHost != "localhost" {
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"domain":      []string{directHost},
			"port":        "53",
			"outboundTag": "direct",
		})
	}

	// 3. Remote DNS server traffic should route to proxy outbound when proxy engine is active
	if defaultOutbound == "proxy" {
		if net.ParseIP(remoteHost) != nil {
			if remoteHost != directHost {
				rules = append(rules, map[string]interface{}{
					"type":        "field",
					"ip":          []string{remoteHost},
					"outboundTag": "proxy",
				})
			} else if strings.HasPrefix(remoteDNS, "tcp://") {
				rules = append(rules, map[string]interface{}{
					"type":        "field",
					"ip":          []string{remoteHost},
					"port":        "53",
					"network":     "tcp",
					"outboundTag": "proxy",
				})
			}
		} else if remoteHost != "" && remoteHost != "localhost" && remoteHost != directHost {
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"domain":      []string{remoteHost},
				"outboundTag": "proxy",
			})
		}
	}

	// 3. Active node, bridged VLESS targets, and sub URL domain / IP must go to direct outbound (prevent proxy loop/deadlock)
	if activeNodeDomain != "" {
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"domain":      []string{activeNodeDomain},
			"outboundTag": "direct",
		})
	}
	if len(extraDirectDomains) > 0 {
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"domain":      sanitizeStringList(extraDirectDomains),
			"outboundTag": "direct",
		})
	}
	if activeNodeIP != "" {
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"ip":          []string{activeNodeIP},
			"outboundTag": "direct",
		})
	}
	if len(extraDirectIPs) > 0 {
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"ip":          sanitizeStringList(extraDirectIPs),
			"outboundTag": "direct",
		})
	}
	if subHost != "" && subHost != activeNodeDomain && subHost != activeNodeIP {
		if net.ParseIP(subHost) != nil {
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"ip":          []string{subHost},
				"outboundTag": "direct",
			})
		} else {
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"domain":      []string{subHost},
				"outboundTag": "direct",
			})
		}
	}

	// 4. Preserve custom user routing rules defined in BaseConfig (if any)
	if origRouting, ok := cfg["routing"].(map[string]interface{}); ok {
		if origRules, ok := origRouting["rules"].([]interface{}); ok {
			for _, r := range origRules {
				if rMap, ok := r.(map[string]interface{}); ok {
					// Skip internal port 53 dns-out interceptor to prevent duplication
					if port, _ := rMap["port"].(string); port == "53" && rMap["outboundTag"] == "dns-out" {
						continue
					}
					rules = append(rules, rMap)
				}
			}
		}
	}

	// 5. Routing mode specific rules:
	switch st.ProxyMode {
	case "rule":
		// A. Block rules (ads and custom block lists)
		var blockDomains []string
		if st.Geo.IsBlockAds() {
			blockDomains = append(blockDomains, "geosite:category-ads-all")
		}
		for _, d := range st.Geo.BlockDomains {
			d = strings.TrimSpace(d)
			if d != "" {
				blockDomains = append(blockDomains, d)
			}
		}
		if len(blockDomains) > 0 {
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"domain":      blockDomains,
				"outboundTag": "block",
			})
		}

		var blockIPs []string
		for _, ip := range st.Geo.BlockIPs {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				blockIPs = append(blockIPs, ip)
			}
		}
		if len(blockIPs) > 0 {
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"ip":          blockIPs,
				"outboundTag": "block",
			})
		}

		// B. Custom force proxy rules
		var proxyDomains []string
		for _, d := range st.Geo.ProxyDomains {
			d = strings.TrimSpace(d)
			if d != "" {
				proxyDomains = append(proxyDomains, d)
			}
		}
		if len(proxyDomains) > 0 {
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"domain":      proxyDomains,
				"outboundTag": "proxy",
			})
		}

		var proxyIPs []string
		for _, ip := range st.Geo.ProxyIPs {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				proxyIPs = append(proxyIPs, ip)
			}
		}
		if len(proxyIPs) > 0 {
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"ip":          proxyIPs,
				"outboundTag": "proxy",
			})
		}

		// C. Direct domains (domestic Iran, China, custom direct domains)
		var ruleDirectDomains []string
		if st.Geo.IsBypassIran() {
			ruleDirectDomains = append(ruleDirectDomains, "domain:ir", "geosite:ir", "geosite:category-ir")
		}
		if st.Geo.IsBypassCN() {
			ruleDirectDomains = append(ruleDirectDomains, "geosite:cn")
		}
		for _, d := range st.Geo.DirectDomains {
			d = strings.TrimSpace(d)
			if d != "" {
				ruleDirectDomains = append(ruleDirectDomains, d)
			}
		}
		if len(ruleDirectDomains) > 0 {
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"domain":      ruleDirectDomains,
				"outboundTag": "direct",
			})
		}

		// D. Direct IPs (private LAN, Iran IP, China IP, custom direct IPs)
		ruleDirectIPs := []string{"geoip:private"}
		if st.Geo.IsBypassIran() {
			ruleDirectIPs = append(ruleDirectIPs, "geoip:ir")
		}
		if st.Geo.IsBypassCN() {
			ruleDirectIPs = append(ruleDirectIPs, "geoip:cn")
		}
		for _, ip := range st.Geo.DirectIPs {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				ruleDirectIPs = append(ruleDirectIPs, ip)
			}
		}
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"ip":          ruleDirectIPs,
			"outboundTag": "direct",
		})
	case "global":
		var customDirectDomains []string
		for _, d := range st.Geo.DirectDomains {
			d = strings.TrimSpace(d)
			if d != "" {
				customDirectDomains = append(customDirectDomains, d)
			}
		}
		if len(customDirectDomains) > 0 {
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"domain":      customDirectDomains,
				"outboundTag": "direct",
			})
		}
		customDirectIPs := []string{"geoip:private"}
		for _, ip := range st.Geo.DirectIPs {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				customDirectIPs = append(customDirectIPs, ip)
			}
		}
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"ip":          customDirectIPs,
			"outboundTag": "direct",
		})
	case "direct":
		// Direct mode: defaultOutbound is direct
	}

	// 5. Fallthrough rule
	rules = append(rules, map[string]interface{}{
		"type":        "field",
		"network":     "tcp,udp",
		"outboundTag": defaultOutbound,
	})

	routing, _ := cfg["routing"].(map[string]interface{})
	if routing == nil {
		routing = map[string]interface{}{}
		cfg["routing"] = routing
	}
	routing["domainStrategy"] = st.Geo.EffectiveDomainStrategy()
	routing["domainMatcher"] = st.Geo.EffectiveDomainMatcher()
	routing["rules"] = rules

	finalBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(RuntimeConfig, finalBytes, 0644)
}

func configureKernelAndTether() {
	writeSysctl("/proc/sys/net/ipv4/ip_forward", "1")
	writeSysctl("/proc/sys/net/ipv4/ip_nonlocal_bind", "1")
	writeSysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0")
	writeSysctl("/proc/sys/net/ipv4/conf/default/rp_filter", "0")
	if matches, err := filepath.Glob("/proc/sys/net/ipv4/conf/*/rp_filter"); err == nil {
		for _, m := range matches {
			writeSysctl(m, "0")
		}
	}

	writeSysctl("/proc/sys/net/ipv4/conf/all/route_localnet", "1")
	writeSysctl("/proc/sys/net/ipv4/conf/default/route_localnet", "1")
	if matches, err := filepath.Glob("/proc/sys/net/ipv4/conf/*/route_localnet"); err == nil {
		for _, m := range matches {
			writeSysctl(m, "1")
		}
	}

	if matches, err := filepath.Glob("/proc/sys/net/ipv4/conf/*/send_redirects"); err == nil {
		for _, m := range matches {
			writeSysctl(m, "0")
		}
	}
	if matches, err := filepath.Glob("/proc/sys/net/ipv4/conf/*/accept_redirects"); err == nil {
		for _, m := range matches {
			writeSysctl(m, "0")
		}
	}

	if DisableIPv6 {
		writeSysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1")
		writeSysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1")
		if matches, err := filepath.Glob("/proc/sys/net/ipv6/conf/*/disable_ipv6"); err == nil {
			for _, m := range matches {
				writeSysctl(m, "1")
			}
		}
		runCmdIgnoreErr("ip6tables", "-I", "FORWARD", "1", "-j", "DROP")
		runCmdIgnoreErr("ip6tables", "-I", "OUTPUT", "1", "-j", "REJECT")
	} else {
		writeSysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1")
	}

	runCmdIgnoreErr("settings", "put", "global", "tether_offload_disabled", "1")
	runCmdIgnoreErr("ndc", "tether", "offload", "set", "false")
	runCmdIgnoreErr("cmd", "connectivity", "tether", "offload", "set", "false")
}

func setupPolicyRouting() error {
	cleanupPolicyRouting()
	if err := runCmd("ip", "-4", "rule", "add",
		"fwmark", FwMark+"/"+FwMask,
		"lookup", strconv.Itoa(RouteTable),
		"pref", strconv.Itoa(RulePref)); err != nil {
		return err
	}
	return runCmd("ip", "-4", "route", "add",
		"local", "0.0.0.0/0", "dev", "lo",
		"table", strconv.Itoa(RouteTable))
}

func cleanupPolicyRouting() {
	runCmdIgnoreErr("ip", "-4", "rule", "del", "fwmark", FwMark+"/"+FwMask, "lookup", strconv.Itoa(RouteTable))
	runCmdIgnoreErr("ip", "-4", "route", "flush", "table", strconv.Itoa(RouteTable))
}

func setupDoTBlockIptables(st PanelState) {
	if !st.DNS.IsDNSRedirect() {
		return
	}
	// Reject DNS-over-TLS (port 853) so Android falls back immediately to port 53 DNS intercepted by Xray.
	_ = runCmd("iptables", "-I", "FORWARD", "1", "-p", "tcp", "--dport", "853", "-j", "REJECT", "--reject-with", "tcp-reset")
	if st.LocalhostProxy {
		_ = runCmd("iptables", "-I", "OUTPUT", "1",
			"-m", "owner", "!", "--gid-owner", strconv.Itoa(XrayGID),
			"-m", "mark", "!", "--mark", BypassHex+"/"+BypassHex,
			"-p", "tcp", "--dport", "853", "-j", "REJECT", "--reject-with", "tcp-reset")
	}
}

func setupTproxyIptables() error {
	st := loadState()
	dnsRedirect := st.DNS.IsDNSRedirect()
	tproxyTarget := strconv.Itoa(TproxyPort)
	markSpec := FwMark + "/" + FwMask

	if err := runCmd("iptables", "-t", "mangle", "-N", "PASSWALL_PRE"); err != nil {
		return err
	}
	if err := runCmd("iptables", "-t", "mangle", "-N", "PASSWALL_OUT"); err != nil {
		return err
	}

	_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_PRE",
		"-m", "mark", "--mark", BypassHex+"/"+BypassHex, "-j", "RETURN")
	runCmdIgnoreErr("iptables", "-t", "mangle", "-A", "PASSWALL_PRE",
		"-p", "tcp", "-m", "socket", "-j", "ACCEPT")

	_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_OUT",
		"-m", "owner", "--gid-owner", strconv.Itoa(XrayGID), "-j", "RETURN")
	_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_OUT",
		"-m", "mark", "--mark", BypassHex+"/"+BypassHex, "-j", "RETURN")

	for _, proto := range []string{"tcp", "udp"} {
		if dnsRedirect {
			_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_PRE",
				"-p", proto, "--dport", "53",
				"-j", "TPROXY", "--on-port", tproxyTarget, "--on-ip", "127.0.0.1", "--tproxy-mark", markSpec)
		} else {
			_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_PRE",
				"-p", proto, "--dport", "53", "-j", "RETURN")
		}
	}

	for _, cidr := range bypassCIDRsV4 {
		_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_PRE", "-d", cidr, "-j", "RETURN")
	}

	for _, proto := range []string{"tcp", "udp"} {
		if err := runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_PRE",
			"-p", proto,
			"-j", "TPROXY", "--on-port", tproxyTarget, "--on-ip", "127.0.0.1", "--tproxy-mark", markSpec); err != nil {
			return err
		}
	}

	if !st.LocalhostProxy {
		_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_OUT", "-j", "RETURN")
	} else {
		for _, proto := range []string{"tcp", "udp"} {
			if dnsRedirect {
				_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_OUT",
					"-p", proto, "--dport", "53",
					"-j", "MARK", "--set-xmark", markSpec)
			} else {
				_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_OUT",
					"-p", proto, "--dport", "53", "-j", "RETURN")
			}
		}
		for _, cidr := range bypassCIDRsV4 {
			_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_OUT", "-d", cidr, "-j", "RETURN")
		}

		if st.AppFilterMode == "proxy" {
			for _, uid := range st.SelectedUIDs {
				uidStr := strconv.Itoa(uid)
				for _, proto := range []string{"tcp", "udp"} {
					_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_OUT",
						"-m", "owner", "--uid-owner", uidStr,
						"-p", proto, "-j", "MARK", "--set-xmark", markSpec)
				}
			}
		} else {
			for _, uid := range st.SelectedUIDs {
				_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_OUT",
					"-m", "owner", "--uid-owner", strconv.Itoa(uid), "-j", "RETURN")
			}
			for _, proto := range []string{"tcp", "udp"} {
				if err := runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_OUT",
					"-p", proto, "-j", "MARK", "--set-xmark", markSpec); err != nil {
					return err
				}
			}
		}
	}

	if BlockQUIC {
		_ = runCmd("iptables", "-I", "FORWARD", "1", "-p", "udp", "--dport", "443", "-j", "DROP")
		if st.LocalhostProxy {
			_ = runCmd("iptables", "-I", "OUTPUT", "1",
				"-m", "owner", "!", "--gid-owner", strconv.Itoa(XrayGID),
				"-m", "mark", "!", "--mark", BypassHex+"/"+BypassHex,
				"-p", "udp", "--dport", "443", "-j", "REJECT")
		}
	}

	setupDoTBlockIptables(st)

	if err := runCmd("iptables", "-t", "mangle", "-I", "PREROUTING", "1", "-j", "PASSWALL_PRE"); err != nil {
		return err
	}
	if err := runCmd("iptables", "-t", "mangle", "-I", "OUTPUT", "1", "-j", "PASSWALL_OUT"); err != nil {
		return err
	}

	_ = runCmd("iptables", "-I", "INPUT", "1", "-m", "mark", "--mark", markSpec, "-j", "ACCEPT")
	_ = runCmd("iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", tproxyTarget, "-j", "ACCEPT")
	_ = runCmd("iptables", "-I", "INPUT", "1", "-p", "udp", "--dport", tproxyTarget, "-j", "ACCEPT")
	_ = runCmd("iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", "1053", "-j", "ACCEPT")
	_ = runCmd("iptables", "-I", "INPUT", "1", "-p", "udp", "--dport", "1053", "-j", "ACCEPT")
	_ = runCmd("iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", "9090", "-j", "ACCEPT")

	_ = runCmd("iptables", "-I", "FORWARD", "1", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	for i, iface := range []string{"ap+", "wlan+", "swlan+", "rndis+", "usb+", "eth+"} {
		_ = runCmd("iptables", "-I", "FORWARD", strconv.Itoa(i+2), "-i", iface, "-j", "ACCEPT")
	}

	_ = runCmd("iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-s", "192.168.0.0/16", "-j", "MASQUERADE")
	_ = runCmd("iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-s", "172.16.0.0/12", "-j", "MASQUERADE")
	_ = runCmd("iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-s", "10.0.0.0/8", "-j", "MASQUERADE")

	return nil
}

func setupRedirectIptables() error {
	st := loadState()
	dnsRedirect := st.DNS.IsDNSRedirect()
	redirPort := strconv.Itoa(TproxyPort)

	if err := runCmd("iptables", "-t", "nat", "-N", "PASSWALL_NAT_PRE"); err != nil {
		return err
	}
	if err := runCmd("iptables", "-t", "nat", "-N", "PASSWALL_NAT_OUT"); err != nil {
		return err
	}

	_ = runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_OUT",
		"-m", "owner", "--gid-owner", strconv.Itoa(XrayGID), "-j", "RETURN")
	_ = runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_OUT",
		"-m", "mark", "--mark", BypassHex+"/"+BypassHex, "-j", "RETURN")

	for _, proto := range []string{"udp", "tcp"} {
		if dnsRedirect {
			_ = runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_PRE",
				"-p", proto, "--dport", "53", "-j", "REDIRECT", "--to-ports", "1053")
		} else {
			_ = runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_PRE",
				"-p", proto, "--dport", "53", "-j", "RETURN")
		}
	}

	for _, cidr := range bypassCIDRsV4 {
		_ = runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_PRE", "-d", cidr, "-j", "RETURN")
	}

	if BlockQUIC {
		_ = runCmd("iptables", "-I", "FORWARD", "1", "-p", "udp", "--dport", "443", "-j", "DROP")
		if st.LocalhostProxy {
			_ = runCmd("iptables", "-I", "OUTPUT", "1",
				"-m", "owner", "!", "--gid-owner", strconv.Itoa(XrayGID),
				"-m", "mark", "!", "--mark", BypassHex+"/"+BypassHex,
				"-p", "udp", "--dport", "443", "-j", "REJECT")
		}
	}

	setupDoTBlockIptables(st)

	if err := runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_PRE",
		"-p", "tcp", "-j", "REDIRECT", "--to-ports", redirPort); err != nil {
		return err
	}

	if !st.LocalhostProxy {
		_ = runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_OUT", "-j", "RETURN")
	} else {
		for _, proto := range []string{"udp", "tcp"} {
			if dnsRedirect {
				_ = runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_OUT",
					"-p", proto, "--dport", "53", "-j", "REDIRECT", "--to-ports", "1053")
			} else {
				_ = runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_OUT",
					"-p", proto, "--dport", "53", "-j", "RETURN")
			}
		}
		for _, cidr := range bypassCIDRsV4 {
			_ = runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_OUT", "-d", cidr, "-j", "RETURN")
		}

		if st.AppFilterMode == "proxy" {
			for _, uid := range st.SelectedUIDs {
				_ = runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_OUT",
					"-m", "owner", "--uid-owner", strconv.Itoa(uid),
					"-p", "tcp", "-j", "REDIRECT", "--to-ports", redirPort)
			}
		} else {
			for _, uid := range st.SelectedUIDs {
				_ = runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_OUT",
					"-m", "owner", "--uid-owner", strconv.Itoa(uid), "-j", "RETURN")
			}
			if err := runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_OUT",
				"-p", "tcp", "-j", "REDIRECT", "--to-ports", redirPort); err != nil {
				return err
			}
		}
	}

	if err := runCmd("iptables", "-t", "nat", "-I", "PREROUTING", "1", "-j", "PASSWALL_NAT_PRE"); err != nil {
		return err
	}
	if err := runCmd("iptables", "-t", "nat", "-I", "OUTPUT", "1", "-j", "PASSWALL_NAT_OUT"); err != nil {
		return err
	}

	_ = runCmd("iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", redirPort, "-j", "ACCEPT")
	_ = runCmd("iptables", "-I", "INPUT", "1", "-p", "udp", "--dport", redirPort, "-j", "ACCEPT")
	_ = runCmd("iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", "1053", "-j", "ACCEPT")
	_ = runCmd("iptables", "-I", "INPUT", "1", "-p", "udp", "--dport", "1053", "-j", "ACCEPT")
	_ = runCmd("iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", "9090", "-j", "ACCEPT")

	_ = runCmd("iptables", "-I", "FORWARD", "1", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	for i, iface := range []string{"ap+", "wlan+", "swlan+", "rndis+", "usb+", "eth+"} {
		_ = runCmd("iptables", "-I", "FORWARD", strconv.Itoa(i+2), "-i", iface, "-j", "ACCEPT")
	}

	_ = runCmd("iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-s", "192.168.0.0/16", "-j", "MASQUERADE")
	_ = runCmd("iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-s", "172.16.0.0/12", "-j", "MASQUERADE")
	_ = runCmd("iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-s", "10.0.0.0/8", "-j", "MASQUERADE")

	return nil
}

func cleanupIptables() {
	tproxyTarget := strconv.Itoa(TproxyPort)
	markSpec := FwMark + "/" + FwMask

	runCmdIgnoreErr("iptables", "-t", "mangle", "-D", "PREROUTING", "-j", "PASSWALL_PRE")
	runCmdIgnoreErr("iptables", "-t", "mangle", "-D", "OUTPUT", "-j", "PASSWALL_OUT")
	runCmdIgnoreErr("iptables", "-t", "mangle", "-F", "PASSWALL_PRE")
	runCmdIgnoreErr("iptables", "-t", "mangle", "-X", "PASSWALL_PRE")
	runCmdIgnoreErr("iptables", "-t", "mangle", "-F", "PASSWALL_OUT")
	runCmdIgnoreErr("iptables", "-t", "mangle", "-X", "PASSWALL_OUT")

	runCmdIgnoreErr("iptables", "-t", "nat", "-D", "PREROUTING", "-j", "PASSWALL_NAT_PRE")
	runCmdIgnoreErr("iptables", "-t", "nat", "-D", "OUTPUT", "-j", "PASSWALL_NAT_OUT")
	runCmdIgnoreErr("iptables", "-t", "nat", "-F", "PASSWALL_NAT_PRE")
	runCmdIgnoreErr("iptables", "-t", "nat", "-X", "PASSWALL_NAT_PRE")
	runCmdIgnoreErr("iptables", "-t", "nat", "-F", "PASSWALL_NAT_OUT")
	runCmdIgnoreErr("iptables", "-t", "nat", "-X", "PASSWALL_NAT_OUT")

	runCmdIgnoreErr("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "192.168.0.0/16", "-j", "MASQUERADE")
	runCmdIgnoreErr("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "172.16.0.0/12", "-j", "MASQUERADE")
	runCmdIgnoreErr("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "10.0.0.0/8", "-j", "MASQUERADE")

	runCmdIgnoreErr("iptables", "-D", "INPUT", "-m", "mark", "--mark", markSpec, "-j", "ACCEPT")
	runCmdIgnoreErr("iptables", "-D", "INPUT", "-p", "tcp", "--dport", tproxyTarget, "-j", "ACCEPT")
	runCmdIgnoreErr("iptables", "-D", "INPUT", "-p", "udp", "--dport", tproxyTarget, "-j", "ACCEPT")
	runCmdIgnoreErr("iptables", "-D", "INPUT", "-p", "tcp", "--dport", "1053", "-j", "ACCEPT")
	runCmdIgnoreErr("iptables", "-D", "INPUT", "-p", "udp", "--dport", "1053", "-j", "ACCEPT")
	runCmdIgnoreErr("iptables", "-D", "INPUT", "-p", "tcp", "--dport", "9090", "-j", "ACCEPT")

	runCmdIgnoreErr("iptables", "-D", "FORWARD", "-p", "udp", "--dport", "443", "-j", "DROP")
	runCmdIgnoreErr("iptables", "-D", "FORWARD", "-p", "tcp", "--dport", "853", "-j", "REJECT", "--reject-with", "tcp-reset")
	runCmdIgnoreErr("iptables", "-D", "FORWARD", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	for _, iface := range []string{"ap+", "wlan+", "swlan+", "rndis+", "usb+", "eth+"} {
		runCmdIgnoreErr("iptables", "-D", "FORWARD", "-i", iface, "-j", "ACCEPT")
	}

	runCmdIgnoreErr("iptables", "-D", "OUTPUT", "-m", "owner", "!", "--gid-owner", strconv.Itoa(XrayGID),
		"-m", "mark", "!", "--mark", BypassHex+"/"+BypassHex,
		"-p", "udp", "--dport", "443", "-j", "REJECT")
	runCmdIgnoreErr("iptables", "-D", "OUTPUT", "-m", "owner", "!", "--gid-owner", strconv.Itoa(XrayGID),
		"-p", "udp", "--dport", "443", "-j", "REJECT")
	runCmdIgnoreErr("iptables", "-D", "OUTPUT", "-m", "owner", "!", "--gid-owner", strconv.Itoa(XrayGID),
		"-m", "mark", "!", "--mark", BypassHex+"/"+BypassHex,
		"-p", "tcp", "--dport", "853", "-j", "REJECT", "--reject-with", "tcp-reset")
	runCmdIgnoreErr("ip6tables", "-D", "FORWARD", "-j", "DROP")
	runCmdIgnoreErr("ip6tables", "-D", "OUTPUT", "-j", "REJECT")
}

func getAssetDir() string {
	if _, err := os.Stat(filepath.Join(AssetDir, "geoip.dat")); err == nil {
		return AssetDir
	}
	binDir := filepath.Join(BaseDir, "bin")
	if _, err := os.Stat(filepath.Join(binDir, "geoip.dat")); err == nil {
		return binDir
	}
	cfgDir := filepath.Join(BaseDir, "config")
	if _, err := os.Stat(filepath.Join(cfgDir, "geoip.dat")); err == nil {
		return cfgDir
	}
	if _, err := os.Stat(filepath.Join(BaseDir, "geoip.dat")); err == nil {
		return BaseDir
	}
	return AssetDir
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func getGeoAssetInfo() GeoAssetsStatus {
	assetDir := getAssetDir()
	status := GeoAssetsStatus{
		AssetDir: assetDir,
		GeoIP: GeoAssetFile{
			Name: "geoip.dat",
			Path: filepath.Join(assetDir, "geoip.dat"),
		},
		GeoSite: GeoAssetFile{
			Name: "geosite.dat",
			Path: filepath.Join(assetDir, "geosite.dat"),
		},
	}

	if info, err := os.Stat(status.GeoIP.Path); err == nil {
		status.GeoIP.Exists = true
		status.GeoIP.SizeBytes = info.Size()
		status.GeoIP.SizeFormatted = formatBytes(info.Size())
		status.GeoIP.ModTime = info.ModTime().Format("2006-01-02 15:04:05")
	} else {
		status.GeoIP.SizeFormatted = "Not found"
	}

	if info, err := os.Stat(status.GeoSite.Path); err == nil {
		status.GeoSite.Exists = true
		status.GeoSite.SizeBytes = info.Size()
		status.GeoSite.SizeFormatted = formatBytes(info.Size())
		status.GeoSite.ModTime = info.ModTime().Format("2006-01-02 15:04:05")
	} else {
		status.GeoSite.SizeFormatted = "Not found"
	}

	return status
}

func sanitizeStringList(list []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, item := range list {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" && !seen[trimmed] {
			seen[trimmed] = true
			result = append(result, trimmed)
		}
	}
	if result == nil {
		return []string{}
	}
	return result
}

func downloadGeoFile(fileURL, targetPath string) (int64, error) {
	client := &http.Client{
		Timeout: 90 * time.Second,
		Transport: &http.Transport{
			DialContext: directDialer(15 * time.Second).DialContext,
		},
	}
	req, err := http.NewRequest(http.MethodGet, fileURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Passwall-Android/"+getModuleVersion())

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("download error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP error %s", resp.Status)
	}

	tmpPath := targetPath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return 0, fmt.Errorf("create file error: %w", err)
	}

	n, err := io.Copy(f, resp.Body)
	_ = f.Close()
	if err != nil {
		_ = os.Remove(tmpPath)
		return 0, fmt.Errorf("write error: %w", err)
	}

	if n < 1024 {
		_ = os.Remove(tmpPath)
		return 0, fmt.Errorf("downloaded file too small (%d bytes), likely an error page", n)
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		data, readErr := os.ReadFile(tmpPath)
		if readErr != nil {
			_ = os.Remove(tmpPath)
			return 0, err
		}
		if writeErr := os.WriteFile(targetPath, data, 0644); writeErr != nil {
			_ = os.Remove(tmpPath)
			return 0, writeErr
		}
		_ = os.Remove(tmpPath)
	}

	return n, nil
}

func updateGeoAssets(geoIPURL, geoSiteURL string) error {
	st := loadState()
	if strings.TrimSpace(geoIPURL) == "" {
		geoIPURL = st.Geo.GeoIPURL
	}
	if strings.TrimSpace(geoIPURL) == "" {
		geoIPURL = "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geoip.dat"
	}
	if strings.TrimSpace(geoSiteURL) == "" {
		geoSiteURL = st.Geo.GeoSiteURL
	}
	if strings.TrimSpace(geoSiteURL) == "" {
		geoSiteURL = "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geosite.dat"
	}

	assetDir := getAssetDir()
	_ = os.MkdirAll(assetDir, 0755)

	geoipTarget := filepath.Join(assetDir, "geoip.dat")
	geositeTarget := filepath.Join(assetDir, "geosite.dat")

	log.Printf("[passwall-droid] downloading geoip from %s", geoIPURL)
	nIP, err := downloadGeoFile(geoIPURL, geoipTarget)
	if err != nil {
		return fmt.Errorf("failed downloading geoip.dat: %w", err)
	}

	log.Printf("[passwall-droid] downloading geosite from %s", geoSiteURL)
	nSite, err := downloadGeoFile(geoSiteURL, geositeTarget)
	if err != nil {
		return fmt.Errorf("failed downloading geosite.dat: %w", err)
	}

	log.Printf("[passwall-droid] geo assets updated successfully (geoip: %d bytes, geosite: %d bytes)", nIP, nSite)

	if _, err := os.Stat(PersistDir); err == nil {
		if data, err := os.ReadFile(geoipTarget); err == nil {
			_ = os.WriteFile(filepath.Join(PersistDir, "geoip.dat"), data, 0644)
		}
		if data, err := os.ReadFile(geositeTarget); err == nil {
			_ = os.WriteFile(filepath.Join(PersistDir, "geosite.dat"), data, 0644)
		}
	}

	st.Geo.GeoIPURL = geoIPURL
	st.Geo.GeoSiteURL = geoSiteURL
	st.Geo.LastGeoUpdate = time.Now().Format("2006-01-02 15:04:05")
	_ = saveState(st)

	engineMu.Lock()
	active := engineActive
	engineMu.Unlock()
	if active {
		_ = restartProxyEngine()
	}
	return nil
}

func superviseXray(stopCh <-chan struct{}, doneCh chan<- struct{}) {
	defer close(doneCh)
	raiseFileLimits()

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		log.Println("[passwall-droid] starting xray-core...")
		assetDir := getAssetDir()
		cmd := exec.Command(XrayBin, "run", "-c", RuntimeConfig)
		cmd.Dir = assetDir
		cmd.Env = append(os.Environ(),
			"XRAY_LOCATION_ASSET="+assetDir,
			"xray.location.asset="+assetDir,
			"V2RAY_LOCATION_ASSET="+assetDir,
			"v2ray.location.asset="+assetDir,
			"GOGC=80",
			"GOMEMLIMIT=128MiB",
		)
		cmd.Stdout = logSink
		cmd.Stderr = logSink

		configureProcessCredentials(cmd, XrayGID)

		if err := cmd.Start(); err != nil {
			log.Printf("[passwall-droid] xray start error: %v; retrying in 3s", err)
			time.Sleep(3 * time.Second)
			continue
		}
		setXrayPID(cmd.Process.Pid)

		waitCh := make(chan error, 1)
		go func() {
			waitCh <- cmd.Wait()
		}()

		select {
		case <-stopCh:
			log.Println("[passwall-droid] stopping xray-core...")
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-waitCh:
			case <-time.After(3 * time.Second):
				_ = cmd.Process.Kill()
			}
			setXrayPID(0)
			return
		case err := <-waitCh:
			setXrayPID(0)
			log.Printf("[passwall-droid] xray exited (%v); restarting in 2s...", err)
			time.Sleep(2 * time.Second)
		}
	}
}

func startProxyEngine() error {
	engineMu.Lock()
	defer engineMu.Unlock()

	if engineActive {
		return nil
	}

	cleanupIptables()
	configureKernelAndTether()
	invalidateXrayVersion()

	if err := prepareRuntimeConfig(useTproxy); err != nil {
		return err
	}

	if useTproxy {
		if err := setupPolicyRouting(); err != nil {
			return err
		}
		if err := setupTproxyIptables(); err != nil {
			cleanupPolicyRouting()
			return err
		}
	} else {
		if err := setupRedirectIptables(); err != nil {
			return err
		}
	}

	xrayStopCh = make(chan struct{})
	xrayDoneCh = make(chan struct{})
	engineActive = true
	go superviseXray(xrayStopCh, xrayDoneCh)

	modeName := "REDIRECT (nat)"
	if useTproxy {
		modeName = "TPROXY (mangle)"
	}
	log.Printf("[passwall-droid] proxy engine active (%s)", modeName)
	return nil
}

func stopProxyEngine() {
	engineMu.Lock()
	defer engineMu.Unlock()

	if !engineActive {
		cleanupIptables()
		cleanupPolicyRouting()
		return
	}

	close(xrayStopCh)
	<-xrayDoneCh
	setXrayPID(0)
	cleanupIptables()
	cleanupPolicyRouting()
	engineActive = false
	log.Println("[passwall-droid] proxy engine stopped")
}

func restartProxyEngine() error {
	stopProxyEngine()
	time.Sleep(150 * time.Millisecond)
	return startProxyEngine()
}

func watchdogLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		engineMu.Lock()
		active := engineActive
		tproxy := useTproxy
		engineMu.Unlock()

		if !active {
			continue
		}

		writeSysctl("/proc/sys/net/ipv4/ip_forward", "1")
		if matches, err := filepath.Glob("/proc/sys/net/ipv4/conf/*/rp_filter"); err == nil {
			for _, m := range matches {
				writeSysctl(m, "0")
			}
		}

		if tproxy {
			if err := runCmd("iptables", "-t", "mangle", "-C", "PREROUTING", "-j", "PASSWALL_PRE"); err != nil {
				log.Println("[passwall-droid] watchdog: restoring flushed TPROXY rules...")
				engineMu.Lock()
				cleanupIptables()
				_ = setupPolicyRouting()
				_ = setupTproxyIptables()
				engineMu.Unlock()
			}
		} else {
			if err := runCmd("iptables", "-t", "nat", "-C", "PREROUTING", "-j", "PASSWALL_NAT_PRE"); err != nil {
				log.Println("[passwall-droid] watchdog: restoring flushed REDIRECT rules...")
				engineMu.Lock()
				cleanupIptables()
				_ = setupRedirectIptables()
				engineMu.Unlock()
			}
		}
	}
}

func decodeBase64Flexible(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.StdEncoding.DecodeString(s)
}

func parseShareURI(rawURI string, group string) (NodeProfile, error) {
	rawURI = strings.TrimSpace(rawURI)
	id := fmt.Sprintf("%s-%d", group, time.Now().UnixNano())

	if strings.HasPrefix(rawURI, "vmess://") {
		decoded, err := decodeBase64Flexible(strings.TrimPrefix(rawURI, "vmess://"))
		if err != nil {
			return NodeProfile{}, fmt.Errorf("invalid vmess base64: %v", err)
		}
		var v map[string]interface{}
		if err := json.Unmarshal(decoded, &v); err != nil {
			return NodeProfile{}, fmt.Errorf("invalid vmess json: %v", err)
		}
		addr, _ := v["add"].(string)
		uuid, _ := v["id"].(string)
		ps, _ := v["ps"].(string)
		netType, _ := v["net"].(string)
		hdrType, _ := v["type"].(string)
		tlsType, _ := v["tls"].(string)
		host, _ := v["host"].(string)
		path, _ := v["path"].(string)
		sni, _ := v["sni"].(string)
		fp, _ := v["fp"].(string)
		alpn, _ := v["alpn"].(string)
		scy, _ := v["scy"].(string)
		if scy == "" {
			scy = "auto"
		}
		aid := jsonIntValue(v["aid"])
		if aid < 0 {
			aid = 0
		}
		port := jsonIntValue(v["port"])
		if port <= 0 {
			port = 443
		}
		if ps == "" {
			ps = fmt.Sprintf("vmess-%s:%d", addr, port)
		}
		if netType == "" {
			netType = "tcp"
		}
		if netType == "splithttp" {
			netType = "xhttp"
		}
		ss := map[string]interface{}{"network": netType}
		if strings.EqualFold(tlsType, "tls") {
			ss["security"] = "tls"
			if sni == "" {
				sni = host
			}
			tlsSet := map[string]interface{}{}
			if sni != "" {
				tlsSet["serverName"] = sni
			}
			if fp != "" {
				tlsSet["fingerprint"] = fp
			}
			if alpnArr := parseALPNList(alpn); len(alpnArr) > 0 {
				tlsSet["alpn"] = alpnArr
			}
			allowInsec := false
			switch ai := v["allowInsecure"].(type) {
			case bool:
				allowInsec = ai
			case float64:
				allowInsec = ai != 0
			case string:
				allowInsec = ai == "1" || strings.EqualFold(ai, "true")
			}
			if !allowInsec {
				if insecStr, ok := v["insecure"].(string); ok {
					allowInsec = insecStr == "1" || strings.EqualFold(insecStr, "true")
				}
			}
			if allowInsec {
				tlsSet["allowInsecure"] = true
			}
			ss["tlsSettings"] = tlsSet
		}
		switch netType {
		case "ws":
			ws := map[string]interface{}{"path": path}
			if host != "" {
				ws["headers"] = map[string]interface{}{"Host": host}
			}
			ss["wsSettings"] = ws
		case "xhttp":
			xh := map[string]interface{}{"path": path}
			if host != "" {
				xh["host"] = host
			}
			ss["xhttpSettings"] = xh
		case "httpupgrade":
			hu := map[string]interface{}{"path": path}
			if host != "" {
				hu["host"] = host
			}
			ss["httpupgradeSettings"] = hu
		case "grpc":
			gs := map[string]interface{}{"serviceName": path}
			if hdrType == "multi" {
				gs["multiMode"] = true
			}
			ss["grpcSettings"] = gs
		case "tcp":
			if hdrType == "http" {
				reqPath := path
				if reqPath == "" {
					reqPath = "/"
				}
				reqHdr := map[string]interface{}{
					"version": "1.1",
					"method":  "GET",
					"path":    []interface{}{reqPath},
				}
				if host != "" {
					reqHdr["headers"] = map[string]interface{}{"Host": []interface{}{host}}
				}
				ss["tcpSettings"] = map[string]interface{}{
					"header": map[string]interface{}{"type": "http", "request": reqHdr},
				}
			}
		}
		ob := map[string]interface{}{
			"tag":      "proxy",
			"protocol": "vmess",
			"settings": map[string]interface{}{
				"vnext": []interface{}{
					map[string]interface{}{
						"address": addr,
						"port":    port,
						"users": []interface{}{
							map[string]interface{}{"id": uuid, "alterId": aid, "security": scy},
						},
					},
				},
			},
			"streamSettings": ss,
		}
		return NodeProfile{
			ID: id, Name: ps, Group: group, Protocol: "vmess", Address: addr, Port: port, Outbound: ob,
		}, nil
	}

	if strings.HasPrefix(rawURI, "ss://") {
		u, err := url.Parse(rawURI)
		if err != nil {
			return NodeProfile{}, fmt.Errorf("invalid ss URI: %v", err)
		}
		name := u.Fragment
		var method, password, addr string
		var port int

		if u.Host != "" && u.User != nil {
			addr = u.Hostname()
			port, _ = strconv.Atoi(u.Port())
			userInfo := u.User.Username()
			if pw, hasPw := u.User.Password(); hasPw {
				method = userInfo
				password = pw
			} else if dec, err := decodeBase64Flexible(userInfo); err == nil {
				parts := strings.SplitN(string(dec), ":", 2)
				if len(parts) == 2 {
					method, password = parts[0], parts[1]
				}
			}
		} else {
			rawBody := strings.TrimPrefix(rawURI, "ss://")
			if idx := strings.Index(rawBody, "#"); idx != -1 {
				rawBody = rawBody[:idx]
			}
			dec, err := decodeBase64Flexible(rawBody)
			if err != nil {
				return NodeProfile{}, fmt.Errorf("invalid legacy ss URI: %v", err)
			}
			atIdx := strings.LastIndex(string(dec), "@")
			if atIdx == -1 {
				return NodeProfile{}, fmt.Errorf("malformed ss payload")
			}
			creds := strings.SplitN(string(dec)[:atIdx], ":", 2)
			hostPort := string(dec)[atIdx+1:]
			h, pStr, err := net.SplitHostPort(hostPort)
			if err != nil || len(creds) != 2 {
				return NodeProfile{}, fmt.Errorf("malformed ss host:port")
			}
			method, password, addr = creds[0], creds[1], h
			port, _ = strconv.Atoi(pStr)
		}
		if port == 0 {
			port = 8388
		}
		if name == "" {
			name = fmt.Sprintf("ss-%s:%d", addr, port)
		}
		ob := map[string]interface{}{
			"tag":      "proxy",
			"protocol": "shadowsocks",
			"settings": map[string]interface{}{
				"servers": []interface{}{
					map[string]interface{}{
						"address":  addr,
						"port":     port,
						"method":   method,
						"password": password,
					},
				},
			},
		}
		return NodeProfile{
			ID: id, Name: name, Group: group, Protocol: "shadowsocks", Address: addr, Port: port, Outbound: ob,
		}, nil
	}

	normalizedURI := portHopRe.ReplaceAllString(rawURI, ":$1$2")
	u, err := url.Parse(normalizedURI)
	if err != nil {
		return NodeProfile{}, fmt.Errorf("invalid URI: %v", err)
	}
	proto := strings.ToLower(u.Scheme)
	if proto != "vless" && proto != "trojan" && proto != "hysteria" && proto != "hysteria2" && proto != "hy2" {
		return NodeProfile{}, fmt.Errorf("unsupported scheme %q", proto)
	}

	addr := u.Hostname()
	portStr := u.Port()
	if idx := strings.IndexAny(portStr, "-,"); idx != -1 {
		portStr = portStr[:idx]
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port == 0 {
		port = 443
	}

	var userID string
	if u.User != nil {
		userID = u.User.Username()
		if pw, hasPw := u.User.Password(); hasPw && proto == "trojan" {
			userID = userID + ":" + pw
		}
	}

	q := u.Query()
	name := u.Fragment
	if name == "" {
		name = fmt.Sprintf("%s-%s:%d", proto, addr, port)
	}

	if proto == "hysteria" || proto == "hysteria2" || proto == "hy2" {
		auth := userID
		if u.User != nil {
			if pw, hasPw := u.User.Password(); hasPw {
				auth = userID + ":" + pw
			}
		}
		if auth == "" {
			auth = q.Get("auth")
		}

		sni := q.Get("sni")
		if sni == "" {
			sni = q.Get("peer")
		}
		if sni == "" {
			sni = addr
		}

		insecureVal := q.Get("insecure")
		if insecureVal == "" {
			insecureVal = q.Get("allowInsecure")
		}
		allowInsecure := insecureVal == "1" || strings.ToLower(insecureVal) == "true"

		alpnList := []interface{}{"h3"}
		if alpn := q.Get("alpn"); alpn != "" {
			var parts []interface{}
			for _, p := range strings.Split(alpn, ",") {
				if trimmed := strings.TrimSpace(p); trimmed != "" {
					parts = append(parts, trimmed)
				}
			}
			if len(parts) > 0 {
				alpnList = parts
			}
		}

		tlsSettings := map[string]interface{}{
			"serverName":    sni,
			"alpn":          alpnList,
			"allowInsecure": allowInsecure,
		}
		fp := q.Get("fp")
		if fp == "" {
			fp = q.Get("fingerprint")
		}
		if fp == "" {
			fp = "chrome"
		}
		tlsSettings["fingerprint"] = fp

		if pin := q.Get("pinSHA256"); pin != "" {
			tlsSettings["pinnedPeerCertificateSha256"] = pin
		}

		hysteriaSettings := map[string]interface{}{
			"version":        2,
			"auth":           auth,
			"udpIdleTimeout": 60,
		}

		up := q.Get("up")
		if up == "" {
			up = q.Get("upmbps")
		}
		if up != "" {
			if !strings.Contains(up, " ") {
				up = up + " mbps"
			}
			hysteriaSettings["up"] = up
		}

		down := q.Get("down")
		if down == "" {
			down = q.Get("downmbps")
		}
		if down != "" {
			if !strings.Contains(down, " ") {
				down = down + " mbps"
			}
			hysteriaSettings["down"] = down
		}

		ss := map[string]interface{}{
			"network":          "hysteria",
			"security":         "tls",
			"tlsSettings":      tlsSettings,
			"hysteriaSettings": hysteriaSettings,
		}

		obfsType := q.Get("obfs")
		obfsPass := q.Get("obfs-password")
		if obfsType != "" && obfsPass != "" {
			maskObj := []interface{}{
				map[string]interface{}{
					"type": obfsType,
					"settings": map[string]interface{}{
						"password": obfsPass,
					},
				},
			}
			ss["finalmask"] = map[string]interface{}{
				"udp": maskObj,
			}
			ss["udpmasks"] = maskObj
		}

		ob := map[string]interface{}{
			"tag":      "proxy",
			"protocol": "hysteria",
			"settings": map[string]interface{}{
				"version": 2,
				"address": addr,
				"port":    port,
			},
			"streamSettings": ss,
		}

		return NodeProfile{
			ID: id, Name: name, Group: group, Protocol: "hysteria2", Address: addr, Port: port, Outbound: ob,
		}, nil
	}

	netType := strings.ToLower(q.Get("type"))
	if netType == "" {
		netType = "tcp"
	}
	security := strings.ToLower(q.Get("security"))
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("host")
	}
	fp := q.Get("fp")
	if fp == "" {
		fp = q.Get("fingerprint")
	}
	path := q.Get("path")
	if path == "" {
		path = "/"
	}
	host := q.Get("host")

	ss := map[string]interface{}{
		"network": netType,
	}
	if security == "tls" {
		tlsSet := map[string]interface{}{}
		if sni != "" {
			tlsSet["serverName"] = sni
		}
		if fp != "" {
			tlsSet["fingerprint"] = fp
		}
		if alpnArr := parseALPNList(q.Get("alpn")); len(alpnArr) > 0 {
			tlsSet["alpn"] = alpnArr
		}
		insecVal := q.Get("allowInsecure")
		if insecVal == "" {
			insecVal = q.Get("insecure")
		}
		if insecVal == "1" || strings.EqualFold(insecVal, "true") {
			tlsSet["allowInsecure"] = true
		}
		if pin := q.Get("pinSHA256"); pin != "" {
			tlsSet["pinnedPeerCertificateSha256"] = pin
		}
		ss["security"] = "tls"
		ss["tlsSettings"] = tlsSet
	} else if security == "reality" {
		if fp == "" {
			fp = "chrome"
		}
		ss["security"] = "reality"
		ss["realitySettings"] = map[string]interface{}{
			"serverName":  sni,
			"fingerprint": fp,
			"publicKey":   q.Get("pbk"),
			"shortId":     q.Get("sid"),
			"spiderX":     q.Get("spx"),
		}
	}

	switch netType {
	case "tcp", "raw":
		ss["network"] = "tcp"
		if strings.EqualFold(q.Get("headerType"), "http") {
			reqHdr := map[string]interface{}{
				"version": "1.1",
				"method":  "GET",
				"path":    []interface{}{path},
			}
			if host != "" {
				reqHdr["headers"] = map[string]interface{}{"Host": []interface{}{host}}
			}
			ss["tcpSettings"] = map[string]interface{}{
				"header": map[string]interface{}{"type": "http", "request": reqHdr},
			}
		}
	case "ws":
		ws := map[string]interface{}{"path": path}
		if host != "" {
			ws["headers"] = map[string]interface{}{"Host": host}
		}
		ss["wsSettings"] = ws
	case "xhttp", "splithttp":
		xh := map[string]interface{}{"path": path}
		if host != "" {
			xh["host"] = host
		}
		if mode := q.Get("mode"); mode != "" {
			xh["mode"] = mode
		}
		ss["network"] = "xhttp"
		ss["xhttpSettings"] = xh
	case "httpupgrade":
		hu := map[string]interface{}{"path": path}
		if host != "" {
			hu["host"] = host
		}
		ss["httpupgradeSettings"] = hu
	case "grpc":
		gs := map[string]interface{}{
			"serviceName": q.Get("serviceName"),
		}
		if strings.EqualFold(q.Get("mode"), "multi") {
			gs["multiMode"] = true
		}
		if auth := q.Get("authority"); auth != "" {
			gs["authority"] = auth
		}
		ss["grpcSettings"] = gs
	case "kcp":
		ks := map[string]interface{}{}
		if ht := q.Get("headerType"); ht != "" && ht != "none" {
			ks["header"] = map[string]interface{}{"type": ht}
		}
		if seed := q.Get("seed"); seed != "" {
			ks["seed"] = seed
		}
		ss["kcpSettings"] = ks
	}

	var settings map[string]interface{}
	if proto == "vless" {
		enc := strings.TrimSpace(q.Get("encryption"))
		if enc == "" {
			enc = "none"
		}
		userObj := map[string]interface{}{
			"id":         userID,
			"encryption": enc,
		}
		if flow := q.Get("flow"); flow != "" {
			userObj["flow"] = flow
		}
		settings = map[string]interface{}{
			"vnext": []interface{}{
				map[string]interface{}{
					"address": addr,
					"port":    port,
					"users":   []interface{}{userObj},
				},
			},
		}
	} else {
		settings = map[string]interface{}{
			"servers": []interface{}{
				map[string]interface{}{
					"address":  addr,
					"port":     port,
					"password": userID,
				},
			},
		}
	}

	ob := map[string]interface{}{
		"tag":            "proxy",
		"protocol":       proto,
		"settings":       settings,
		"streamSettings": ss,
	}

	return NodeProfile{
		ID: id, Name: name, Group: group, Protocol: proto, Address: addr, Port: port, Outbound: ob,
	}, nil
}

func updateSubscription(subURL string, insecure bool) (int, error) {
	subURL = strings.TrimSpace(subURL)
	if subURL == "" {
		return 0, fmt.Errorf("subscription URL is empty")
	}

	tr := &http.Transport{
		DialContext: directDialer(12 * time.Second).DialContext,
	}
	if insecure {
		tr.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	client := &http.Client{
		Timeout:   20 * time.Second,
		Transport: tr,
	}

	req, err := http.NewRequest(http.MethodGet, subURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Passwall-Android/1.2")

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetch failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("HTTP %d from subscription server", resp.StatusCode)
	}

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return 0, err
	}

	text := strings.TrimSpace(string(rawBody))
	if !strings.Contains(text, "://") {
		if decoded, decErr := decodeBase64Flexible(text); decErr == nil {
			text = string(decoded)
		}
	}

	var parsedNodes []NodeProfile
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "://") {
			continue
		}
		if node, err := parseShareURI(line, "sub"); err == nil {
			parsedNodes = append(parsedNodes, node)
		}
	}

	if len(parsedNodes) == 0 {
		return 0, fmt.Errorf("no valid vless/trojan/vmess/ss/hysteria nodes found in subscription")
	}

	st := loadState()
	var kept []NodeProfile
	activeStillExists := false
	for _, existing := range st.Nodes {
		if existing.Group != "sub" {
			kept = append(kept, existing)
			if existing.ID == st.ActiveNode {
				activeStillExists = true
			}
		}
	}
	kept = append(kept, parsedNodes...)

	st.SubURL = subURL
	st.LastSubUpdate = time.Now().Format("2006-01-02 15:04")
	st.Nodes = kept
	if !activeStillExists && len(parsedNodes) > 0 {
		st.ActiveNode = parsedNodes[0].ID
	}
	_ = saveState(st)
	log.Printf("[passwall-droid] subscription updated: %d nodes imported", len(parsedNodes))
	return len(parsedNodes), nil
}

func subscriptionAutoUpdater() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		st := loadState()
		if st.AutoUpdateHours <= 0 || st.SubURL == "" {
			continue
		}
		needUpdate := true
		if st.LastSubUpdate != "" {
			if last, err := time.ParseInLocation("2006-01-02 15:04", st.LastSubUpdate, time.Local); err == nil {
				if time.Since(last) < time.Duration(st.AutoUpdateHours)*time.Hour {
					needUpdate = false
				}
			}
		}
		if needUpdate {
			if count, err := updateSubscription(st.SubURL, st.SubInsecure); err == nil && count > 0 {
				_ = restartProxyEngine()
			}
		}
	}
}

func measureHysteriaLatency(n NodeProfile, dialer *net.Dialer) int {
	target := net.JoinHostPort(n.Address, strconv.Itoa(n.Port))
	start := time.Now()

	uConn, err := dialer.Dial("udp", target)
	if err != nil {
		return -1
	}
	defer uConn.Close()

	// Send RFC 9000 QUIC Version Negotiation probe datagram (1200 bytes)
	probe := make([]byte, 1200)
	probe[0] = 0xc0 // Long Header, Initial
	// 0x1a2a3a4a: experimental/unsupported version to force Version Negotiation
	probe[1], probe[2], probe[3], probe[4] = 0x1a, 0x2a, 0x3a, 0x4a
	probe[5] = 8 // DCIL
	copy(probe[6:14], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	probe[14] = 8 // SCIL
	copy(probe[15:23], []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01})

	_ = uConn.SetDeadline(time.Now().Add(2500 * time.Millisecond))
	if _, err := uConn.Write(probe); err != nil {
		return -1
	}

	buf := make([]byte, 1500)
	nBytes, err := uConn.Read(buf)
	if err == nil && nBytes > 0 {
		ms := int(time.Since(start).Milliseconds())
		if ms < 1 {
			ms = 1
		}
		return ms
	}

	// For obfuscated UDP servers (e.g. Salamander) that drop unmasked QUIC probes,
	// test if server has a reachable TCP listener or responding endpoint:
	tcpDialer := directDialer(1500 * time.Millisecond)
	tcpStart := time.Now()
	if tConn, tErr := tcpDialer.Dial("tcp", target); tErr == nil {
		_ = tConn.Close()
		ms := int(time.Since(tcpStart).Milliseconds())
		if ms < 1 {
			ms = 1
		}
		return ms
	}

	// If UDP socket write completed without socket failure within reasonable RTT:
	ms := int(time.Since(start).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	if ms < 1000 {
		return ms
	}
	return -1
}

func measureNodeLatency(n NodeProfile) int {
	dialer := directDialer(4 * time.Second)
	if n.Protocol == "hysteria2" || n.Protocol == "hysteria" {
		return measureHysteriaLatency(n, dialer)
	}

	target := net.JoinHostPort(n.Address, strconv.Itoa(n.Port))
	start := time.Now()
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		return -1
	}
	defer conn.Close()

	if ss, ok := n.Outbound["streamSettings"].(map[string]interface{}); ok {
		sec, _ := ss["security"].(string)
		if sec == "tls" || sec == "reality" {
			sni := n.Address
			if tlsSet, ok := ss["tlsSettings"].(map[string]interface{}); ok {
				if sn, _ := tlsSet["serverName"].(string); sn != "" {
					sni = sn
				}
			} else if realSet, ok := ss["realitySettings"].(map[string]interface{}); ok {
				if sn, _ := realSet["serverName"].(string); sn != "" {
					sni = sn
				}
			}
			_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
			tlsConn := tls.Client(conn, &tls.Config{
				ServerName:         sni,
				InsecureSkipVerify: true,
			})
			if err := tlsConn.Handshake(); err != nil {
				return -1
			}
		}
	}

	ms := int(time.Since(start).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	return ms
}

func pingNodes(targetID string, selectFastest bool) {
	st := loadState()
	if len(st.Nodes) == 0 {
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	results := make([]int, len(st.Nodes))
	for i := range st.Nodes {
		results[i] = st.Nodes[i].LatencyMs
	}

	for i, n := range st.Nodes {
		if targetID != "" && n.ID != targetID {
			continue
		}
		wg.Add(1)
		go func(idx int, node NodeProfile) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = measureNodeLatency(node)
		}(i, n)
	}
	wg.Wait()

	st = loadState()
	bestID := ""
	bestMs := 999999
	for i := range st.Nodes {
		if i < len(results) {
			st.Nodes[i].LatencyMs = results[i]
		}
		if st.Nodes[i].LatencyMs > 0 && st.Nodes[i].LatencyMs < bestMs {
			bestMs = st.Nodes[i].LatencyMs
			bestID = st.Nodes[i].ID
		}
	}

	switched := false
	if selectFastest && bestID != "" && st.ActiveNode != bestID {
		st.ActiveNode = bestID
		switched = true
	}
	_ = saveState(st)
	if switched {
		log.Printf("[passwall-droid] auto-selected fastest node (%d ms)", bestMs)
		_ = restartProxyEngine()
	}
}

func checkTargetConnectivity(client *http.Client, targetURL string) TargetStatus {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return TargetStatus{Reachable: false, LatencyMs: -1, Status: err.Error()}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return TargetStatus{Reachable: false, LatencyMs: -1, Status: "Connection error"}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	ms := int(time.Since(start).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return TargetStatus{Reachable: true, LatencyMs: ms, Status: fmt.Sprintf("%d OK", resp.StatusCode)}
	}
	return TargetStatus{Reachable: false, LatencyMs: ms, Status: fmt.Sprintf("HTTP %d", resp.StatusCode)}
}

func checkConnectivity() ConnectivityStatus {
	engineMu.Lock()
	active := engineActive
	engineMu.Unlock()

	if !active {
		return ConnectivityStatus{
			Google: TargetStatus{Reachable: false, LatencyMs: -1, Status: "Proxy stopped"},
			Github: TargetStatus{Reachable: false, LatencyMs: -1, Status: "Proxy stopped"},
		}
	}

	proxyURL, err := url.Parse("socks5://127.0.0.1:10808")
	var transport *http.Transport
	if err == nil {
		transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableKeepAlives: true,
		}
	} else {
		transport = &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   6 * time.Second,
	}

	var res ConnectivityStatus
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		res.Google = checkTargetConnectivity(client, "https://www.google.com/generate_204")
	}()
	go func() {
		defer wg.Done()
		res.Github = checkTargetConnectivity(client, "https://github.com")
	}()
	wg.Wait()
	return res
}

func buildWebMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashboardHTML))
	})

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		engineMu.Lock()
		active := engineActive
		tproxy := useTproxy
		engineMu.Unlock()

		st := loadState()
		netMode := "REDIRECT (nat)"
		if tproxy {
			netMode = "TPROXY (mangle)"
		}

		daemonPID := os.Getpid()
		currentXrayPID := getXrayPID()

		batPct, batStatus := getBatteryStatus()
		modCPU := getProcessCPU(daemonPID)
		modRAMBytes, modRAMStr := getProcessRAM(daemonPID)

		var xrayCPU float64
		var xrayRAMBytes int64
		var xrayRAMStr string = "0 B"
		if currentXrayPID > 0 {
			xrayCPU = getProcessCPU(currentXrayPID)
			xrayRAMBytes, xrayRAMStr = getProcessRAM(currentXrayPID)
		}

		resp := map[string]interface{}{
			"running":               active,
			"daemon_pid":            daemonPID,
			"net_mode":              netMode,
			"proxy_mode":            st.ProxyMode,
			"active_node":           st.ActiveNode,
			"sub_url":               st.SubURL,
			"sub_insecure":          st.SubInsecure,
			"auto_update_hours":     st.AutoUpdateHours,
			"last_sub_update":       st.LastSubUpdate,
			"app_filter_mode":       st.AppFilterMode,
			"selected_uids":         st.SelectedUIDs,
			"localhost_proxy":       st.LocalhostProxy,
			"allow_insecure_vless":  st.AllowInsecureVless,
			"vless_insecure_needed": activeNodeNeedsVlessSecurityBypass(st),
			"dns":                   st.DNS,
			"geo":                   st.Geo,
			"module_version":        getModuleVersion(),
			"xray_version":          getXrayVersion(),
			"nodes":                 st.Nodes,
			"battery_pct":           batPct,
			"battery_status":        batStatus,
			"module_pid":            daemonPID,
			"module_cpu":            modCPU,
			"module_ram":            modRAMBytes,
			"module_ram_str":        modRAMStr,
			"xray_pid":              currentXrayPID,
			"xray_cpu":              xrayCPU,
			"xray_ram":              xrayRAMBytes,
			"xray_ram_str":          xrayRAMStr,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api/control", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Action string `json:"action"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var err error
		switch req.Action {
		case "start":
			err = startProxyEngine()
		case "stop":
			stopProxyEngine()
		case "restart":
			err = restartProxyEngine()
		default:
			err = fmt.Errorf("unknown action")
		}
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/mode", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ProxyMode string `json:"proxy_mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		st := loadState()
		st.ProxyMode = req.ProxyMode
		_ = saveState(st)
		log.Printf("[passwall-droid] routing mode set to %s", req.ProxyMode)

		engineMu.Lock()
		active := engineActive
		engineMu.Unlock()

		var restartErr error
		if active {
			restartErr = restartProxyEngine()
		}

		w.Header().Set("Content-Type", "application/json")
		if restartErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": restartErr.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "ok",
			"mode":      req.ProxyMode,
			"restarted": active,
		})
	})

	mux.HandleFunc("/api/localhost_proxy", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			LocalhostProxy bool `json:"localhost_proxy"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		st := loadState()
		st.LocalhostProxy = req.LocalhostProxy
		_ = saveState(st)
		log.Printf("[passwall-droid] localhost proxy set to %v", req.LocalhostProxy)
		_ = restartProxyEngine()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/vless_insecure", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			AllowInsecureVless bool `json:"allow_insecure_vless"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		st := loadState()
		st.AllowInsecureVless = req.AllowInsecureVless
		if err := saveState(st); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		log.Printf("[passwall-droid] VLESS without TLS/encryption bypass set to %v", req.AllowInsecureVless)

		engineMu.Lock()
		active := engineActive
		engineMu.Unlock()
		if active {
			_ = restartProxyEngine()
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":               "ok",
			"allow_insecure_vless": st.AllowInsecureVless,
			"restarted":            active,
		})
	})

	mux.HandleFunc("/api/backup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		data, err := createBackupBundle()
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if r.URL.Query().Get("download") == "1" || r.URL.Query().Get("download") == "true" {
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"passwall-backup-%s.json\"", time.Now().Format("20060102-150405")))
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		}
		_, _ = w.Write(data)
	})

	mux.HandleFunc("/api/restore", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		var rawData []byte
		ct := strings.ToLower(r.Header.Get("Content-Type"))
		if strings.HasPrefix(ct, "multipart/form-data") {
			if err := r.ParseMultipartForm(16 << 20); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid multipart upload: " + err.Error()})
				return
			}
			f, _, err := r.FormFile("file")
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Missing backup file field: " + err.Error()})
				return
			}
			defer f.Close()
			rawData, err = io.ReadAll(io.LimitReader(f, 16<<20))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
		} else {
			var err error
			rawData, err = io.ReadAll(io.LimitReader(r.Body, 16<<20))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
		}

		restoredState, configRestored, err := restoreBackupBundle(rawData)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		engineMu.Lock()
		active := engineActive
		engineMu.Unlock()
		if active {
			_ = restartProxyEngine()
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":          "ok",
			"nodes":           len(restoredState.Nodes),
			"config_restored": configRestored,
			"restarted":       active,
		})
	})

	mux.HandleFunc("/api/connectivity", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		res := checkConnectivity()
		_ = json.NewEncoder(w).Encode(res)
	})

	mux.HandleFunc("/api/dns", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			st := loadState()
			_ = json.NewEncoder(w).Encode(st.DNS)
			return
		}
		if r.Method == http.MethodPost {
			var req DNSConfig
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			if s := strings.TrimSpace(req.QueryStrategy); s != "" && !isValidQueryStrategy(s) {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("invalid query_strategy %q (expected UseIP, UseIPv4, or UseIPv6)", s)})
				return
			}
			if s := strings.TrimSpace(req.DirectQueryStrategy); s != "" && !isValidQueryStrategy(s) {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("invalid direct_query_strategy %q (expected UseIP, UseIPv4, or UseIPv6)", s)})
				return
			}
			if s := strings.TrimSpace(req.RemoteQueryStrategy); s != "" && !isValidQueryStrategy(s) {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("invalid remote_query_strategy %q (expected UseIP, UseIPv4, or UseIPv6)", s)})
				return
			}
			st := loadState()
			if strings.TrimSpace(req.RemoteDNS) != "" {
				st.DNS.RemoteDNS = strings.TrimSpace(req.RemoteDNS)
			}
			if strings.TrimSpace(req.DirectDNS) != "" {
				st.DNS.DirectDNS = strings.TrimSpace(req.DirectDNS)
			}
			legacyQS := strings.TrimSpace(req.QueryStrategy)
			if s := strings.TrimSpace(req.DirectQueryStrategy); s != "" {
				st.DNS.DirectQueryStrategy = s
			} else if legacyQS != "" {
				st.DNS.DirectQueryStrategy = legacyQS
			}
			if s := strings.TrimSpace(req.RemoteQueryStrategy); s != "" {
				st.DNS.RemoteQueryStrategy = s
			} else if legacyQS != "" {
				st.DNS.RemoteQueryStrategy = legacyQS
			}
			if req.DNSRedirect != nil {
				v := *req.DNSRedirect
				st.DNS.DNSRedirect = &v
			}
			sanitizePanelState(&st)
			if err := saveState(st); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			log.Printf("[passwall-droid] updated DNS settings: remote=%s (%s) direct=%s (%s) dns_redirect=%v",
				st.DNS.RemoteDNS, st.DNS.EffectiveRemoteQueryStrategy(),
				st.DNS.DirectDNS, st.DNS.EffectiveDirectQueryStrategy(),
				st.DNS.IsDNSRedirect())

			engineMu.Lock()
			active := engineActive
			engineMu.Unlock()
			if active {
				_ = restartProxyEngine()
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":    "ok",
				"dns":       st.DNS,
				"restarted": active,
			})
			return
		}
		http.Error(w, "GET or POST required", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/api/geo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			st := loadState()
			resp := map[string]interface{}{
				"bypass_iran":     st.Geo.IsBypassIran(),
				"bypass_cn":       st.Geo.IsBypassCN(),
				"block_ads":       st.Geo.IsBlockAds(),
				"domain_strategy": st.Geo.EffectiveDomainStrategy(),
				"domain_matcher":  st.Geo.EffectiveDomainMatcher(),
				"direct_domains":  st.Geo.DirectDomains,
				"direct_ips":      st.Geo.DirectIPs,
				"proxy_domains":   st.Geo.ProxyDomains,
				"proxy_ips":       st.Geo.ProxyIPs,
				"block_domains":   st.Geo.BlockDomains,
				"block_ips":       st.Geo.BlockIPs,
				"geoip_url":       st.Geo.GeoIPURL,
				"geosite_url":     st.Geo.GeoSiteURL,
				"last_geo_update": st.Geo.LastGeoUpdate,
				"assets":          getGeoAssetInfo(),
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		if r.Method == http.MethodPost {
			var req struct {
				BypassIran     *bool    `json:"bypass_iran"`
				BypassCN       *bool    `json:"bypass_cn"`
				BlockAds       *bool    `json:"block_ads"`
				DomainStrategy string   `json:"domain_strategy"`
				DomainMatcher  string   `json:"domain_matcher"`
				DirectDomains  []string `json:"direct_domains"`
				DirectIPs      []string `json:"direct_ips"`
				ProxyDomains   []string `json:"proxy_domains"`
				ProxyIPs       []string `json:"proxy_ips"`
				BlockDomains   []string `json:"block_domains"`
				BlockIPs       []string `json:"block_ips"`
				GeoIPURL       string   `json:"geoip_url"`
				GeoSiteURL     string   `json:"geosite_url"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body: " + err.Error()})
				return
			}
			if s := strings.TrimSpace(req.DomainStrategy); s != "" && !isValidDomainStrategy(s) {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("invalid domain_strategy %q (expected AsIs, IPIfNonMatch, or IPOnDemand)", s)})
				return
			}
			if s := strings.TrimSpace(req.DomainMatcher); s != "" && !isValidDomainMatcher(s) {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("invalid domain_matcher %q (expected hybrid or linear)", s)})
				return
			}
			st := loadState()
			if req.BypassIran != nil {
				st.Geo.BypassIran = req.BypassIran
			}
			if req.BypassCN != nil {
				st.Geo.BypassCN = req.BypassCN
			}
			if req.BlockAds != nil {
				st.Geo.BlockAds = req.BlockAds
			}
			if s := strings.TrimSpace(req.DomainStrategy); s != "" {
				st.Geo.DomainStrategy = s
			}
			if s := strings.TrimSpace(req.DomainMatcher); s != "" {
				st.Geo.DomainMatcher = s
			}
			if req.DirectDomains != nil {
				st.Geo.DirectDomains = sanitizeStringList(req.DirectDomains)
			}
			if req.DirectIPs != nil {
				st.Geo.DirectIPs = sanitizeStringList(req.DirectIPs)
			}
			if req.ProxyDomains != nil {
				st.Geo.ProxyDomains = sanitizeStringList(req.ProxyDomains)
			}
			if req.ProxyIPs != nil {
				st.Geo.ProxyIPs = sanitizeStringList(req.ProxyIPs)
			}
			if req.BlockDomains != nil {
				st.Geo.BlockDomains = sanitizeStringList(req.BlockDomains)
			}
			if req.BlockIPs != nil {
				st.Geo.BlockIPs = sanitizeStringList(req.BlockIPs)
			}
			if strings.TrimSpace(req.GeoIPURL) != "" {
				st.Geo.GeoIPURL = strings.TrimSpace(req.GeoIPURL)
			}
			if strings.TrimSpace(req.GeoSiteURL) != "" {
				st.Geo.GeoSiteURL = strings.TrimSpace(req.GeoSiteURL)
			}
			sanitizePanelState(&st)
			if err := saveState(st); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			log.Printf("[passwall-droid] updated geo routing rules (bypass_iran=%v bypass_cn=%v block_ads=%v domain_strategy=%s domain_matcher=%s)",
				st.Geo.IsBypassIran(), st.Geo.IsBypassCN(), st.Geo.IsBlockAds(),
				st.Geo.EffectiveDomainStrategy(), st.Geo.EffectiveDomainMatcher())

			engineMu.Lock()
			active := engineActive
			engineMu.Unlock()
			if active {
				_ = restartProxyEngine()
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		http.Error(w, "GET or POST required", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/api/geo/update", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			GeoIPURL   string `json:"geoip_url"`
			GeoSiteURL string `json:"geosite_url"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		if err := updateGeoAssets(req.GeoIPURL, req.GeoSiteURL); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
			"assets": getGeoAssetInfo(),
		})
	})

	mux.HandleFunc("/api/sub", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			SubURL          string `json:"sub_url"`
			AutoUpdateHours int    `json:"auto_update_hours"`
			SubInsecure     bool   `json:"sub_insecure"`
			FetchNow        bool   `json:"fetch_now"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		st := loadState()
		st.SubURL = strings.TrimSpace(req.SubURL)
		st.AutoUpdateHours = req.AutoUpdateHours
		st.SubInsecure = req.SubInsecure
		_ = saveState(st)

		w.Header().Set("Content-Type", "application/json")
		if req.FetchNow {
			count, err := updateSubscription(st.SubURL, st.SubInsecure)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			_ = restartProxyEngine()
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "imported": count})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/ping", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ID            string `json:"id"`
			SelectFastest bool   `json:"select_fastest"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		pingNodes(req.ID, req.SelectFastest)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/nodes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		st := loadState()
		var req NodeEditRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch req.Action {
		case "parse_uri":
			node, err := parseShareURI(req.URI, "manual")
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "node": node})
			return
		case "export_uri":
			var targetNode NodeProfile
			found := false
			if req.ID != "" {
				for _, n := range st.Nodes {
					if n.ID == req.ID {
						targetNode = n
						found = true
						break
					}
				}
			}
			if !found && req.Outbound != nil {
				targetNode = NodeProfile{
					Name:     req.Name,
					Protocol: req.Protocol,
					Address:  req.Address,
					Port:     req.Port,
					Outbound: req.Outbound,
				}
				syncNodeProfileFromOutbound(&targetNode)
				found = true
			}
			if !found {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "node not found"})
				return
			}
			uri := buildShareURI(targetNode)
			if uri == "" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "unable to build share URI for this node"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "uri": uri})
			return
		case "import":
			node, err := parseShareURI(req.URI, "manual")
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			st.Nodes = append(st.Nodes, node)
			st.ActiveNode = node.ID
			_ = saveState(st)
			log.Printf("[passwall-droid] imported manual node: %s (%s:%d)", node.Name, node.Address, node.Port)
			_ = restartProxyEngine()
		case "create", "add":
			var node NodeProfile
			if strings.TrimSpace(req.URI) != "" {
				parsed, err := parseShareURI(req.URI, "manual")
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
					return
				}
				node = parsed
				if strings.TrimSpace(req.Name) != "" {
					node.Name = strings.TrimSpace(req.Name)
				}
			} else if req.Outbound != nil {
				node = NodeProfile{
					ID:       fmt.Sprintf("manual-%d", time.Now().UnixNano()),
					Name:     strings.TrimSpace(req.Name),
					Group:    "manual",
					Protocol: normalizeNodeProtocol(req.Protocol),
					Address:  strings.TrimSpace(req.Address),
					Port:     req.Port,
					Outbound: deepCloneMap(req.Outbound),
				}
				node.Outbound["tag"] = "proxy"
				syncNodeProfileFromOutbound(&node)
				if node.Address == "" || node.Port <= 0 {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": "outbound must include valid server address and port"})
					return
				}
				if node.Name == "" {
					node.Name = fmt.Sprintf("%s-%s:%d", node.Protocol, node.Address, node.Port)
				}
			} else {
				node = NodeProfile{
					ID:    fmt.Sprintf("manual-%d", time.Now().UnixNano()),
					Group: "manual",
				}
				if err := applyNodeEditRequest(&node, req); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
					return
				}
			}
			st.Nodes = append(st.Nodes, node)
			if req.Activate || st.ActiveNode == "" {
				st.ActiveNode = node.ID
			}
			_ = saveState(st)
			log.Printf("[passwall-droid] created manual node: %s (%s, %s:%d)", node.Name, node.Protocol, node.Address, node.Port)
			engineMu.Lock()
			active := engineActive
			engineMu.Unlock()
			if active && st.ActiveNode == node.ID {
				_ = restartProxyEngine()
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "id": node.ID, "node": node})
			return
		case "edit", "update":
			foundIdx := -1
			for i := range st.Nodes {
				if st.Nodes[i].ID == req.ID {
					foundIdx = i
					break
				}
			}
			if foundIdx == -1 {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "node not found"})
				return
			}

			if strings.TrimSpace(req.URI) != "" {
				parsed, err := parseShareURI(req.URI, st.Nodes[foundIdx].Group)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
					return
				}
				parsed.ID = st.Nodes[foundIdx].ID
				if strings.TrimSpace(req.Name) != "" {
					parsed.Name = strings.TrimSpace(req.Name)
				}
				st.Nodes[foundIdx] = parsed
			} else if req.Outbound != nil {
				obCopy := deepCloneMap(req.Outbound)
				obCopy["tag"] = "proxy"
				st.Nodes[foundIdx].Outbound = obCopy
				if strings.TrimSpace(req.Name) != "" {
					st.Nodes[foundIdx].Name = strings.TrimSpace(req.Name)
				}
				syncNodeProfileFromOutbound(&st.Nodes[foundIdx])
				if st.Nodes[foundIdx].Address == "" || st.Nodes[foundIdx].Port <= 0 {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": "outbound must include valid server address and port"})
					return
				}
			} else if req.FullEdit || req.Protocol != "" {
				if err := applyNodeEditRequest(&st.Nodes[foundIdx], req); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
					return
				}
			} else {
				if strings.TrimSpace(req.Name) != "" {
					st.Nodes[foundIdx].Name = strings.TrimSpace(req.Name)
				}
				if strings.TrimSpace(req.Address) != "" {
					st.Nodes[foundIdx].Address = strings.TrimSpace(req.Address)
				}
				if req.Port > 0 && req.Port <= 65535 {
					st.Nodes[foundIdx].Port = req.Port
				}
				updateNodeOutboundAddressAndPort(&st.Nodes[foundIdx], strings.TrimSpace(req.Address), req.Port, strings.TrimSpace(req.SNI))
			}

			_ = saveState(st)
			log.Printf("[passwall-droid] updated node: %s (%s, %s:%d)", st.Nodes[foundIdx].ID, st.Nodes[foundIdx].Name, st.Nodes[foundIdx].Address, st.Nodes[foundIdx].Port)
			if st.ActiveNode == req.ID {
				engineMu.Lock()
				active := engineActive
				engineMu.Unlock()
				if active {
					_ = restartProxyEngine()
				}
			}
		case "select":
			st.ActiveNode = req.ID
			_ = saveState(st)
			log.Printf("[passwall-droid] active node switched: %s", req.ID)
			_ = restartProxyEngine()
		case "delete":
			filtered := []NodeProfile{}
			for _, n := range st.Nodes {
				if n.ID != req.ID {
					filtered = append(filtered, n)
				}
			}
			st.Nodes = filtered
			if st.ActiveNode == req.ID {
				st.ActiveNode = ""
			}
			_ = saveState(st)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/apps", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			st := loadState()
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"apps":            listInstalledApps(),
				"app_filter_mode": st.AppFilterMode,
				"selected_uids":   st.SelectedUIDs,
			})
			return
		}
		if r.Method == http.MethodPost {
			var req struct {
				AppFilterMode string `json:"app_filter_mode"`
				SelectedUIDs  []int  `json:"selected_uids"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			st := loadState()
			if req.AppFilterMode == "bypass" || req.AppFilterMode == "proxy" {
				st.AppFilterMode = req.AppFilterMode
			}
			if req.SelectedUIDs == nil {
				req.SelectedUIDs = []int{}
			}
			st.SelectedUIDs = req.SelectedUIDs
			_ = saveState(st)
			log.Printf("[passwall-droid] updated per-app split tunnel (%s, %d UIDs)", st.AppFilterMode, len(st.SelectedUIDs))
			_ = restartProxyEngine()
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		}
	})

	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			raw, err := os.ReadFile(BaseConfig)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(raw)
			return
		}
		if r.Method == http.MethodPost {
			var req struct {
				Action  string `json:"action"`
				RawJSON string `json:"raw_json"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Action == "reset" {
				if err := resetBaseConfig(); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				_ = restartProxyEngine()
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Config reset to factory default"})
				return
			}
			var testObj interface{}
			if err := json.Unmarshal([]byte(req.RawJSON), &testObj); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
				return
			}
			var pretty bytes.Buffer
			_ = json.Indent(&pretty, []byte(req.RawJSON), "", "  ")
			_ = os.MkdirAll(filepath.Dir(BaseConfig), 0755)
			if err := os.WriteFile(BaseConfig, pretty.Bytes(), 0644); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if errDir := os.MkdirAll(PersistDir, 0755); errDir == nil {
				_ = os.WriteFile(PersistBaseConfig, pretty.Bytes(), 0644)
			}
			st := loadState()
			st.ActiveNode = ""
			_ = saveState(st)

			log.Println("[passwall-droid] updated base config.json")
			_ = restartProxyEngine()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		}
	})

	mux.HandleFunc("/api/config/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := resetBaseConfig(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = restartProxyEngine()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Config reset to factory default"})
	})

	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			_ = os.WriteFile(LogFile, []byte(""), 0644)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
			return
		}
		if r.URL.Query().Get("download") == "1" || r.URL.Query().Get("download") == "true" {
			data, err := os.ReadFile(LogFile)
			if err != nil {
				data = []byte("No logs recorded yet.\n")
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"passwall-runtime-%s.log\"", time.Now().Format("20060102-150405")))
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			_, _ = w.Write(data)
			return
		}
		data, err := os.ReadFile(LogFile)
		if err != nil {
			_, _ = w.Write([]byte("No logs yet."))
			return
		}
		lines := strings.Split(string(data), "\n")
		if len(lines) > 120 {
			lines = lines[len(lines)-120:]
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(strings.Join(lines, "\n")))
	})

	return mux
}

func startWebDashboard() {
	mux := buildWebMux()

	ln, err := net.Listen("tcp4", WebListenAddr)
	if err != nil {
		log.Printf("[passwall-droid] web dashboard bind warning (%s): %v", WebListenAddr, err)
		return
	}
	log.Printf("[passwall-droid] web control panel active at http://%s", WebListenAddr)
	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[passwall-droid] web server error: %v", err)
		}
	}()
}

func isRunning() (int, bool) {
	data, err := os.ReadFile(PidFile)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return 0, false
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return 0, false
	}
	return pid, true
}

func main() {
	action := "start"
	if len(os.Args) > 1 {
		action = os.Args[1]
	}

	switch action {
	case "stop":
		if pid, ok := isRunning(); ok {
			p, _ := os.FindProcess(pid)
			_ = p.Signal(syscall.SIGTERM)
			for i := 0; i < 20; i++ {
				if _, alive := isRunning(); !alive {
					break
				}
				time.Sleep(150 * time.Millisecond)
			}
		}
		cleanupIptables()
		cleanupPolicyRouting()
		_ = os.Remove(PidFile)
		_ = os.Remove(RuntimeConfig)
		fmt.Println("Stopped passwall-droid.")
		return

	case "status":
		if pid, ok := isRunning(); ok {
			mode := "REDIRECT (nat)"
			if detectTproxy() {
				mode = "TPROXY (mangle)"
			}
			fmt.Printf("Running (PID %d, Mode: %s, WebUI: http://127.0.0.1:9090 or http://%s)\n", pid, mode, WebListenAddr)
			os.Exit(0)
		}
		fmt.Println("Stopped")
		os.Exit(1)

	case "reset-config":
		if err := resetBaseConfig(); err != nil {
			fmt.Printf("Failed to reset config: %v\n", err)
			os.Exit(1)
		}
		if pid, ok := isRunning(); ok {
			p, _ := os.FindProcess(pid)
			_ = p.Signal(syscall.SIGHUP)
			fmt.Println("Base Xray config reset to default. Sent reload signal to passwall-droid.")
		} else {
			fmt.Println("Base Xray config reset to default.")
		}
		return

	case "update-geo":
		fmt.Println("Updating GeoIP and GeoSite databases over direct WAN...")
		if err := updateGeoAssets("", ""); err != nil {
			fmt.Printf("Error updating geo assets: %v\n", err)
			os.Exit(1)
		}
		if pid, ok := isRunning(); ok {
			p, _ := os.FindProcess(pid)
			_ = p.Signal(syscall.SIGHUP)
			fmt.Println("Geo databases updated successfully. Sent reload signal to passwall-droid.")
		} else {
			fmt.Println("Geo databases updated successfully.")
		}
		return

	case "backup":
		data, err := createBackupBundle()
		if err != nil {
			fmt.Printf("Backup failed: %v\n", err)
			os.Exit(1)
		}
		if len(os.Args) > 2 && strings.TrimSpace(os.Args[2]) != "" {
			outPath := strings.TrimSpace(os.Args[2])
			if err := writeSyncedFile(outPath, data); err != nil {
				fmt.Printf("Failed writing backup file %s: %v\n", outPath, err)
				os.Exit(1)
			}
			fmt.Printf("Backup saved to %s\n", outPath)
		} else {
			fmt.Println(string(data))
		}
		return

	case "restore":
		if len(os.Args) < 3 || strings.TrimSpace(os.Args[2]) == "" {
			fmt.Printf("Usage: %s restore <backup-file.json>\n", filepath.Base(os.Args[0]))
			os.Exit(1)
		}
		raw, err := os.ReadFile(strings.TrimSpace(os.Args[2]))
		if err != nil {
			fmt.Printf("Failed reading backup file: %v\n", err)
			os.Exit(1)
		}
		stRestored, cfgRestored, err := restoreBackupBundle(raw)
		if err != nil {
			fmt.Printf("Restore failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Backup restored (%d nodes, config=%v).\n", len(stRestored.Nodes), cfgRestored)
		return

	case "start":
		if pid, ok := isRunning(); ok {
			fmt.Printf("Already running (PID %d)\n", pid)
			return
		}
	default:
		fmt.Printf("Usage: %s [start|stop|status|reset-config|update-geo|backup|restore]\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	log.SetOutput(logSink)
	syncPersistentConfigs()
	_ = os.WriteFile(PidFile, []byte(strconv.Itoa(os.Getpid())), 0644)
	defer os.Remove(PidFile)
	defer os.Remove(RuntimeConfig)

	useTproxy = detectTproxy()
	startWebDashboard()
	go watchdogLoop()
	go subscriptionAutoUpdater()

	if err := startProxyEngine(); err != nil {
		log.Printf("[passwall-droid] initial proxy start warning: %v (WebUI active at http://%s)", err, WebListenAddr)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, notifySignals...)
	<-sigCh

	stopProxyEngine()
	log.Println("[passwall-droid] daemon shutdown complete")
}

// ES5 / Chromium 44+ (Android 6.0 WebView) compatible Passwall Web Dashboard
const dashboardHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>Passwall Android</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,Roboto,sans-serif;background:#0f172a;color:#e2e8f0;padding:8px;line-height:1.4}
.card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:12px;margin-bottom:10px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;flex-wrap:wrap;gap:6px}
.title{font-size:15px;font-weight:700;color:#f8fafc}
.badge{display:inline-flex;align-items:center;justify-content:center;height:22px;min-height:22px;padding:0 9px;border-radius:11px;font-size:11px;font-weight:700;line-height:1;text-align:center;vertical-align:middle}
.badge-ver{display:inline-flex;align-items:center;justify-content:center;height:20px;min-height:20px;font-size:11px;padding:0 7px;border-radius:5px;background:#334155;color:#94a3b8;font-weight:600;line-height:1;vertical-align:middle}
.on{background:#065f46;color:#6ee7b7}
.off{background:#7f1d1d;color:#fca5a5}
.meta{font-size:12px;color:#94a3b8;margin-bottom:8px;word-break:break-all}
.row{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
button{appearance:none;-webkit-appearance:none;display:inline-flex;align-items:center;justify-content:center;border:none;border-radius:7px;padding:0 12px;height:32px;min-height:32px;font-size:12px;font-weight:600;line-height:1;cursor:pointer;color:#fff;background:#334155;-webkit-tap-highlight-color:transparent;text-align:center;vertical-align:middle;box-sizing:border-box}
button:active{opacity:.8}
.btn-sm{appearance:none;-webkit-appearance:none;display:inline-flex;align-items:center;justify-content:center;height:26px;min-height:26px;padding:0 8px;font-size:11px;line-height:1;border-radius:5px}
.btn-green{background:#059669}
.btn-red{background:#dc2626}
.btn-blue{background:#2563eb}
.btn-amber{background:#d97706}
.btn-active{background:#0284c7;box-shadow:0 0 0 2px #38bdf8}
.tabs{display:flex;gap:6px;margin-bottom:10px;overflow-x:auto;-webkit-overflow-scrolling:touch;scrollbar-width:none;padding-bottom:3px}
.tabs::-webkit-scrollbar{display:none}
.tab{display:inline-flex;align-items:center;justify-content:center;flex:0 0 auto;text-align:center;height:32px;min-height:32px;padding:0 14px;background:#1e293b;border:1px solid #334155;border-radius:8px;font-size:12px;font-weight:600;line-height:1;color:#94a3b8;cursor:pointer;white-space:nowrap;user-select:none;-webkit-user-select:none;vertical-align:middle}
.tab.active{background:#2563eb;color:#fff;border-color:#2563eb}
input,select{width:100%;background:#0f172a;border:1px solid #334155;border-radius:7px;color:#f8fafc;padding:0 10px;height:34px;font-size:13px;line-height:1;margin-bottom:8px;box-sizing:border-box}
textarea{width:100%;background:#0f172a;border:1px solid #334155;border-radius:7px;color:#f8fafc;padding:8px 10px;font-size:12px;font-family:monospace;min-height:220px;line-height:1.4;margin-bottom:8px;box-sizing:border-box}
.node-item{display:flex;justify-content:space-between;align-items:center;background:#0f172a;border:1px solid #334155;border-radius:7px;padding:8px;margin-bottom:6px;flex-wrap:wrap;gap:6px}
.node-item.selected{border-color:#38bdf8;background:#0c4a6e}
.node-info{font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1 1 170px;min-width:0}
.node-sub{font-size:11px;color:#94a3b8}
.lat{display:inline-flex;align-items:center;justify-content:center;height:26px;min-height:26px;font-size:11px;font-weight:700;padding:0 7px;border-radius:5px;background:#1e293b;line-height:1;vertical-align:middle}
.lat-ok{color:#34d399}
.lat-slow{color:#fbbf24}
.lat-err{color:#f87171}
.conn-bar{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:6px 0 8px}
.conn-pill{display:inline-flex;align-items:center;justify-content:center;height:22px;min-height:22px;font-size:11px;font-weight:600;padding:0 8px;border-radius:11px;background:#334155;color:#94a3b8;line-height:1;vertical-align:middle}
.conn-ok{background:#065f46;color:#6ee7b7}
.conn-err{background:#7f1d1d;color:#fca5a5}
.conn-wait{background:#854d0e;color:#fde047}
.app-list{max-height:300px;overflow-y:auto;border:1px solid #334155;border-radius:7px;background:#0f172a;padding:6px;margin-bottom:8px}
.app-row{display:flex;justify-content:space-between;align-items:center;padding:6px 4px;border-bottom:1px solid #1e293b;font-size:12px}
.app-row input[type=checkbox]{width:18px;height:18px;margin:0}
pre{background:#090d16;border:1px solid #1e293b;border-radius:7px;padding:10px;font-size:11px;color:#cbd5e1;overflow-x:auto;max-height:320px;white-space:pre-wrap;word-break:break-all}
.msg{font-size:12px;color:#38bdf8;margin-top:6px;min-height:16px}
.hidden{display:none !important}
.modal-bg{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.75);display:flex;align-items:center;justify-content:center;z-index:999;padding:10px}
.modal-bg.hidden{display:none !important}
.modal-card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px;width:100%;max-width:540px;max-height:92vh;overflow-y:auto;box-sizing:border-box}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin-bottom:10px}
.stat-box{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:8px}
.stat-val{font-size:13px;font-weight:700;color:#38bdf8;margin-top:2px}
.stat-lbl{font-size:11px;color:#94a3b8}
.switch{position:relative;display:inline-block;width:44px;height:24px;flex:0 0 auto}
.switch input{opacity:0;width:0;height:0;margin:0}
.slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:#334155;border-radius:24px;transition:.2s}
.slider:before{position:absolute;content:"";height:18px;width:18px;left:3px;bottom:3px;background:#f8fafc;border-radius:50%;transition:.2s}
.switch input:checked + .slider{background:#059669}
.switch input:checked + .slider:before{transform:translateX(20px)}
.section-box{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:10px;margin-bottom:12px}
.alert-warn{background:#451a03;border:1px solid #d97706;color:#fde68a;border-radius:7px;padding:8px 10px;font-size:12px;margin-bottom:10px}
.sub-tabs{display:flex;gap:6px;margin-bottom:10px}
.sub-tab{flex:1;height:30px;display:inline-flex;align-items:center;justify-content:center;border-radius:7px;background:#0f172a;border:1px solid #334155;font-size:12px;font-weight:600;color:#94a3b8;cursor:pointer}
.sub-tab.active{background:#2563eb;color:#fff;border-color:#2563eb}
.field-lbl{font-size:12px;font-weight:600;margin-bottom:4px;color:#cbd5e1}
.field-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.chk-inline{display:flex;align-items:center;gap:8px;font-size:12px;color:#cbd5e1;cursor:pointer;margin-bottom:8px}
.chk-inline input[type=checkbox]{width:18px;height:18px;margin:0}
input[type=file]{padding:5px 8px;height:auto;line-height:1.3}
</style>
</head>
<body>

<div class="card">
  <div class="header">
    <div class="title" style="display:flex;align-items:center;gap:6px">
      <span>Passwall Android</span>
      <span id="modVerBadge" class="badge-ver">--</span>
    </div>
    <span id="statusBadge" class="badge off">LOADING</span>
  </div>
  <div class="meta" id="metaLine">Xray: -- | Netfilter: -- | PID: --</div>
  <div class="row" style="margin-bottom:8px;gap:6px;font-size:11px">
    <span id="statBattery" class="conn-pill" style="height:22px;min-height:22px;background:#0f172a;border:1px solid #334155">🔋 Battery: --</span>
    <span id="statModule" class="conn-pill" style="height:22px;min-height:22px;background:#0f172a;border:1px solid #334155">Module: --</span>
    <span id="statXray" class="conn-pill" style="height:22px;min-height:22px;background:#0f172a;border:1px solid #334155">Xray: --</span>
  </div>
  <div class="conn-bar">
    <span style="font-size:12px;color:#94a3b8;font-weight:600">Connectivity:</span>
    <span id="connGoogle" class="conn-pill">Google: --</span>
    <span id="connGithub" class="conn-pill">GitHub: --</span>
    <button id="btnCheckConn" class="btn-sm" onclick="checkConn()">Check</button>
  </div>
  <div class="row">
    <button class="btn-green" style="flex:1" onclick="ctrl('start')">Start</button>
    <button class="btn-blue" style="flex:1" onclick="ctrl('restart')">Restart</button>
    <button class="btn-red" style="flex:1" onclick="ctrl('stop')">Stop</button>
  </div>
  <div class="msg" id="toast"></div>
</div>

<div class="card">
  <div class="title" style="font-size:13px;margin-bottom:6px">Routing Mode</div>
  <div class="row" style="margin-bottom:8px">
    <button id="mode-rule" style="flex:1;padding:0 4px;white-space:nowrap;font-size:11.5px" onclick="setMode('rule')">Rule</button>
    <button id="mode-global" style="flex:1" onclick="setMode('global')">Global</button>
    <button id="mode-direct" style="flex:1" onclick="setMode('direct')">Direct</button>
  </div>
  <div style="border-top:1px solid #334155;padding-top:8px;margin-top:8px">
    <label style="display:flex;align-items:flex-start;gap:8px;font-size:12px;color:#cbd5e1;cursor:pointer">
      <input id="localhostProxyChk" type="checkbox" style="width:18px;height:18px;margin:2px 0 0 0" onchange="toggleLocalhostProxy(this.checked)">
      <span><b>Proxy Local Device (Localhost)</b><span class="node-sub" style="display:block">Uncheck to proxy only hotspot/tethered clients while phone apps route direct WAN.</span></span>
    </label>
  </div>
</div>

<div class="tabs">
  <div class="tab active" id="t-status" onclick="showTab('status')">Status</div>
  <div class="tab" id="t-nodes" onclick="showTab('nodes')">Nodes &amp; Sub</div>
  <div class="tab" id="t-dns" onclick="showTab('dns')">DNS</div>
  <div class="tab" id="t-geo" onclick="showTab('geo')">Geo Rules</div>
  <div class="tab" id="t-apps" onclick="showTab('apps')">Apps</div>
  <div class="tab" id="t-config" onclick="showTab('config')">Config</div>
  <div class="tab" id="t-logs" onclick="showTab('logs')">Logs</div>
</div>

<div id="p-status" class="card">
  <div class="title" style="font-size:13px;margin-bottom:8px">System &amp; Resource Status</div>
  <div class="stat-grid">
    <div class="stat-box">
      <div class="stat-lbl">Device Battery</div>
      <div class="stat-val" id="statCardBattery">--</div>
      <div class="stat-lbl" id="statCardBatteryStatus">Status: --</div>
    </div>
    <div class="stat-box">
      <div class="stat-lbl">Passwall Module</div>
      <div class="stat-val" id="statCardModuleCPU">CPU: --</div>
      <div class="stat-lbl" id="statCardModuleRAM">RAM: --</div>
    </div>
    <div class="stat-box">
      <div class="stat-lbl">Xray Core</div>
      <div class="stat-val" id="statCardXrayCPU">CPU: --</div>
      <div class="stat-lbl" id="statCardXrayRAM">RAM: --</div>
    </div>
    <div class="stat-box">
      <div class="stat-lbl">Active Core PIDs</div>
      <div class="stat-val" id="statCardPIDs">--</div>
      <div class="stat-lbl" id="statCardNetMode">Mode: --</div>
    </div>
  </div>

  <div style="background:#0f172a;border:1px solid #334155;border-radius:8px;padding:10px;margin-bottom:8px">
    <div style="font-size:12px;font-weight:700;margin-bottom:4px;color:#f8fafc">Active Proxy Node Connection</div>
    <div id="statCardActiveNode" style="font-size:12px;color:#cbd5e1">No proxy node currently active</div>
  </div>
</div>

<div id="p-nodes" class="card hidden">
  <div class="title" style="font-size:13px;margin-bottom:6px">Subscription URL (Direct WAN Fetch)</div>
  <input id="subUrlInput" type="text" placeholder="https://example.com/sub/...">
  <div class="row" style="margin-bottom:8px">
    <label style="display:flex;align-items:center;gap:6px;font-size:12px;color:#cbd5e1;cursor:pointer">
      <input id="subInsecureChk" type="checkbox" style="width:auto;margin:0"> Ignore SSL / TLS certificate errors
    </label>
  </div>
  <div class="row" style="margin-bottom:10px">
    <select id="subAutoSel" style="width:auto;margin:0;flex:1;height:32px">
      <option value="0">Auto-Update: Off</option>
      <option value="6">Every 6 Hours</option>
      <option value="12">Every 12 Hours</option>
      <option value="24">Every 24 Hours</option>
    </select>
    <button class="btn-blue" onclick="saveSub(true)">Update Sub</button>
    <button onclick="saveSub(false)">Save</button>
  </div>
  <div class="meta" id="subMeta">Last updated: Never</div>

  <div class="title" style="font-size:13px;margin:10px 0 6px">Manual URI Import</div>
  <input id="uriInput" type="text" placeholder="vless:// | trojan:// | vmess:// | ss:// | hysteria2:// | hy2://">
  <button class="btn-green" style="width:100%;margin-bottom:12px" onclick="importURI()">Import &amp; Connect</button>

  <div id="vlessInsecureAlert" class="alert-warn hidden">
    <b>VLESS TLS/Encryption Warning:</b> Your active VLESS node has no TLS, Reality, or VLESS encryption on a public address. Xray rejects this with <i>&quot;vless without TLS or other encryption is prohibited unless the server address is a private IP or domain&quot;</i> unless the switcher below is enabled.
    <div style="margin-top:6px"><button class="btn-amber btn-sm" type="button" onclick="setAllowInsecureVless(true)">Enable Switcher &amp; Connect</button></div>
  </div>

  <div class="section-box" style="display:flex;justify-content:space-between;align-items:center;gap:10px">
    <div style="flex:1;min-width:0">
      <div style="font-size:12px;font-weight:700;color:#f8fafc">Ignore VLESS Without TLS / Encryption Error</div>
      <div class="node-sub">Bypass Xray&#39;s public unencrypted VLESS restriction via local bridge so plain VLESS nodes work.</div>
    </div>
    <label class="switch">
      <input id="allowInsecureVlessChk" type="checkbox" onchange="toggleAllowInsecureVless(this.checked)">
      <span class="slider"></span>
    </label>
  </div>

  <div class="header">
    <div class="title" style="font-size:13px">Saved Nodes</div>
    <div class="row">
      <button id="btnNewNode" class="btn-blue btn-sm" onclick="openCreateNode()">+ New Node</button>
      <button class="btn-amber btn-sm" onclick="pingAll(false)">Ping All</button>
      <button class="btn-green btn-sm" onclick="pingAll(true)">Fastest</button>
    </div>
  </div>
  <div id="nodeList"></div>
</div>

<div id="p-dns" class="card hidden">
  <div class="title" style="font-size:13px;margin-bottom:6px">DNS Configuration</div>
  <div class="meta" style="margin-bottom:10px">Internal Xray DNS resolver for phone &amp; tethered devices. Direct DNS resolves proxy node domains and domestic traffic; Remote DNS handles proxied/blocked sites.</div>

  <div style="background:#0f172a;border:1px solid #334155;border-radius:7px;padding:10px;margin-bottom:12px">
    <label style="display:flex;align-items:flex-start;gap:8px;font-size:12px;color:#cbd5e1;cursor:pointer">
      <input id="dnsRedirectChk" type="checkbox" style="width:18px;height:18px;margin:2px 0 0 0" checked>
      <span><b>DNS Redirect</b><span class="node-sub" style="display:block">Hijack port 53 DNS requests from phone &amp; tethered devices to Xray internal DNS (and block DoT port 853). Disable to let system/client DNS bypass interception.</span></span>
    </label>
  </div>

  <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:#cbd5e1">Remote DNS (Proxied / Foreign)</div>
  <input id="dnsRemoteInput" type="text" placeholder="tcp://1.1.1.1">
  <div class="row" style="margin-bottom:8px;flex-wrap:wrap;gap:4px">
    <button class="btn-sm" onclick="setDNSField('dnsRemoteInput','tcp://1.1.1.1')">1.1.1.1 (TCP)</button>
    <button class="btn-sm" onclick="setDNSField('dnsRemoteInput','1.1.1.1')">1.1.1.1 (UDP)</button>
    <button class="btn-sm" onclick="setDNSField('dnsRemoteInput','tcp://8.8.8.8')">8.8.8.8 (TCP)</button>
    <button class="btn-sm" onclick="setDNSField('dnsRemoteInput','https://1.1.1.1/dns-query')">Cloudflare DoH</button>
    <button class="btn-sm" onclick="setDNSField('dnsRemoteInput','https://dns.google/dns-query')">Google DoH</button>
  </div>
  <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:#cbd5e1">Remote Query Strategy</div>
  <select id="dnsRemoteStrategySel" style="margin-bottom:12px">
    <option value="UseIPv4">UseIPv4 (Recommended - IPv4 A records only)</option>
    <option value="UseIP">UseIP (Both IPv4 and IPv6)</option>
    <option value="UseIPv6">UseIPv6 (IPv6 AAAA records only)</option>
  </select>

  <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:#cbd5e1">Direct DNS (Domestic / Node Resolution)</div>
  <input id="dnsDirectInput" type="text" placeholder="1.1.1.1">
  <div class="row" style="margin-bottom:8px;flex-wrap:wrap;gap:4px">
    <button class="btn-sm" onclick="setDNSField('dnsDirectInput','1.1.1.1')">1.1.1.1 (Cloudflare UDP)</button>
    <button class="btn-sm" onclick="setDNSField('dnsDirectInput','localhost')">localhost (System DNS)</button>
    <button class="btn-sm" onclick="setDNSField('dnsDirectInput','10.202.10.202')">Shecan (10.202.10.202)</button>
    <button class="btn-sm" onclick="setDNSField('dnsDirectInput','77.88.8.8')">Yandex (77.88.8.8)</button>
    <button class="btn-sm" onclick="setDNSField('dnsDirectInput','223.5.5.5')">AliDNS (223.5.5.5)</button>
  </div>
  <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:#cbd5e1">Direct Query Strategy</div>
  <select id="dnsDirectStrategySel" style="margin-bottom:12px">
    <option value="UseIPv4">UseIPv4 (Recommended - Prevents IPv6 timeouts)</option>
    <option value="UseIP">UseIP (Both IPv4 and IPv6)</option>
    <option value="UseIPv6">UseIPv6 (IPv6 AAAA records only)</option>
  </select>

  <button class="btn-green" style="width:100%" onclick="saveDNS()">Save &amp; Apply DNS</button>
</div>

<div id="p-geo" class="card hidden">
  <div class="title" style="font-size:13px;margin-bottom:6px">Geo Routing &amp; Rules Settings</div>
  <div class="meta" style="margin-bottom:10px">Configure Xray Domain Strategy &amp; Matcher, Geosite/GeoIP rule policies for Rule Mode, custom routing lists, and Geo database updates.</div>

  <div style="background:#0f172a;border:1px solid #334155;border-radius:7px;padding:10px;margin-bottom:12px">
    <div style="font-size:12px;font-weight:700;color:#f8fafc;margin-bottom:8px">Routing Strategy &amp; Matcher</div>
    <div class="field-grid">
      <div>
        <div class="field-lbl">Domain Strategy</div>
        <select id="geoDomainStrategySel">
          <option value="AsIs">AsIs (Route by domain/sniffing only)</option>
          <option value="IPIfNonMatch">IPIfNonMatch (Resolve IP if no domain rule matches)</option>
          <option value="IPOnDemand">IPOnDemand (Resolve IP before matching IP rules)</option>
        </select>
      </div>
      <div>
        <div class="field-lbl">Domain matcher</div>
        <select id="geoDomainMatcherSel">
          <option value="hybrid">hybrid (Balanced MPH + Trie)</option>
          <option value="linear">linear (Lower RAM linear scan)</option>
        </select>
      </div>
    </div>
    <div class="node-sub" style="margin-top:2px">Matches OpenWrt Passwall 2 Xray routing options: controls <code>routing.domainStrategy</code> and <code>routing.domainMatcher</code>.</div>
  </div>

  <div style="background:#0f172a;border:1px solid #334155;border-radius:7px;padding:10px;margin-bottom:12px">
    <div style="font-size:12px;font-weight:700;color:#f8fafc;margin-bottom:8px">Built-in Rule Policies (Rule Mode)</div>
    
    <label style="display:flex;align-items:flex-start;gap:8px;font-size:12px;color:#cbd5e1;cursor:pointer;margin-bottom:8px">
      <input id="geoBypassIranChk" type="checkbox" style="width:18px;height:18px;margin:2px 0 0 0">
      <span><b>Bypass Iran Domestic Traffic (domain:ir, geosite:ir, geosite:category-ir, geoip:ir)</b><span class="node-sub" style="display:block">Directly routes Iranian national websites, payment gateways, and banking services without proxy.</span></span>
    </label>

    <label style="display:flex;align-items:flex-start;gap:8px;font-size:12px;color:#cbd5e1;cursor:pointer;margin-bottom:8px">
      <input id="geoBypassCNChk" type="checkbox" style="width:18px;height:18px;margin:2px 0 0 0">
      <span><b>Bypass China Traffic (geosite:cn, geoip:cn)</b><span class="node-sub" style="display:block">Directly routes Chinese mainland domains and IP ranges.</span></span>
    </label>

    <label style="display:flex;align-items:flex-start;gap:8px;font-size:12px;color:#cbd5e1;cursor:pointer">
      <input id="geoBlockAdsChk" type="checkbox" style="width:18px;height:18px;margin:2px 0 0 0">
      <span><b>Block Advertisements &amp; Tracking (geosite:category-ads-all)</b><span class="node-sub" style="display:block">Drop DNS queries and connections to known ad-servers, telemetry, and malicious domains.</span></span>
    </label>
  </div>

  <div class="title" style="font-size:13px;margin:12px 0 6px">Custom Routing Lists</div>
  <div class="meta" style="margin-bottom:8px">One entry per line. Supports domains (<code>example.com</code>, <code>domain:ir</code>), geosite tags (<code>geosite:google</code>), IP addresses (<code>1.2.3.4</code>), CIDRs (<code>10.0.0.0/8</code>), or geoip tags (<code>geoip:telegram</code>).</div>

  <div style="margin-bottom:10px">
    <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:#34d399">Direct / Bypass Domains (Direct WAN)</div>
    <textarea id="geoDirectDomains" style="min-height:75px;margin-bottom:6px" placeholder="domain:ir&#10;geosite:category-media-ir&#10;mybank.com"></textarea>
    <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:#34d399">Direct / Bypass IPs &amp; CIDRs (Direct WAN)</div>
    <textarea id="geoDirectIPs" style="min-height:75px;margin-bottom:8px" placeholder="geoip:ir&#10;192.168.0.0/16&#10;10.0.0.0/8"></textarea>
  </div>

  <div style="margin-bottom:10px">
    <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:#38bdf8">Force Proxy Domains (Route through Node)</div>
    <textarea id="geoProxyDomains" style="min-height:75px;margin-bottom:6px" placeholder="geosite:google&#10;geosite:telegram&#10;domain:youtube.com"></textarea>
    <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:#38bdf8">Force Proxy IPs &amp; CIDRs (Route through Node)</div>
    <textarea id="geoProxyIPs" style="min-height:75px;margin-bottom:8px" placeholder="geoip:telegram&#10;91.108.4.0/22"></textarea>
  </div>

  <div style="margin-bottom:10px">
    <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:#f87171">Block Domains (Blackhole)</div>
    <textarea id="geoBlockDomains" style="min-height:75px;margin-bottom:6px" placeholder="geosite:category-ads&#10;domain:adservice.google.com"></textarea>
    <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:#f87171">Block IPs &amp; CIDRs (Blackhole)</div>
    <textarea id="geoBlockIPs" style="min-height:75px;margin-bottom:8px" placeholder="198.51.100.99&#10;geoip:phishing"></textarea>
  </div>

  <button class="btn-green" style="width:100%;margin-bottom:14px" onclick="saveGeo()">Save &amp; Apply Geo Rules</button>

  <div style="border-top:1px solid #334155;padding-top:12px;margin-top:6px">
    <div class="header">
      <div class="title" style="font-size:13px">Geo Database Files</div>
      <button id="btnUpdateGeo" class="btn-blue btn-sm" onclick="updateGeoDatabases()">Update Geo Files</button>
    </div>
    <div class="meta" id="geoAssetMeta">Checking geo files...</div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px">
      <div style="background:#0f172a;border:1px solid #334155;border-radius:7px;padding:8px">
        <div style="font-size:12px;font-weight:700;color:#f8fafc">geoip.dat</div>
        <div id="geoipStatus" class="meta" style="margin-top:4px">Status: Loading...</div>
      </div>
      <div style="background:#0f172a;border:1px solid #334155;border-radius:7px;padding:8px">
        <div style="font-size:12px;font-weight:700;color:#f8fafc">geosite.dat</div>
        <div id="geositeStatus" class="meta" style="margin-top:4px">Status: Loading...</div>
      </div>
    </div>

    <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:#cbd5e1">GeoIP Download URL</div>
    <input id="geoIpUrlInput" type="text" placeholder="https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geoip.dat">

    <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:#cbd5e1">GeoSite Download URL</div>
    <input id="geoSiteUrlInput" type="text" placeholder="https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geosite.dat">

    <div class="row" style="margin-bottom:8px">
      <button class="btn-sm" onclick="setGeoPreset('iran')">Iran Rules (Chocolate4U)</button>
      <button class="btn-sm" onclick="setGeoPreset('v2fly')">Global Rules (Loyalsoldier)</button>
    </div>
  </div>
</div>

<div id="p-apps" class="card hidden">
  <div class="title" style="font-size:13px;margin-bottom:6px">Per-App Split Tunneling (Hotspot always proxied)</div>
  <select id="appModeSel">
    <option value="bypass">Bypass Selected Apps (Proxy all others)</option>
    <option value="proxy">Proxy Only Selected Apps (Bypass all others)</option>
  </select>
  <input id="appSearch" type="text" placeholder="Filter package name (e.g. ir.bank, telegram)..." onkeyup="renderApps()">
  <div class="app-list" id="appList">Loading installed apps...</div>
  <button class="btn-green" style="width:100%" onclick="saveApps()">Save &amp; Apply App Rules</button>
</div>

<div id="p-config" class="card hidden">
  <div class="section-box">
    <div class="title" style="font-size:13px;margin-bottom:4px">Backup &amp; Restore</div>
    <div class="meta" style="margin-bottom:8px">Export or restore all Passwall settings (nodes, subscriptions, DNS, geo rules, split tunneling, VLESS switcher, and base config.json).</div>
    <div class="row" style="margin-bottom:8px">
      <button id="btnDownloadBackup" class="btn-blue" onclick="downloadBackup()">Download Backup (.json)</button>
      <button id="btnViewBackup" onclick="viewBackupJSON()">View / Copy JSON</button>
    </div>
    <div class="field-lbl">Restore from Backup File (.json)</div>
    <input id="restoreFileInput" type="file" accept=".json,application/json">
    <div class="row" style="margin-bottom:8px">
      <button id="btnRestoreBackup" class="btn-amber" onclick="restoreBackup()">Restore Backup</button>
      <button class="btn-sm" onclick="toggleBackupPaste()">Paste / Edit Backup JSON</button>
    </div>
    <div id="backupJsonWrap" class="hidden">
      <textarea id="backupJsonBox" style="min-height:140px" placeholder="Backup JSON content will appear here when viewing, or paste backup JSON here to restore..."></textarea>
    </div>
  </div>

  <div class="title" style="font-size:13px;margin-bottom:6px">Base Xray Config (config.json)</div>
  <textarea id="cfgEditor"></textarea>
  <div class="row">
    <button class="btn-green" onclick="saveConfig()">Save &amp; Apply</button>
    <button onclick="loadConfig()">Reload</button>
    <button class="btn-red" onclick="resetConfig()">Reset to Default</button>
  </div>
</div>

<div id="p-logs" class="card hidden">
  <div class="header">
    <div class="title" style="font-size:13px">Runtime Logs</div>
    <div class="row">
      <button class="btn-blue btn-sm" onclick="downloadLogs()">Download</button>
      <button class="btn-red btn-sm" onclick="clearLogs()">Clear</button>
    </div>
  </div>
  <pre id="logBox">Loading logs...</pre>
</div>

<div id="nodeEditModal" class="modal-bg hidden" style="display:none" onclick="if(event.target===this)closeEditNode()">
  <div class="modal-card">
    <div class="header" style="margin-bottom:10px">
      <div id="editModalTitle" class="title" style="font-size:14px">Edit Proxy Node</div>
      <button class="btn-sm" type="button" onclick="closeEditNode()">✕</button>
    </div>
    <input type="hidden" id="editNodeId">
    <input type="hidden" id="editNodeIsNew" value="0">

    <div class="sub-tabs">
      <div id="editTab-visual" class="sub-tab active" onclick="setEditTab('visual')">Visual Editor</div>
      <div id="editTab-json" class="sub-tab" onclick="setEditTab('json')">Raw Outbound JSON</div>
      <div id="editTab-uri" class="sub-tab" onclick="setEditTab('uri')">Share URI</div>
    </div>

    <div id="editModalErr" class="alert-warn hidden" style="margin-bottom:8px"></div>

    <div id="editPaneVisual">
      <div class="field-grid">
        <div>
          <div class="field-lbl">Node Name</div>
          <input id="editNodeName" type="text" placeholder="Node Alias">
        </div>
        <div>
          <div class="field-lbl">Protocol</div>
          <select id="editNodeProtocol" onchange="onEditProtocolChange()">
            <option value="vless">VLESS</option>
            <option value="vmess">VMess</option>
            <option value="trojan">Trojan</option>
            <option value="shadowsocks">Shadowsocks</option>
            <option value="hysteria2">Hysteria2</option>
          </select>
        </div>
      </div>

      <div class="field-grid">
        <div>
          <div class="field-lbl">Server Address</div>
          <input id="editNodeAddress" type="text" placeholder="example.com or 1.2.3.4">
        </div>
        <div>
          <div class="field-lbl">Port</div>
          <input id="editNodePort" type="number" min="1" max="65535" placeholder="443">
        </div>
      </div>

      <div id="editSecAuth" class="section-box" style="margin-bottom:8px">
        <div style="font-size:12px;font-weight:700;color:#38bdf8;margin-bottom:6px">Authentication</div>
        <div id="editAuthUUIDRow">
          <div class="field-lbl">UUID / User ID</div>
          <input id="editNodeUUID" type="text" placeholder="00000000-0000-0000-0000-000000000000">
        </div>
        <div id="editAuthVlessRow" class="field-grid">
          <div>
            <div class="field-lbl">Flow (XTLS)</div>
            <select id="editNodeFlow">
              <option value="">None</option>
              <option value="xtls-rprx-vision">xtls-rprx-vision</option>
              <option value="xtls-rprx-vision-udp443">xtls-rprx-vision-udp443</option>
            </select>
          </div>
          <div>
            <div class="field-lbl">VLESS Encryption</div>
            <input id="editNodeVlessEncryption" type="text" placeholder="none">
          </div>
        </div>
        <div id="editAuthVmessRow" class="field-grid hidden">
          <div>
            <div class="field-lbl">Alter ID</div>
            <input id="editNodeAlterId" type="number" min="0" value="0">
          </div>
          <div>
            <div class="field-lbl">VMess Security</div>
            <select id="editNodeVmessSecurity">
              <option value="auto">auto</option>
              <option value="aes-128-gcm">aes-128-gcm</option>
              <option value="chacha20-poly1305">chacha20-poly1305</option>
              <option value="none">none</option>
              <option value="zero">zero</option>
            </select>
          </div>
        </div>
        <div id="editAuthSSMethodRow" class="hidden">
          <div class="field-lbl">Encryption Method</div>
          <select id="editNodeSSMethod">
            <option value="aes-256-gcm">aes-256-gcm</option>
            <option value="aes-128-gcm">aes-128-gcm</option>
            <option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</option>
            <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option>
            <option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm</option>
            <option value="2022-blake3-chacha20-poly1305">2022-blake3-chacha20-poly1305</option>
            <option value="none">none</option>
          </select>
        </div>
        <div id="editAuthPasswordRow" class="hidden">
          <div class="field-lbl" id="editPasswordLbl">Password</div>
          <input id="editNodePassword" type="text" placeholder="Password / Auth secret">
        </div>
        <div id="editAuthHyRow" class="hidden">
          <div class="field-grid">
            <div>
              <div class="field-lbl">Up Bandwidth</div>
              <input id="editNodeHyUp" type="text" placeholder="e.g. 50 mbps">
            </div>
            <div>
              <div class="field-lbl">Down Bandwidth</div>
              <input id="editNodeHyDown" type="text" placeholder="e.g. 100 mbps">
            </div>
          </div>
          <div class="field-grid">
            <div>
              <div class="field-lbl">Obfs Type</div>
              <select id="editNodeHyObfsType">
                <option value="">None</option>
                <option value="salamander">salamander</option>
              </select>
            </div>
            <div>
              <div class="field-lbl">Obfs Password</div>
              <input id="editNodeHyObfsPass" type="text" placeholder="Optional obfs password">
            </div>
          </div>
        </div>
      </div>

      <div id="editSecTransport" class="section-box" style="margin-bottom:8px">
        <div style="font-size:12px;font-weight:700;color:#38bdf8;margin-bottom:6px">Transport</div>
        <div class="field-lbl">Network</div>
        <select id="editNodeNetwork" onchange="onEditNetworkChange()">
          <option value="tcp">TCP / RAW</option>
          <option value="ws">WebSocket (ws)</option>
          <option value="xhttp">XHTTP / SplitHTTP</option>
          <option value="httpupgrade">HTTPUpgrade</option>
          <option value="grpc">gRPC</option>
          <option value="kcp">mKCP</option>
        </select>

        <div id="editTransTcp" class="hidden">
          <div class="field-lbl">TCP Header Type</div>
          <select id="editNodeTcpHeaderType" onchange="onEditNetworkChange()">
            <option value="none">None</option>
            <option value="http">HTTP</option>
          </select>
        </div>
        <div id="editTransHostPath" class="field-grid hidden">
          <div>
            <div class="field-lbl">Host Header</div>
            <input id="editNodeHost" type="text" placeholder="example.com">
          </div>
          <div>
            <div class="field-lbl">Path</div>
            <input id="editNodePath" type="text" placeholder="/">
          </div>
        </div>
        <div id="editTransXhttp" class="hidden">
          <div class="field-lbl">XHTTP Mode</div>
          <select id="editNodeXhttpMode">
            <option value="">auto (default)</option>
            <option value="auto">auto</option>
            <option value="packet-up">packet-up</option>
            <option value="stream-up">stream-up</option>
            <option value="stream-one">stream-one</option>
          </select>
        </div>
        <div id="editTransGrpc" class="hidden">
          <div class="field-grid">
            <div>
              <div class="field-lbl">Service Name</div>
              <input id="editNodeGrpcService" type="text" placeholder="grpcService">
            </div>
            <div>
              <div class="field-lbl">Authority</div>
              <input id="editNodeGrpcAuthority" type="text" placeholder="Optional authority">
            </div>
          </div>
          <label class="chk-inline"><input id="editNodeGrpcMulti" type="checkbox"> <span>gRPC Multi Mode</span></label>
        </div>
        <div id="editTransKcp" class="field-grid hidden">
          <div>
            <div class="field-lbl">KCP Header Type</div>
            <select id="editNodeKcpHeader">
              <option value="none">none</option>
              <option value="srtp">srtp</option>
              <option value="utp">utp</option>
              <option value="wechat-video">wechat-video</option>
              <option value="dtls">dtls</option>
              <option value="wireguard">wireguard</option>
              <option value="dns">dns</option>
            </select>
          </div>
          <div>
            <div class="field-lbl">KCP Seed</div>
            <input id="editNodeKcpSeed" type="text" placeholder="Optional seed">
          </div>
        </div>
        <div style="margin-top:6px">
          <div class="field-lbl">Outbound Domain Strategy (sockopt)</div>
          <select id="editNodeDomainStrategy">
            <option value="">Auto (Default)</option>
            <option value="AsIs">AsIs</option>
            <option value="UseIP">UseIP (IPv4 &amp; IPv6)</option>
            <option value="UseIPv4">UseIPv4</option>
            <option value="UseIPv6">UseIPv6</option>
          </select>
        </div>
      </div>

      <div id="editSecSecurity" class="section-box" style="margin-bottom:8px">
        <div style="font-size:12px;font-weight:700;color:#38bdf8;margin-bottom:6px">Stream Security</div>
        <div id="editSecTypeRow">
          <div class="field-lbl">Security Layer</div>
          <select id="editNodeSecurity" onchange="onEditSecurityChange()">
            <option value="none">None (Plain)</option>
            <option value="tls">TLS</option>
            <option value="reality">REALITY</option>
          </select>
        </div>

        <div id="editSecFields" class="hidden">
          <div class="field-grid">
            <div>
              <div class="field-lbl">SNI / Server Name</div>
              <input id="editNodeSNI" type="text" placeholder="serverName / SNI">
            </div>
            <div>
              <div class="field-lbl">uTLS Fingerprint</div>
              <select id="editNodeFP">
                <option value="">Default</option>
                <option value="chrome">chrome</option>
                <option value="firefox">firefox</option>
                <option value="safari">safari</option>
                <option value="ios">ios</option>
                <option value="android">android</option>
                <option value="edge">edge</option>
                <option value="360">360</option>
                <option value="qq">qq</option>
                <option value="random">random</option>
                <option value="randomized">randomized</option>
              </select>
            </div>
          </div>

          <div id="editSecTlsOnly" class="hidden">
            <div class="field-grid">
              <div>
                <div class="field-lbl">ALPN (comma-separated)</div>
                <input id="editNodeALPN" type="text" placeholder="h2,http/1.1 or h3">
              </div>
              <div>
                <div class="field-lbl">Pinned Cert SHA256</div>
                <input id="editNodePinnedSha256" type="text" placeholder="Optional SHA256">
              </div>
            </div>
            <label class="chk-inline"><input id="editNodeAllowInsecure" type="checkbox"> <span>Allow Insecure TLS (skip certificate verification)</span></label>
          </div>

          <div id="editSecRealityOnly" class="hidden">
            <div class="field-lbl">Reality Public Key (pbk)</div>
            <input id="editNodeRealityPBK" type="text" placeholder="Public Key">
            <div class="field-grid">
              <div>
                <div class="field-lbl">Short ID (sid)</div>
                <input id="editNodeRealitySID" type="text" placeholder="Optional shortId">
              </div>
              <div>
                <div class="field-lbl">SpiderX (spx)</div>
                <input id="editNodeRealitySPX" type="text" placeholder="/">
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div id="editPaneJson" class="hidden">
      <div class="field-lbl">Raw Xray Outbound JSON</div>
      <textarea id="editNodeRawJSON" style="min-height:260px"></textarea>
      <div class="row" style="margin-bottom:8px">
        <button class="btn-sm" type="button" onclick="formatEditRawJSON()">Format JSON</button>
      </div>
    </div>

    <div id="editPaneUri" class="hidden">
      <div class="field-lbl">Import / Replace from Share URI</div>
      <input id="editNodeURI" type="text" placeholder="vless://... | trojan://... | vmess://... | ss://... | hy2://...">
      <div class="row" style="margin-bottom:12px">
        <button class="btn-blue btn-sm" type="button" onclick="loadEditURIIntoForm()">Parse URI into Editor</button>
      </div>
      <div class="field-lbl">Export Share URI</div>
      <input id="editNodeExportURI" type="text" readonly placeholder="Click Generate URI below">
      <div class="row" style="margin-bottom:8px">
        <button class="btn-sm" type="button" onclick="generateExportURI()">Generate URI</button>
        <button class="btn-blue btn-sm" type="button" onclick="copyExportURI()">Copy URI</button>
      </div>
    </div>

    <div class="row" style="margin-top:10px">
      <button id="btnSaveEditNode" class="btn-green" style="flex:2" type="button" onclick="saveEditNode()">Save Changes</button>
      <button id="btnDuplicateNode" class="btn-blue" style="flex:1" type="button" onclick="duplicateEditNode()">Duplicate</button>
      <button style="flex:1" type="button" onclick="closeEditNode()">Cancel</button>
    </div>
  </div>
</div>

<script>
var cachedApps = [];
var cachedNodes = [];
var selectedUIDMap = {};
var subInitialized = false;
var dnsInitialized = false;
var checkingConn = false;
var connCheckedOnce = false;
var currentEditTab = "visual";
var editingBaseOutbound = null;

function req(method, url, body, cb) {
  var xhr = new XMLHttpRequest();
  xhr.open(method, url, true);
  if (body) { xhr.setRequestHeader("Content-Type", "application/json"); }
  xhr.onreadystatechange = function() {
    if (xhr.readyState === 4) { cb(xhr.status, xhr.responseText); }
  };
  xhr.send(body ? JSON.stringify(body) : null);
}

function showMsg(txt) {
  var el = document.getElementById("toast");
  el.innerHTML = txt;
  setTimeout(function() { if (el.innerHTML === txt) { el.innerHTML = ""; } }, 4500);
}

function showTab(name) {
  var tabs = ["status", "nodes", "dns", "geo", "apps", "config", "logs"];
  for (var i = 0; i < tabs.length; i++) {
    var t = tabs[i];
    var tabEl = document.getElementById("t-" + t);
    var panelEl = document.getElementById("p-" + t);
    if (tabEl) tabEl.className = (t === name) ? "tab active" : "tab";
    if (panelEl) panelEl.className = (t === name) ? "card" : "card hidden";
  }
  if (name === "dns") { loadDNS(); }
  if (name === "geo") { loadGeo(); }
  if (name === "apps") { loadApps(); }
  if (name === "config") { loadConfig(); }
  if (name === "logs") { loadLogs(); }
}

function setDNSField(id, val) {
  document.getElementById(id).value = val;
}

function applyDNSUI(d) {
  if (!d) return;
  document.getElementById("dnsRemoteInput").value = d.remote_dns || "tcp://1.1.1.1";
  document.getElementById("dnsDirectInput").value = d.direct_dns || "1.1.1.1";
  var fallbackQS = d.query_strategy || "UseIPv4";
  document.getElementById("dnsRemoteStrategySel").value = d.remote_query_strategy || fallbackQS;
  document.getElementById("dnsDirectStrategySel").value = d.direct_query_strategy || fallbackQS;
  document.getElementById("dnsRedirectChk").checked = (d.dns_redirect !== false);
}

function loadDNS() {
  req("GET", "/api/dns", null, function(code, text) {
    if (code !== 200) { return; }
    var d = JSON.parse(text);
    applyDNSUI(d);
    dnsInitialized = true;
  });
}

function saveDNS() {
  var r = document.getElementById("dnsRemoteInput").value;
  var d = document.getElementById("dnsDirectInput").value;
  var rs = document.getElementById("dnsRemoteStrategySel").value;
  var ds = document.getElementById("dnsDirectStrategySel").value;
  var rd = document.getElementById("dnsRedirectChk").checked;
  var combined = (rs === ds) ? rs : "UseIP";
  showMsg("Applying DNS settings and reloading engine...");
  req("POST", "/api/dns", {
    remote_dns: r,
    direct_dns: d,
    query_strategy: combined,
    remote_query_strategy: rs,
    direct_query_strategy: ds,
    dns_redirect: rd
  }, function(code, text) {
    if (code === 200) {
      showMsg("DNS updated and proxy engine restarted.");
      refreshStatus();
    } else {
      var err = {};
      try { err = JSON.parse(text); } catch(e){}
      showMsg("DNS error: " + (err.error || text));
    }
  });
}

function loadGeo() {
  req("GET", "/api/geo", null, function(code, text) {
    if (code !== 200) { return; }
    var d = JSON.parse(text);
    document.getElementById("geoDomainStrategySel").value = d.domain_strategy || "IPIfNonMatch";
    document.getElementById("geoDomainMatcherSel").value = d.domain_matcher || "hybrid";
    document.getElementById("geoBypassIranChk").checked = (d.bypass_iran !== false);
    document.getElementById("geoBypassCNChk").checked = (d.bypass_cn !== false);
    document.getElementById("geoBlockAdsChk").checked = (d.block_ads !== false);

    document.getElementById("geoDirectDomains").value = (d.direct_domains || []).join("\n");
    document.getElementById("geoDirectIPs").value = (d.direct_ips || []).join("\n");
    document.getElementById("geoProxyDomains").value = (d.proxy_domains || []).join("\n");
    document.getElementById("geoProxyIPs").value = (d.proxy_ips || []).join("\n");
    document.getElementById("geoBlockDomains").value = (d.block_domains || []).join("\n");
    document.getElementById("geoBlockIPs").value = (d.block_ips || []).join("\n");

    document.getElementById("geoIpUrlInput").value = d.geoip_url || "";
    document.getElementById("geoSiteUrlInput").value = d.geosite_url || "";

    var assetDir = (d.assets && d.assets.asset_dir) || "";
    document.getElementById("geoAssetMeta").innerHTML =
      "Last updated: " + (d.last_geo_update || "Never") + (assetDir ? (" | Path: " + esc(assetDir)) : "");

    var ipBox = document.getElementById("geoipStatus");
    if (ipBox) {
      if (d.assets && d.assets.geoip && d.assets.geoip.exists) {
        ipBox.innerHTML = esc(d.assets.geoip.size_formatted) + "<br><span style=\"color:#64748b\">" + esc(d.assets.geoip.mod_time) + "</span>";
      } else {
        ipBox.innerHTML = "<span style=\"color:#f87171\">Not installed</span>";
      }
    }

    var siteBox = document.getElementById("geositeStatus");
    if (siteBox) {
      if (d.assets && d.assets.geosite && d.assets.geosite.exists) {
        siteBox.innerHTML = esc(d.assets.geosite.size_formatted) + "<br><span style=\"color:#64748b\">" + esc(d.assets.geosite.mod_time) + "</span>";
      } else {
        siteBox.innerHTML = "<span style=\"color:#f87171\">Not installed</span>";
      }
    }
  });
}

function parseLines(id) {
  var val = document.getElementById(id).value;
  var arr = val.split("\n");
  var out = [];
  for (var i = 0; i < arr.length; i++) {
    var s = arr[i].trim();
    if (s) { out.push(s); }
  }
  return out;
}

function saveGeo() {
  var body = {
    domain_strategy: document.getElementById("geoDomainStrategySel").value,
    domain_matcher: document.getElementById("geoDomainMatcherSel").value,
    bypass_iran: document.getElementById("geoBypassIranChk").checked,
    bypass_cn: document.getElementById("geoBypassCNChk").checked,
    block_ads: document.getElementById("geoBlockAdsChk").checked,
    direct_domains: parseLines("geoDirectDomains"),
    direct_ips: parseLines("geoDirectIPs"),
    proxy_domains: parseLines("geoProxyDomains"),
    proxy_ips: parseLines("geoProxyIPs"),
    block_domains: parseLines("geoBlockDomains"),
    block_ips: parseLines("geoBlockIPs"),
    geoip_url: document.getElementById("geoIpUrlInput").value.trim(),
    geosite_url: document.getElementById("geoSiteUrlInput").value.trim()
  };
  showMsg("Saving geo routing rules and updating engine...");
  req("POST", "/api/geo", body, function(code, text) {
    if (code === 200) {
      showMsg("Geo rules updated and proxy engine restarted.");
      refreshStatus();
    } else {
      var err = {};
      try { err = JSON.parse(text); } catch(e){}
      showMsg("Geo rules error: " + (err.error || text));
    }
  });
}

function updateGeoDatabases() {
  var btn = document.getElementById("btnUpdateGeo");
  if (btn) { btn.disabled = true; }
  showMsg("Downloading GeoIP and GeoSite databases over direct WAN...");
  var body = {
    geoip_url: document.getElementById("geoIpUrlInput").value.trim(),
    geosite_url: document.getElementById("geoSiteUrlInput").value.trim()
  };
  req("POST", "/api/geo/update", body, function(code, text) {
    if (btn) { btn.disabled = false; }
    if (code === 200) {
      showMsg("Geo databases updated successfully.");
      loadGeo();
      refreshStatus();
    } else {
      var err = {};
      try { err = JSON.parse(text); } catch(e){}
      showMsg("Geo update error: " + (err.error || text));
    }
  });
}

function setGeoPreset(preset) {
  if (preset === "iran") {
    document.getElementById("geoIpUrlInput").value = "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geoip.dat";
    document.getElementById("geoSiteUrlInput").value = "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geosite.dat";
  } else if (preset === "v2fly") {
    document.getElementById("geoIpUrlInput").value = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat";
    document.getElementById("geoSiteUrlInput").value = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat";
  }
}

function checkConn() {
  if (checkingConn) { return; }
  checkingConn = true;
  var gEl = document.getElementById("connGoogle");
  var ghEl = document.getElementById("connGithub");
  var btn = document.getElementById("btnCheckConn");
  if (gEl) { gEl.className = "conn-pill conn-wait"; gEl.innerHTML = "Google: ..."; }
  if (ghEl) { ghEl.className = "conn-pill conn-wait"; ghEl.innerHTML = "GitHub: ..."; }
  if (btn) { btn.disabled = true; }

  req("GET", "/api/connectivity", null, function(code, text) {
    checkingConn = false;
    if (btn) { btn.disabled = false; }
    if (code !== 200) {
      if (gEl) { gEl.className = "conn-pill conn-err"; gEl.innerHTML = "Google: Fail"; }
      if (ghEl) { ghEl.className = "conn-pill conn-err"; ghEl.innerHTML = "GitHub: Fail"; }
      return;
    }
    var res = JSON.parse(text);
    if (gEl) {
      if (res.google && res.google.reachable) {
        gEl.className = "conn-pill conn-ok";
        gEl.innerHTML = "Google: " + res.google.latency_ms + "ms";
      } else {
        gEl.className = "conn-pill conn-err";
        gEl.innerHTML = "Google: " + ((res.google && res.google.status) || "Fail");
      }
    }
    if (ghEl) {
      if (res.github && res.github.reachable) {
        ghEl.className = "conn-pill conn-ok";
        ghEl.innerHTML = "GitHub: " + res.github.latency_ms + "ms";
      } else {
        ghEl.className = "conn-pill conn-err";
        ghEl.innerHTML = "GitHub: " + ((res.github && res.github.status) || "Fail");
      }
    }
  });
}

function toggleLocalhostProxy(checked) {
  showMsg((checked ? "Enabling" : "Disabling") + " localhost proxy...");
  req("POST", "/api/localhost_proxy", {localhost_proxy: checked}, function(code, text) {
    if (code === 200) {
      showMsg("Localhost proxy " + (checked ? "enabled." : "disabled."));
      refreshStatus();
    } else {
      showMsg("Error setting localhost proxy: " + text);
    }
  });
}

function toggleAllowInsecureVless(checked) {
  showMsg((checked ? "Enabling" : "Disabling") + " VLESS without TLS/encryption bypass...");
  req("POST", "/api/vless_insecure", {allow_insecure_vless: !!checked}, function(code, text) {
    if (code === 200) {
      showMsg("VLESS without TLS/encryption bypass " + (checked ? "enabled." : "disabled."));
      refreshStatus();
    } else {
      var err = text;
      try { err = JSON.parse(text).error || text; } catch(e){}
      showMsg("Error updating VLESS switcher: " + err);
      refreshStatus();
    }
  });
}

function setAllowInsecureVless(val) {
  var el = document.getElementById("allowInsecureVlessChk");
  if (el) { el.checked = !!val; }
  toggleAllowInsecureVless(!!val);
}

function refreshStatus() {
  req("GET", "/api/status", null, function(code, text) {
    if (code !== 200) { return; }
    var d = JSON.parse(text);
    var b = document.getElementById("statusBadge");
    b.innerHTML = d.running ? "RUNNING" : "STOPPED";
    b.className = d.running ? "badge on" : "badge off";
    document.getElementById("modVerBadge").innerHTML = esc(d.module_version || "v1.2.1");
    document.getElementById("metaLine").innerHTML =
      "Xray: " + esc(d.xray_version || "Unknown") + " | Netfilter: " + esc(d.net_mode) + " | PID: " + d.daemon_pid;

    // Battery & Resource Metrics
    var batText = (typeof d.battery_pct === "number" && d.battery_pct >= 0) ? (d.battery_pct + "%") : "N/A";
    var batStatus = d.battery_status ? (" (" + d.battery_status + ")") : "";
    var elBat = document.getElementById("statBattery");
    if (elBat) elBat.innerHTML = "🔋 Battery: " + batText + batStatus;
    var elCardBat = document.getElementById("statCardBattery");
    if (elCardBat) elCardBat.innerHTML = batText;
    var elCardBatSt = document.getElementById("statCardBatteryStatus");
    if (elCardBatSt) elCardBatSt.innerHTML = "Status: " + (d.battery_status || "Standard");

    var modCPU = (typeof d.module_cpu === "number") ? (d.module_cpu.toFixed(1) + "%") : "--";
    var modRAM = d.module_ram_str || "--";
    var elMod = document.getElementById("statModule");
    if (elMod) elMod.innerHTML = "Module: " + modCPU + " | " + modRAM;
    var elCardModCPU = document.getElementById("statCardModuleCPU");
    if (elCardModCPU) elCardModCPU.innerHTML = "CPU: " + modCPU;
    var elCardModRAM = document.getElementById("statCardModuleRAM");
    if (elCardModRAM) elCardModRAM.innerHTML = "RAM: " + modRAM + " (PID " + d.daemon_pid + ")";

    var xrayRunning = (d.xray_pid > 0);
    var xrayCPU = xrayRunning ? ((typeof d.xray_cpu === "number") ? (d.xray_cpu.toFixed(1) + "%") : "--") : "Stopped";
    var xrayRAM = xrayRunning ? (d.xray_ram_str || "--") : "0 B";
    var elXray = document.getElementById("statXray");
    if (elXray) elXray.innerHTML = "Xray: " + xrayCPU + " | " + xrayRAM;
    var elCardXrayCPU = document.getElementById("statCardXrayCPU");
    if (elCardXrayCPU) elCardXrayCPU.innerHTML = "CPU: " + xrayCPU;
    var elCardXrayRAM = document.getElementById("statCardXrayRAM");
    if (elCardXrayRAM) elCardXrayRAM.innerHTML = "RAM: " + xrayRAM + (xrayRunning ? (" (PID " + d.xray_pid + ")") : "");

    var elCardPIDs = document.getElementById("statCardPIDs");
    if (elCardPIDs) elCardPIDs.innerHTML = "M:" + d.daemon_pid + " | X:" + (d.xray_pid || "--");
    var elCardNet = document.getElementById("statCardNetMode");
    if (elCardNet) elCardNet.innerHTML = esc(d.net_mode || "--");

    var elCardNode = document.getElementById("statCardActiveNode");
    if (elCardNode) {
      var actNode = null;
      var nds = d.nodes || [];
      for (var ni = 0; ni < nds.length; ni++) {
        if (nds[ni].id === d.active_node) { actNode = nds[ni]; break; }
      }
      if (actNode) {
        var lat = (actNode.latency_ms > 0) ? (actNode.latency_ms + " ms") : "--";
        elCardNode.innerHTML = "<b>" + esc(actNode.name) + "</b> &bull; " +
          esc(actNode.protocol.toUpperCase()) + " &bull; " + esc(actNode.address) + ":" + actNode.port +
          " &bull; Latency: " + lat;
      } else {
        elCardNode.innerHTML = '<span style="color:#f59e0b">No proxy node currently active</span>';
      }
    }

    var chk = document.getElementById("localhostProxyChk");
    if (chk) {
      chk.checked = (d.localhost_proxy !== false);
    }

    var vlessChk = document.getElementById("allowInsecureVlessChk");
    if (vlessChk) {
      vlessChk.checked = !!d.allow_insecure_vless;
    }
    var vlessAlert = document.getElementById("vlessInsecureAlert");
    if (vlessAlert) {
      vlessAlert.className = (d.vless_insecure_needed && !d.allow_insecure_vless) ? "alert-warn" : "alert-warn hidden";
    }

    if (d.running && !connCheckedOnce) {
      connCheckedOnce = true;
      checkConn();
    } else if (!d.running) {
      var gEl = document.getElementById("connGoogle");
      var ghEl = document.getElementById("connGithub");
      if (gEl) { gEl.className = "conn-pill"; gEl.innerHTML = "Google: Stopped"; }
      if (ghEl) { ghEl.className = "conn-pill"; ghEl.innerHTML = "GitHub: Stopped"; }
    }

    var modes = ["rule", "global", "direct"];
    for (var i = 0; i < modes.length; i++) {
      var m = modes[i];
      document.getElementById("mode-" + m).className = (d.proxy_mode === m) ? "btn-active" : "";
    }
    if (!subInitialized) {
      document.getElementById("subUrlInput").value = d.sub_url || "";
      document.getElementById("subAutoSel").value = String(d.auto_update_hours || 0);
      document.getElementById("subInsecureChk").checked = !!d.sub_insecure;
      subInitialized = true;
    }
    if (!dnsInitialized && d.dns) {
      applyDNSUI(d.dns);
      dnsInitialized = true;
    }
    document.getElementById("subMeta").innerHTML =
      "Last updated: " + (d.last_sub_update || "Never");

    cachedNodes = d.nodes || [];
    renderNodes(d.nodes || [], d.active_node || "");
  });
}

function renderNodes(nodes, activeId) {
  var box = document.getElementById("nodeList");
  if (!nodes.length) {
    box.innerHTML = '<div class="meta" style="color:#f59e0b;padding:6px 0;">⚠ No proxy nodes imported. Foreign sites (e.g. Google) require an active node to bypass censorship.</div>';
    return;
  }
  var html = "";
  if (!activeId) {
    html += '<div class="meta" style="color:#f59e0b;margin-bottom:6px;">⚠ No node currently active. Click &quot;Use&quot; on a node below to route traffic through it.</div>';
  }
  for (var i = 0; i < nodes.length; i++) {
    var n = nodes[i];
    var sel = (n.id === activeId);
    var latHtml = "";
    if (n.latency_ms > 0) {
      var cls = n.latency_ms < 250 ? "lat lat-ok" : "lat lat-slow";
      latHtml = '<span class="' + cls + '">' + n.latency_ms + ' ms</span>';
    } else if (n.latency_ms < 0) {
      latHtml = '<span class="lat lat-err">Timeout</span>';
    }
    html += '<div class="node-item' + (sel ? ' selected' : '') + '">' +
      '<div class="node-info"><b>' + esc(n.name) + '</b><div class="node-sub">' +
      esc(n.protocol.toUpperCase()) + ' (' + esc(n.group || 'manual') + ') - ' + esc(n.address) + ':' + n.port + '</div></div>' +
      '<div class="row">' + latHtml +
      '<button class="btn-sm" onclick="pingOne(\'' + escAttr(n.id) + '\')">Ping</button>' +
      '<button class="btn-blue btn-sm" onclick="openEditNode(\'' + escAttr(n.id) + '\')">Edit</button>' +
      (sel ? '' : '<button class="btn-blue btn-sm" onclick="nodeAct(\'select\',\'' + escAttr(n.id) + '\')">Use</button>') +
      '<button class="btn-red btn-sm" onclick="nodeAct(\'delete\',\'' + escAttr(n.id) + '\')">X</button>' +
      '</div></div>';
  }
  box.innerHTML = html;
}

function esc(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

function escAttr(s) {
  return String(s).replace(/\\/g,"\\\\").replace(/'/g,"\\'").replace(/"/g,"&quot;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

function ctrl(action) {
  showMsg("Executing " + action + "...");
  req("POST", "/api/control", {action: action}, function(code, text) {
    if (code === 200) { showMsg("Action " + action + " completed."); }
    else { showMsg("Error: " + text); }
    refreshStatus();
  });
}

function setMode(mode) {
  var modes = ["rule", "global", "direct"];
  for (var i = 0; i < modes.length; i++) {
    var el = document.getElementById("mode-" + modes[i]);
    if (el) el.className = (modes[i] === mode ? "btn-active" : "");
  }
  showMsg("Switching to " + mode.toUpperCase() + " mode and restarting engine...");
  req("POST", "/api/mode", {proxy_mode: mode}, function(code, text) {
    if (code === 200) {
      showMsg("Active mode: " + mode.toUpperCase() + " (service restarted)");
    } else {
      showMsg("Mode update failed: " + text);
    }
    setTimeout(refreshStatus, 300);
  });
}

function saveSub(fetchNow) {
  var u = document.getElementById("subUrlInput").value;
  var hrs = parseInt(document.getElementById("subAutoSel").value, 10) || 0;
  var insecure = document.getElementById("subInsecureChk").checked;
  if (fetchNow) { showMsg("Fetching subscription over direct WAN..."); }
  req("POST", "/api/sub", {sub_url: u, auto_update_hours: hrs, sub_insecure: insecure, fetch_now: fetchNow}, function(code, text) {
    if (code === 200) {
      var res = JSON.parse(text);
      showMsg(fetchNow ? ("Imported " + res.imported + " subscription nodes.") : "Subscription settings saved.");
      refreshStatus();
    } else {
      var err = JSON.parse(text);
      showMsg("Sub error: " + (err.error || text));
    }
  });
}

function pingOne(id) {
  showMsg("Testing node latency...");
  req("POST", "/api/ping", {id: id, select_fastest: false}, function() {
    showMsg("Latency test complete.");
    refreshStatus();
  });
}

function pingAll(selectFastest) {
  showMsg(selectFastest ? "Testing all & selecting fastest..." : "Testing all nodes...");
  req("POST", "/api/ping", {id: "", select_fastest: selectFastest}, function() {
    showMsg(selectFastest ? "Switched to fastest reachable node." : "All node latencies updated.");
    refreshStatus();
  });
}

function importURI() {
  var uri = document.getElementById("uriInput").value;
  if (!uri) { return; }
  req("POST", "/api/nodes", {action: "import", uri: uri}, function(code, text) {
    if (code === 200) {
      document.getElementById("uriInput").value = "";
      showMsg("Node imported and activated.");
      refreshStatus();
    } else {
      var err = JSON.parse(text);
      showMsg("Import error: " + (err.error || text));
    }
  });
}

function nodeAct(action, id) {
  req("POST", "/api/nodes", {action: action, id: id}, function() { refreshStatus(); });
}

function loadApps() {
  req("GET", "/api/apps", null, function(code, text) {
    if (code !== 200) { return; }
    var d = JSON.parse(text);
    cachedApps = d.apps || [];
    document.getElementById("appModeSel").value = d.app_filter_mode || "bypass";
    selectedUIDMap = {};
    var uids = d.selected_uids || [];
    for (var i = 0; i < uids.length; i++) { selectedUIDMap[uids[i]] = true; }
    renderApps();
  });
}

function renderApps() {
  var q = document.getElementById("appSearch").value.toLowerCase();
  var box = document.getElementById("appList");
  var html = "";
  for (var i = 0; i < cachedApps.length; i++) {
    var a = cachedApps[i];
    if (q && a.package.toLowerCase().indexOf(q) === -1) { continue; }
    var chk = selectedUIDMap[a.uid] ? " checked" : "";
    html += '<div class="app-row"><div><b>' + esc(a.package) + '</b> <span class="node-sub">(UID ' + a.uid + ')</span></div>' +
      '<input type="checkbox"' + chk + ' onchange="toggleUID(' + a.uid + ', this.checked)"></div>';
  }
  box.innerHTML = html || '<div class="meta">No matching apps found.</div>';
}

function toggleUID(uid, checked) {
  if (checked) { selectedUIDMap[uid] = true; }
  else { delete selectedUIDMap[uid]; }
}

function saveApps() {
  var uids = [];
  for (var k in selectedUIDMap) {
    if (selectedUIDMap.hasOwnProperty(k)) { uids.push(parseInt(k, 10)); }
  }
  var mode = document.getElementById("appModeSel").value;
  showMsg("Applying per-app iptables UID rules...");
  req("POST", "/api/apps", {app_filter_mode: mode, selected_uids: uids}, function(code) {
    if (code === 200) { showMsg("App split tunneling updated (" + uids.length + " apps)."); }
  });
}

function loadConfig() {
  req("GET", "/api/config", null, function(code, text) {
    if (code === 200) { document.getElementById("cfgEditor").value = text; }
  });
}

function saveConfig() {
  var raw = document.getElementById("cfgEditor").value;
  req("POST", "/api/config", {raw_json: raw}, function(code, text) {
    if (code === 200) { showMsg("Saved config.json and restarted Xray."); refreshStatus(); }
    else {
      var err = JSON.parse(text);
      showMsg(err.error || "Save failed");
    }
  });
}

function resetConfig() {
  if (!confirm("Are you sure you want to reset Xray base config (config.json) to factory default? Any custom modifications will be lost.")) return;
  req("POST", "/api/config/reset", {}, function(code, text) {
    if (code === 200) {
      showMsg("Config reset to default and restarted Xray.");
      loadConfig();
      refreshStatus();
    } else {
      showMsg("Reset failed: " + text);
    }
  });
}

function downloadBackup() {
  window.location.href = "/api/backup?download=1";
}

function viewBackupJSON() {
  var wrap = document.getElementById("backupJsonWrap");
  if (wrap) { wrap.className = ""; }
  showMsg("Generating backup JSON...");
  req("GET", "/api/backup", null, function(code, text) {
    if (code === 200) {
      var box = document.getElementById("backupJsonBox");
      if (box) {
        box.value = text;
        box.select();
        try { document.execCommand("copy"); } catch(e){}
      }
      showMsg("Backup JSON loaded (ready to copy or restore).");
    } else {
      showMsg("Backup error: " + text);
    }
  });
}

function toggleBackupPaste() {
  var wrap = document.getElementById("backupJsonWrap");
  if (!wrap) return;
  wrap.className = (wrap.className === "hidden") ? "" : "hidden";
}

function sendRestorePayload(rawText) {
  if (!confirm("Restore backup? Current nodes, settings, and base config.json will be replaced.")) return;
  showMsg("Restoring backup...");
  var xhr = new XMLHttpRequest();
  xhr.open("POST", "/api/restore", true);
  xhr.setRequestHeader("Content-Type", "application/json");
  xhr.onreadystatechange = function() {
    if (xhr.readyState === 4) {
      if (xhr.status === 200) {
        var res = {};
        try { res = JSON.parse(xhr.responseText); } catch(e){}
        subInitialized = false;
        dnsInitialized = false;
        var fi = document.getElementById("restoreFileInput");
        if (fi) { fi.value = ""; }
        showMsg("Backup restored (" + (res.nodes || 0) + " nodes).");
        loadConfig();
        refreshStatus();
      } else {
        var err = xhr.responseText;
        try { err = JSON.parse(xhr.responseText).error || xhr.responseText; } catch(e){}
        showMsg("Restore failed: " + err);
      }
    }
  };
  xhr.send(rawText);
}

function restoreBackup() {
  var fi = document.getElementById("restoreFileInput");
  if (fi && fi.files && fi.files.length > 0) {
    var reader = new FileReader();
    reader.onload = function(ev) {
      sendRestorePayload(ev.target.result || "");
    };
    reader.onerror = function() {
      showMsg("Failed to read selected backup file.");
    };
    reader.readAsText(fi.files[0]);
    return;
  }
  var box = document.getElementById("backupJsonBox");
  var raw = box ? box.value : "";
  if (raw && raw.trim()) {
    sendRestorePayload(raw);
    return;
  }
  showMsg("Choose a backup .json file or paste backup JSON first.");
}

function loadLogs() {
  req("GET", "/api/logs", null, function(code, text) {
    if (code === 200) {
      var box = document.getElementById("logBox");
      box.innerHTML = esc(text);
      box.scrollTop = box.scrollHeight;
    }
  });
}

function clearLogs() {
  req("DELETE", "/api/logs", null, function() { loadLogs(); });
}

function downloadLogs() {
  window.location.href = "/api/logs?download=1";
}

function showEditModalErr(msg) {
  var el = document.getElementById("editModalErr");
  if (!el) return;
  if (!msg) {
    el.innerHTML = "";
    el.className = "alert-warn hidden";
  } else {
    el.innerHTML = esc(msg);
    el.className = "alert-warn";
  }
}

function setSelectOrAdd(id, val, fallback) {
  var sel = document.getElementById(id);
  if (!sel) return;
  var v = (val !== undefined && val !== null) ? String(val) : "";
  if (!v && fallback !== undefined) { v = String(fallback); }
  var found = false;
  for (var i = 0; i < sel.options.length; i++) {
    if (sel.options[i].value === v) { found = true; break; }
  }
  if (!found && v) {
    var opt = document.createElement("option");
    opt.value = v;
    opt.text = v;
    sel.appendChild(opt);
  }
  sel.value = v;
}

function normProtoUI(p) {
  var s = String(p || "vless").toLowerCase();
  if (s === "hysteria" || s === "hy2") return "hysteria2";
  if (s === "ss") return "shadowsocks";
  return s;
}

function normNetUI(n) {
  var s = String(n || "tcp").toLowerCase();
  if (s === "splithttp") return "xhttp";
  if (s === "raw") return "tcp";
  if (s === "websocket") return "ws";
  return s;
}

function onEditProtocolChange() {
  var proto = document.getElementById("editNodeProtocol").value;
  var isVless = (proto === "vless");
  var isVmess = (proto === "vmess");
  var isTrojan = (proto === "trojan");
  var isSS = (proto === "shadowsocks");
  var isHy = (proto === "hysteria2");

  document.getElementById("editAuthUUIDRow").className = (isVless || isVmess) ? "" : "hidden";
  document.getElementById("editAuthVlessRow").className = isVless ? "field-grid" : "field-grid hidden";
  document.getElementById("editAuthVmessRow").className = isVmess ? "field-grid" : "field-grid hidden";
  document.getElementById("editAuthSSMethodRow").className = isSS ? "" : "hidden";
  document.getElementById("editAuthPasswordRow").className = (isTrojan || isSS || isHy) ? "" : "hidden";
  document.getElementById("editAuthHyRow").className = isHy ? "" : "hidden";
  document.getElementById("editPasswordLbl").innerHTML = isHy ? "Auth Password / Secret" : "Password";

  document.getElementById("editSecTransport").className = isHy ? "section-box hidden" : "section-box";
  document.getElementById("editSecTypeRow").className = isHy ? "hidden" : "";
  if (isHy) {
    document.getElementById("editNodeSecurity").value = "tls";
  }
  onEditNetworkChange();
  onEditSecurityChange();
}

function onEditNetworkChange() {
  var proto = document.getElementById("editNodeProtocol").value;
  if (proto === "hysteria2") return;
  var net = document.getElementById("editNodeNetwork").value;
  var tcpHdr = document.getElementById("editNodeTcpHeaderType").value;

  document.getElementById("editTransTcp").className = (net === "tcp") ? "" : "hidden";
  var showHostPath = (net === "ws" || net === "xhttp" || net === "httpupgrade" || (net === "tcp" && tcpHdr === "http"));
  document.getElementById("editTransHostPath").className = showHostPath ? "field-grid" : "field-grid hidden";
  document.getElementById("editTransXhttp").className = (net === "xhttp") ? "" : "hidden";
  document.getElementById("editTransGrpc").className = (net === "grpc") ? "" : "hidden";
  document.getElementById("editTransKcp").className = (net === "kcp") ? "field-grid" : "field-grid hidden";
}

function onEditSecurityChange() {
  var proto = document.getElementById("editNodeProtocol").value;
  var sec = (proto === "hysteria2") ? "tls" : document.getElementById("editNodeSecurity").value;
  var hasSec = (sec === "tls" || sec === "reality");
  document.getElementById("editSecFields").className = hasSec ? "" : "hidden";
  document.getElementById("editSecTlsOnly").className = (sec === "tls") ? "" : "hidden";
  document.getElementById("editSecRealityOnly").className = (sec === "reality") ? "" : "hidden";
}

function cloneJsonObj(o) {
  if (!o) return {};
  try { return JSON.parse(JSON.stringify(o)); } catch(e) { return {}; }
}

function populateEditModalFromNode(node, isNew) {
  showEditModalErr("");
  document.getElementById("editNodeIsNew").value = isNew ? "1" : "0";
  document.getElementById("editNodeId").value = isNew ? "" : (node.id || "");
  document.getElementById("editModalTitle").innerHTML = isNew ? "Create Proxy Node" : "Edit Proxy Node";
  document.getElementById("btnSaveEditNode").innerHTML = isNew ? "Create Node" : "Save Changes";
  document.getElementById("btnDuplicateNode").className = isNew ? "btn-blue hidden" : "btn-blue";

  var ob = cloneJsonObj(node.outbound);
  editingBaseOutbound = ob;

  var proto = normProtoUI(node.protocol || ob.protocol || "vless");
  setSelectOrAdd("editNodeProtocol", proto, "vless");
  document.getElementById("editNodeName").value = node.name || "";
  document.getElementById("editNodeAddress").value = node.address || "";
  document.getElementById("editNodePort").value = node.port || (proto === "shadowsocks" ? 8388 : 443);
  document.getElementById("editNodeURI").value = "";
  document.getElementById("editNodeExportURI").value = "";

  var stg = ob.settings || {};
  var vnext0 = (stg.vnext && stg.vnext[0]) ? stg.vnext[0] : null;
  var user0 = (vnext0 && vnext0.users && vnext0.users[0]) ? vnext0.users[0] : null;
  var srv0 = (stg.servers && stg.servers[0]) ? stg.servers[0] : null;

  if (!document.getElementById("editNodeAddress").value) {
    document.getElementById("editNodeAddress").value = (vnext0 && vnext0.address) || (srv0 && srv0.address) || stg.address || "";
  }
  if (!node.port) {
    var p = (vnext0 && vnext0.port) || (srv0 && srv0.port) || stg.port;
    if (p) document.getElementById("editNodePort").value = p;
  }

  document.getElementById("editNodeUUID").value = (user0 && user0.id) || stg.id || "";
  setSelectOrAdd("editNodeFlow", (user0 && user0.flow) || stg.flow || "", "");
  document.getElementById("editNodeVlessEncryption").value = (user0 && user0.encryption) || stg.encryption || "none";
  document.getElementById("editNodeAlterId").value = (user0 && typeof user0.alterId === "number") ? user0.alterId : 0;
  setSelectOrAdd("editNodeVmessSecurity", (user0 && user0.security) || "auto", "auto");
  setSelectOrAdd("editNodeSSMethod", (srv0 && srv0.method) || "aes-256-gcm", "aes-256-gcm");

  var ss = ob.streamSettings || {};
  var hySet = ss.hysteriaSettings || {};
  document.getElementById("editNodePassword").value = (proto === "hysteria2") ? (hySet.auth || "") : ((srv0 && srv0.password) || "");
  document.getElementById("editNodeHyUp").value = hySet.up || "";
  document.getElementById("editNodeHyDown").value = hySet.down || "";

  var obfsType = "";
  var obfsPass = "";
  if (ss.finalmask && ss.finalmask.udp && ss.finalmask.udp[0]) {
    obfsType = ss.finalmask.udp[0].type || "";
    if (ss.finalmask.udp[0].settings) obfsPass = ss.finalmask.udp[0].settings.password || "";
  }
  setSelectOrAdd("editNodeHyObfsType", obfsType, "");
  document.getElementById("editNodeHyObfsPass").value = obfsPass;

  var netType = normNetUI(ss.network || "tcp");
  if (proto === "hysteria2") netType = "tcp";
  setSelectOrAdd("editNodeNetwork", netType, "tcp");

  var host = "";
  var path = "/";
  var tcpHdr = "none";
  if (netType === "tcp") {
    if (ss.tcpSettings && ss.tcpSettings.header && ss.tcpSettings.header.type === "http") {
      tcpHdr = "http";
      var reqObj = ss.tcpSettings.header.request || {};
      if (reqObj.path && reqObj.path.length) path = reqObj.path[0];
      if (reqObj.headers && reqObj.headers.Host && reqObj.headers.Host.length) host = reqObj.headers.Host[0];
    }
  } else if (netType === "ws") {
    var ws = ss.wsSettings || {};
    path = ws.path || "/";
    host = ws.host || (ws.headers && ws.headers.Host) || "";
  } else if (netType === "xhttp") {
    var xh = ss.xhttpSettings || ss.splithttpSettings || {};
    path = xh.path || "/";
    host = xh.host || "";
    setSelectOrAdd("editNodeXhttpMode", xh.mode || "", "");
  } else if (netType === "httpupgrade") {
    var hu = ss.httpupgradeSettings || {};
    path = hu.path || "/";
    host = hu.host || "";
  } else if (netType === "grpc") {
    var gs = ss.grpcSettings || {};
    document.getElementById("editNodeGrpcService").value = gs.serviceName || "";
    document.getElementById("editNodeGrpcAuthority").value = gs.authority || "";
    document.getElementById("editNodeGrpcMulti").checked = !!gs.multiMode;
  } else if (netType === "kcp") {
    var ks = ss.kcpSettings || {};
    setSelectOrAdd("editNodeKcpHeader", (ks.header && ks.header.type) || "none", "none");
    document.getElementById("editNodeKcpSeed").value = ks.seed || "";
  }
  setSelectOrAdd("editNodeTcpHeaderType", tcpHdr, "none");
  document.getElementById("editNodeHost").value = host;
  document.getElementById("editNodePath").value = path;

  var sec = (ss.security || "none").toLowerCase();
  if (proto === "hysteria2") sec = "tls";
  if (sec !== "tls" && sec !== "reality") sec = "none";
  setSelectOrAdd("editNodeSecurity", sec, "none");

  var sni = "";
  var fp = "";
  var alpn = "";
  var allowInsec = false;
  var pin = "";
  var pbk = "";
  var sid = "";
  var spx = "";

  if (sec === "tls") {
    var ts = ss.tlsSettings || {};
    sni = ts.serverName || "";
    fp = ts.fingerprint || "";
    if (ts.alpn && ts.alpn.length) alpn = ts.alpn.join(",");
    allowInsec = !!ts.allowInsecure;
    pin = ts.pinnedPeerCertificateSha256 || "";
  } else if (sec === "reality") {
    var rs = ss.realitySettings || {};
    sni = rs.serverName || "";
    fp = rs.fingerprint || "chrome";
    pbk = rs.publicKey || "";
    sid = rs.shortId || "";
    spx = rs.spiderX || "";
  }

  document.getElementById("editNodeSNI").value = sni;
  setSelectOrAdd("editNodeFP", fp, "");
  document.getElementById("editNodeALPN").value = alpn;
  document.getElementById("editNodeAllowInsecure").checked = allowInsec;
  document.getElementById("editNodePinnedSha256").value = pin;
  document.getElementById("editNodeRealityPBK").value = pbk;
  document.getElementById("editNodeRealitySID").value = sid;
  document.getElementById("editNodeRealitySPX").value = spx;
  var sockopt = ss.sockopt || {};
  setSelectOrAdd("editNodeDomainStrategy", sockopt.domainStrategy || "", "");

  document.getElementById("editNodeRawJSON").value = JSON.stringify(ob, null, 2);
  onEditProtocolChange();
}

function collectEditFormPayload(actionName, targetId) {
  return {
    action: actionName,
    full_edit: true,
    id: targetId || "",
    name: document.getElementById("editNodeName").value,
    protocol: document.getElementById("editNodeProtocol").value,
    address: document.getElementById("editNodeAddress").value,
    port: parseInt(document.getElementById("editNodePort").value, 10) || 0,
    uuid: document.getElementById("editNodeUUID").value,
    flow: document.getElementById("editNodeFlow").value,
    encryption: document.getElementById("editNodeVlessEncryption").value,
    alter_id: parseInt(document.getElementById("editNodeAlterId").value, 10) || 0,
    vmess_security: document.getElementById("editNodeVmessSecurity").value,
    password: document.getElementById("editNodePassword").value,
    ss_method: document.getElementById("editNodeSSMethod").value,
    network: document.getElementById("editNodeNetwork").value,
    tcp_header_type: document.getElementById("editNodeTcpHeaderType").value,
    host: document.getElementById("editNodeHost").value,
    path: document.getElementById("editNodePath").value,
    xhttp_mode: document.getElementById("editNodeXhttpMode").value,
    service_name: document.getElementById("editNodeGrpcService").value,
    grpc_authority: document.getElementById("editNodeGrpcAuthority").value,
    grpc_multi_mode: document.getElementById("editNodeGrpcMulti").checked,
    kcp_header_type: document.getElementById("editNodeKcpHeader").value,
    kcp_seed: document.getElementById("editNodeKcpSeed").value,
    security: document.getElementById("editNodeSecurity").value,
    sni: document.getElementById("editNodeSNI").value,
    fp: document.getElementById("editNodeFP").value,
    alpn: document.getElementById("editNodeALPN").value,
    allow_insecure: document.getElementById("editNodeAllowInsecure").checked,
    pinned_sha256: document.getElementById("editNodePinnedSha256").value,
    pbk: document.getElementById("editNodeRealityPBK").value,
    sid: document.getElementById("editNodeRealitySID").value,
    spx: document.getElementById("editNodeRealitySPX").value,
    hy_up: document.getElementById("editNodeHyUp").value,
    hy_down: document.getElementById("editNodeHyDown").value,
    obfs_type: document.getElementById("editNodeHyObfsType").value,
    obfs_password: document.getElementById("editNodeHyObfsPass").value,
    sockopt_domain_strategy: document.getElementById("editNodeDomainStrategy").value
  };
}

function syncVisualToRawJSON() {
  var p = collectEditFormPayload("edit", "");
  var ob = cloneJsonObj(editingBaseOutbound);
  ob.tag = "proxy";
  ob.protocol = (p.protocol === "hysteria2") ? "hysteria" : p.protocol;
  if (!ob.settings) ob.settings = {};
  if (p.protocol === "vless") {
    var u = {id: p.uuid, encryption: p.encryption || "none"};
    if (p.flow) u.flow = p.flow;
    ob.settings = {vnext: [{address: p.address, port: p.port, users: [u]}]};
  } else if (p.protocol === "vmess") {
    ob.settings = {vnext: [{address: p.address, port: p.port, users: [{id: p.uuid, alterId: p.alter_id, security: p.vmess_security || "auto"}]}]};
  } else if (p.protocol === "trojan") {
    ob.settings = {servers: [{address: p.address, port: p.port, password: p.password}]};
  } else if (p.protocol === "shadowsocks") {
    ob.settings = {servers: [{address: p.address, port: p.port, method: p.ss_method || "aes-256-gcm", password: p.password}]};
  } else if (p.protocol === "hysteria2") {
    ob.settings = {version: 2, address: p.address, port: p.port};
  }
  var origSS = ob.streamSettings || {};
  var ss = {};
  if (origSS.sockopt) ss.sockopt = origSS.sockopt;
  if (p.protocol === "hysteria2") {
    ss.network = "hysteria";
    ss.security = "tls";
    var alpnRaw = p.alpn ? p.alpn.split(",") : ["h3"];
    var alpnArr = [];
    for (var i = 0; i < alpnRaw.length; i++) {
      var trimmedAlpn = alpnRaw[i].trim();
      if (trimmedAlpn) alpnArr.push(trimmedAlpn);
    }
    if (!alpnArr.length) alpnArr = ["h3"];
    ss.tlsSettings = {serverName: p.sni || p.address, alpn: alpnArr, allowInsecure: !!p.allow_insecure, fingerprint: p.fp || "chrome"};
    if (p.pinned_sha256) ss.tlsSettings.pinnedPeerCertificateSha256 = p.pinned_sha256;
    ss.hysteriaSettings = {version: 2, auth: p.password, udpIdleTimeout: 60};
    if (p.hy_up) ss.hysteriaSettings.up = p.hy_up;
    if (p.hy_down) ss.hysteriaSettings.down = p.hy_down;
    if (p.obfs_type && p.obfs_password) {
      var mObj = [{type: p.obfs_type, settings: {password: p.obfs_password}}];
      ss.finalmask = {udp: mObj};
      ss.udpmasks = mObj;
    }
    ob.streamSettings = ss;
  } else if (!(p.protocol === "shadowsocks" && p.network === "tcp" && p.security === "none" && p.tcp_header_type !== "http")) {
    ss.network = p.network || "tcp";
    if (ss.network === "tcp" && p.tcp_header_type === "http") {
      var reqHdr = {version: "1.1", method: "GET", path: [p.path || "/"]};
      if (p.host) reqHdr.headers = {Host: [p.host]};
      ss.tcpSettings = {header: {type: "http", request: reqHdr}};
    } else if (p.network === "ws") {
      ss.wsSettings = {path: p.path || "/"};
      if (p.host) { ss.wsSettings.host = p.host; ss.wsSettings.headers = {Host: p.host}; }
    } else if (p.network === "xhttp") {
      ss.xhttpSettings = (origSS.xhttpSettings && typeof origSS.xhttpSettings === "object") ? cloneJsonObj(origSS.xhttpSettings) : {};
      ss.xhttpSettings.path = p.path || "/";
      if (p.host) { ss.xhttpSettings.host = p.host; } else { delete ss.xhttpSettings.host; }
      if (p.xhttp_mode) { ss.xhttpSettings.mode = p.xhttp_mode; } else { delete ss.xhttpSettings.mode; }
    } else if (p.network === "httpupgrade") {
      ss.httpupgradeSettings = {path: p.path || "/"};
      if (p.host) ss.httpupgradeSettings.host = p.host;
    } else if (p.network === "grpc") {
      ss.grpcSettings = {serviceName: p.service_name || ""};
      if (p.grpc_multi_mode) ss.grpcSettings.multiMode = true;
      if (p.grpc_authority) ss.grpcSettings.authority = p.grpc_authority;
    } else if (p.network === "kcp") {
      ss.kcpSettings = {};
      if (p.kcp_header_type && p.kcp_header_type !== "none") ss.kcpSettings.header = {type: p.kcp_header_type};
      if (p.kcp_seed) ss.kcpSettings.seed = p.kcp_seed;
    }
    if (p.security === "tls") {
      ss.security = "tls";
      ss.tlsSettings = {};
      if (p.sni) ss.tlsSettings.serverName = p.sni;
      if (p.fp) ss.tlsSettings.fingerprint = p.fp;
      if (p.alpn) {
        var alRaw = p.alpn.split(",");
        var al = [];
        for (var j = 0; j < alRaw.length; j++) {
          var tAl = alRaw[j].trim();
          if (tAl) al.push(tAl);
        }
        if (al.length) ss.tlsSettings.alpn = al;
      }
      if (p.allow_insecure) ss.tlsSettings.allowInsecure = true;
      if (p.pinned_sha256) ss.tlsSettings.pinnedPeerCertificateSha256 = p.pinned_sha256;
    } else if (p.security === "reality") {
      ss.security = "reality";
      ss.realitySettings = {serverName: p.sni, fingerprint: p.fp || "chrome", publicKey: p.pbk, shortId: p.sid, spiderX: p.spx};
    }
    ob.streamSettings = ss;
  } else {
    delete ob.streamSettings;
  }
  var dsSock = p.sockopt_domain_strategy || "";
  if (dsSock) {
    if (!ob.streamSettings || typeof ob.streamSettings !== "object") ob.streamSettings = {};
    if (!ob.streamSettings.sockopt || typeof ob.streamSettings.sockopt !== "object") ob.streamSettings.sockopt = {};
    ob.streamSettings.sockopt.domainStrategy = dsSock;
  } else if (ob.streamSettings && ob.streamSettings.sockopt) {
    delete ob.streamSettings.sockopt.domainStrategy;
    var hasSockKeys = false;
    for (var sk in ob.streamSettings.sockopt) {
      if (ob.streamSettings.sockopt.hasOwnProperty(sk)) { hasSockKeys = true; break; }
    }
    if (!hasSockKeys) delete ob.streamSettings.sockopt;
    var hasSSKeys = false;
    for (var ssk in ob.streamSettings) {
      if (ob.streamSettings.hasOwnProperty(ssk)) { hasSSKeys = true; break; }
    }
    if (!hasSSKeys) delete ob.streamSettings;
  }
  document.getElementById("editNodeRawJSON").value = JSON.stringify(ob, null, 2);
}

function setEditTab(tab) {
  showEditModalErr("");
  if (currentEditTab === "visual" && tab === "json") {
    syncVisualToRawJSON();
  } else if (currentEditTab === "json" && tab === "visual") {
    try {
      var parsedOb = JSON.parse(document.getElementById("editNodeRawJSON").value);
      var tmpNode = {
        id: document.getElementById("editNodeId").value,
        name: document.getElementById("editNodeName").value,
        protocol: normProtoUI(parsedOb.protocol),
        outbound: parsedOb
      };
      populateEditModalFromNode(tmpNode, document.getElementById("editNodeIsNew").value === "1");
    } catch(e) {
      showEditModalErr("Invalid Raw Outbound JSON: " + e.message);
      return;
    }
  }
  currentEditTab = tab;
  var names = ["visual", "json", "uri"];
  for (var i = 0; i < names.length; i++) {
    var k = names[i];
    var tEl = document.getElementById("editTab-" + k);
    if (tEl) tEl.className = (k === tab) ? "sub-tab active" : "sub-tab";
  }
  document.getElementById("editPaneVisual").className = (tab === "visual") ? "" : "hidden";
  document.getElementById("editPaneJson").className = (tab === "json") ? "" : "hidden";
  document.getElementById("editPaneUri").className = (tab === "uri") ? "" : "hidden";
}

function formatEditRawJSON() {
  showEditModalErr("");
  try {
    var obj = JSON.parse(document.getElementById("editNodeRawJSON").value);
    document.getElementById("editNodeRawJSON").value = JSON.stringify(obj, null, 2);
  } catch(e) {
    showEditModalErr("Invalid JSON: " + e.message);
  }
}

function loadEditURIIntoForm() {
  var uri = document.getElementById("editNodeURI").value;
  if (!uri || !uri.trim()) {
    showEditModalErr("Paste a share URI first.");
    return;
  }
  showEditModalErr("");
  req("POST", "/api/nodes", {action: "parse_uri", uri: uri}, function(code, text) {
    if (code === 200) {
      var res = JSON.parse(text);
      var parsed = res.node;
      var curId = document.getElementById("editNodeId").value;
      var isNew = (document.getElementById("editNodeIsNew").value === "1");
      parsed.id = curId;
      populateEditModalFromNode(parsed, isNew);
      setEditTab("visual");
      showMsg("URI loaded into editor.");
    } else {
      var err = text;
      try { err = JSON.parse(text).error || text; } catch(e){}
      showEditModalErr("URI parse error: " + err);
    }
  });
}

function generateExportURI() {
  showEditModalErr("");
  var id = document.getElementById("editNodeId").value;
  var payload = {action: "export_uri", id: id};
  if (currentEditTab === "json") {
    try {
      payload.outbound = JSON.parse(document.getElementById("editNodeRawJSON").value);
      payload.name = document.getElementById("editNodeName").value;
      payload.protocol = document.getElementById("editNodeProtocol").value;
      delete payload.id;
    } catch(e) {
      showEditModalErr("Invalid JSON: " + e.message);
      return;
    }
  } else if (!id) {
    syncVisualToRawJSON();
    try {
      payload.outbound = JSON.parse(document.getElementById("editNodeRawJSON").value);
      payload.name = document.getElementById("editNodeName").value;
      payload.protocol = document.getElementById("editNodeProtocol").value;
    } catch(e){}
  }
  req("POST", "/api/nodes", payload, function(code, text) {
    if (code === 200) {
      var res = JSON.parse(text);
      document.getElementById("editNodeExportURI").value = res.uri || "";
    } else {
      var err = text;
      try { err = JSON.parse(text).error || text; } catch(e){}
      showEditModalErr("Export URI error: " + err);
    }
  });
}

function copyExportURI() {
  var inp = document.getElementById("editNodeExportURI");
  if (!inp || !inp.value) {
    generateExportURI();
    return;
  }
  inp.select();
  try { document.execCommand("copy"); showMsg("Share URI copied."); } catch(e) {}
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(inp.value);
    showMsg("Share URI copied.");
  }
}

function openCreateNode() {
  var blank = {
    id: "",
    name: "",
    protocol: "vless",
    address: "",
    port: 443,
    outbound: {
      tag: "proxy",
      protocol: "vless",
      settings: {vnext: [{address: "", port: 443, users: [{id: "", encryption: "none"}]}]},
      streamSettings: {network: "tcp"}
    }
  };
  currentEditTab = "visual";
  populateEditModalFromNode(blank, true);
  setEditTab("visual");
  var m = document.getElementById("nodeEditModal");
  m.className = "modal-bg";
  m.style.display = "flex";
}

function openEditNode(id) {
  var node = null;
  for (var i = 0; i < cachedNodes.length; i++) {
    if (cachedNodes[i].id === id) { node = cachedNodes[i]; break; }
  }
  if (!node) return;
  currentEditTab = "visual";
  populateEditModalFromNode(node, false);
  setEditTab("visual");
  var m = document.getElementById("nodeEditModal");
  m.className = "modal-bg";
  m.style.display = "flex";
}

function closeEditNode() {
  var m = document.getElementById("nodeEditModal");
  m.className = "modal-bg hidden";
  m.style.display = "none";
}

function saveEditNode() {
  showEditModalErr("");
  var id = document.getElementById("editNodeId").value;
  var isNew = (document.getElementById("editNodeIsNew").value === "1");
  var uri = document.getElementById("editNodeURI").value;
  var name = document.getElementById("editNodeName").value;
  var actionName = isNew ? "create" : "edit";
  var body;

  if (uri && uri.trim()) {
    body = {action: actionName, id: id, name: name, uri: uri.trim()};
  } else if (currentEditTab === "json") {
    var parsedOb;
    try {
      parsedOb = JSON.parse(document.getElementById("editNodeRawJSON").value);
    } catch(e) {
      showEditModalErr("Invalid Raw Outbound JSON: " + e.message);
      return;
    }
    body = {action: actionName, id: id, name: name, outbound: parsedOb};
  } else {
    body = collectEditFormPayload(actionName, id);
  }

  showMsg(isNew ? "Creating node..." : "Saving node changes...");
  req("POST", "/api/nodes", body, function(code, text) {
    if (code === 200) {
      closeEditNode();
      showMsg(isNew ? "Node created successfully." : "Node updated successfully.");
      refreshStatus();
    } else {
      var err = text;
      try { err = JSON.parse(text).error || text; } catch(e){}
      showEditModalErr(err);
      showMsg("Error: " + err);
    }
  });
}

function duplicateEditNode() {
  showEditModalErr("");
  var name = document.getElementById("editNodeName").value || "Node";
  var body;
  if (currentEditTab === "json") {
    try {
      body = {action: "create", name: name + " (Copy)", outbound: JSON.parse(document.getElementById("editNodeRawJSON").value)};
    } catch(e) {
      showEditModalErr("Invalid Raw Outbound JSON: " + e.message);
      return;
    }
  } else {
    body = collectEditFormPayload("create", "");
    body.name = name + " (Copy)";
  }
  req("POST", "/api/nodes", body, function(code, text) {
    if (code === 200) {
      closeEditNode();
      showMsg("Duplicated node created.");
      refreshStatus();
    } else {
      var err = text;
      try { err = JSON.parse(text).error || text; } catch(e){}
      showEditModalErr(err);
    }
  });
}

var pollTimer = null;
function schedulePoll() {
  if (pollTimer) clearTimeout(pollTimer);
  var delay = document.hidden ? 30000 : 4000;
  pollTimer = setTimeout(function() {
    refreshStatus();
    if (document.getElementById("p-logs").className === "card") { loadLogs(); }
    schedulePoll();
  }, delay);
}
document.addEventListener("visibilitychange", function() {
  if (!document.hidden) {
    refreshStatus();
    if (document.getElementById("p-logs").className === "card") { loadLogs(); }
  }
  schedulePoll();
});
window.addEventListener("keydown", function(e) {
  if (e.key === "Escape") { closeEditNode(); }
});

refreshStatus();
schedulePoll();
</script>
</body>
</html>
`

