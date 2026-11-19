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
	AppVersion    = "v1.2.5"

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
	RemoteDNS     string `json:"remote_dns"`     // e.g. "tcp://1.1.1.1", "tcp://8.8.8.8", "https://dns.google/dns-query"
	DirectDNS     string `json:"direct_dns"`     // e.g. "223.5.5.5", "10.202.10.202", "77.88.8.8"
	QueryStrategy string `json:"query_strategy"` // "UseIPv4", "UseIP", "UseIPv6"
}

type GeoConfig struct {
	BypassIran    *bool    `json:"bypass_iran,omitempty"`
	BypassCN      *bool    `json:"bypass_cn,omitempty"`
	BlockAds      *bool    `json:"block_ads,omitempty"`
	DirectDomains []string `json:"direct_domains"`
	DirectIPs     []string `json:"direct_ips"`
	ProxyDomains  []string `json:"proxy_domains"`
	ProxyIPs      []string `json:"proxy_ips"`
	BlockDomains  []string `json:"block_domains"`
	BlockIPs      []string `json:"block_ips"`
	GeoIPURL      string   `json:"geoip_url"`
	GeoSiteURL    string   `json:"geosite_url"`
	LastGeoUpdate string   `json:"last_geo_update"`
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
	ProxyMode       string        `json:"proxy_mode"`        // "rule", "global", "direct"
	ActiveNode      string        `json:"active_node"`
	SubURL          string        `json:"sub_url"`
	SubInsecure     bool          `json:"sub_insecure"`      // Ignore SSL/TLS cert errors
	AutoUpdateHours int           `json:"auto_update_hours"` // 0 = disabled
	LastSubUpdate   string        `json:"last_sub_update"`
	AppFilterMode   string        `json:"app_filter_mode"` // "bypass" or "proxy"
	SelectedUIDs    []int         `json:"selected_uids"`
	LocalhostProxy  bool          `json:"localhost_proxy"`   // Proxy local device (default true)
	DNS             DNSConfig     `json:"dns"`
	Geo             GeoConfig     `json:"geo"`
	Nodes           []NodeProfile `json:"nodes"`
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
	logSink      = &CappedLogWriter{path: LogFile}
	stateMu      sync.Mutex
	engineMu     sync.Mutex
	engineActive bool
	useTproxy    bool
	xrayStopCh   chan struct{}
	xrayDoneCh   chan struct{}
	portHopRe    = regexp.MustCompile(`:(\d+)[-,][0-9,-]*([/?#].*|$)`)
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
		}
		if servers, ok := settings["servers"].([]interface{}); ok && len(servers) > 0 {
			if sObj, ok := servers[0].(map[string]interface{}); ok {
				if newAddr != "" {
					sObj["address"] = newAddr
				}
				if newPort > 0 {
					sObj["port"] = newPort
				}
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
	}

	if st.DNS.RemoteDNS == "" {
		st.DNS.RemoteDNS = "tcp://1.1.1.1"
	}
	if st.DNS.DirectDNS == "" {
		st.DNS.DirectDNS = "1.1.1.1"
	}
	if st.DNS.QueryStrategy == "" {
		st.DNS.QueryStrategy = "UseIPv4"
	}

	boolTrue := true
	if st.Geo.BypassIran == nil {
		st.Geo.BypassIran = &boolTrue
	}
	if st.Geo.BypassCN == nil {
		st.Geo.BypassCN = &boolTrue
	}
	if st.Geo.BlockAds == nil {
		st.Geo.BlockAds = &boolTrue
	}
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
	queryStrategy := strings.TrimSpace(st.DNS.QueryStrategy)
	if queryStrategy == "" {
		queryStrategy = "UseIPv4"
	}

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
	var subHost string
	if st.SubURL != "" {
		if subU, err := url.Parse(st.SubURL); err == nil && subU.Hostname() != "" {
			subHost = subU.Hostname()
			if net.ParseIP(subHost) == nil {
				directDomains = append(directDomains, subHost)
			}
		}
	}

	var dnsServers []interface{}
	switch st.ProxyMode {
	case "rule":
		if defaultOutbound == "direct" {
			dnsServers = []interface{}{
				directDNS,
				"1.1.1.1",
				"localhost",
			}
		} else {
			dnsServers = []interface{}{
				map[string]interface{}{
					"address":      directDNS,
					"domains":      directDomains,
					"skipFallback": false,
				},
				map[string]interface{}{
					"address": remoteDNS,
				},
				directDNS,
				"localhost",
			}
		}
	case "global":
		if defaultOutbound == "direct" {
			dnsServers = []interface{}{
				directDNS,
				"1.1.1.1",
				"localhost",
			}
		} else {
			dnsServers = []interface{}{
				map[string]interface{}{
					"address":      directDNS,
					"domains":      directDomains,
					"skipFallback": false,
				},
				map[string]interface{}{
					"address": remoteDNS,
				},
				"localhost",
			}
		}
	case "direct":
		dnsServers = []interface{}{
			directDNS,
			"1.1.1.1",
			"localhost",
		}
	}
	cfg["dns"] = map[string]interface{}{
		"servers":       dnsServers,
		"queryStrategy": queryStrategy,
	}

	if inbounds, ok := cfg["inbounds"].([]interface{}); ok {
		hasSocks := false
		for _, item := range inbounds {
			inb, ok := item.(map[string]interface{})
			if !ok {
				continue
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

	if st.ActiveNode != "" {
		for _, n := range st.Nodes {
			if n.ID == st.ActiveNode && n.Outbound != nil {
				outCopy := map[string]interface{}{}
				for k, v := range n.Outbound {
					outCopy[k] = v
				}
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
						if sockopt["domainStrategy"] == nil || sockopt["domainStrategy"] == "" {
							sockopt["domainStrategy"] = queryStrategy
						}
					}
				}
			}
		}
	}

	var rules []interface{}
	// 1. Intercept all inbound DNS to Xray internal DNS (dns-in dedicated port 1053, and port 53 for tproxy/socks)
	rules = append(rules,
		map[string]interface{}{
			"type":        "field",
			"inboundTag":  []string{"dns-in"},
			"outboundTag": "dns-out",
		},
		map[string]interface{}{
			"type":        "field",
			"inboundTag":  []string{"tproxy-in", "socks-in"},
			"port":        "53",
			"outboundTag": "dns-out",
		},
	)

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

	// 3. Active node and sub URL domain / IP must go to direct outbound (prevent proxy loop/deadlock)
	if activeNodeDomain != "" {
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"domain":      []string{activeNodeDomain},
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
	routing["domainStrategy"] = "IPIfNonMatch"
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

func setupTproxyIptables() error {
	st := loadState()
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
		_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_PRE",
			"-p", proto, "--dport", "53",
			"-j", "TPROXY", "--on-port", tproxyTarget, "--on-ip", "127.0.0.1", "--tproxy-mark", markSpec)
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
			_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_OUT",
				"-p", proto, "--dport", "53",
				"-j", "MARK", "--set-xmark", markSpec)
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

	// Reject DNS-over-TLS (port 853) so Android falls back immediately to port 53 DNS intercepted by Xray
	_ = runCmd("iptables", "-I", "FORWARD", "1", "-p", "tcp", "--dport", "853", "-j", "REJECT", "--reject-with", "tcp-reset")
	if st.LocalhostProxy {
		_ = runCmd("iptables", "-I", "OUTPUT", "1",
			"-m", "owner", "!", "--gid-owner", strconv.Itoa(XrayGID),
			"-m", "mark", "!", "--mark", BypassHex+"/"+BypassHex,
			"-p", "tcp", "--dport", "853", "-j", "REJECT", "--reject-with", "tcp-reset")
	}

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
		_ = runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_PRE",
			"-p", proto, "--dport", "53", "-j", "REDIRECT", "--to-ports", "1053")
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

	// Reject DNS-over-TLS (port 853) so Android falls back immediately to port 53 DNS intercepted by Xray
	_ = runCmd("iptables", "-I", "FORWARD", "1", "-p", "tcp", "--dport", "853", "-j", "REJECT", "--reject-with", "tcp-reset")
	if st.LocalhostProxy {
		_ = runCmd("iptables", "-I", "OUTPUT", "1",
			"-m", "owner", "!", "--gid-owner", strconv.Itoa(XrayGID),
			"-m", "mark", "!", "--mark", BypassHex+"/"+BypassHex,
			"-p", "tcp", "--dport", "853", "-j", "REJECT", "--reject-with", "tcp-reset")
	}

	if err := runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_PRE",
		"-p", "tcp", "-j", "REDIRECT", "--to-ports", redirPort); err != nil {
		return err
	}

	if !st.LocalhostProxy {
		_ = runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_OUT", "-j", "RETURN")
	} else {
		for _, proto := range []string{"udp", "tcp"} {
			_ = runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_OUT",
				"-p", proto, "--dport", "53", "-j", "REDIRECT", "--to-ports", "1053")
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
		tlsType, _ := v["tls"].(string)
		host, _ := v["host"].(string)
		path, _ := v["path"].(string)
		sni, _ := v["sni"].(string)
		port := 443
		switch p := v["port"].(type) {
		case float64:
			port = int(p)
		case string:
			if parsed, err := strconv.Atoi(p); err == nil {
				port = parsed
			}
		}
		if ps == "" {
			ps = fmt.Sprintf("vmess-%s:%d", addr, port)
		}
		if netType == "" {
			netType = "tcp"
		}
		ss := map[string]interface{}{"network": netType}
		if tlsType == "tls" {
			ss["security"] = "tls"
			if sni == "" {
				sni = host
			}
			if sni != "" {
				ss["tlsSettings"] = map[string]interface{}{"serverName": sni}
			}
		}
		if netType == "ws" {
			ws := map[string]interface{}{"path": path}
			if host != "" {
				ws["headers"] = map[string]interface{}{"Host": host}
			}
			ss["wsSettings"] = ws
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
							map[string]interface{}{"id": uuid, "alterId": 0, "security": "auto"},
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

	netType := q.Get("type")
	if netType == "" {
		netType = "tcp"
	}
	security := q.Get("security")
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("host")
	}
	fp := q.Get("fp")
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
	case "grpc":
		ss["grpcSettings"] = map[string]interface{}{
			"serviceName": q.Get("serviceName"),
		}
	}

	var settings map[string]interface{}
	if proto == "vless" {
		userObj := map[string]interface{}{
			"id":         userID,
			"encryption": "none",
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

func startWebDashboard() {
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
			"running":           active,
			"daemon_pid":        daemonPID,
			"net_mode":          netMode,
			"proxy_mode":        st.ProxyMode,
			"active_node":       st.ActiveNode,
			"sub_url":           st.SubURL,
			"sub_insecure":      st.SubInsecure,
			"auto_update_hours": st.AutoUpdateHours,
			"last_sub_update":   st.LastSubUpdate,
			"app_filter_mode":   st.AppFilterMode,
			"selected_uids":     st.SelectedUIDs,
			"localhost_proxy":   st.LocalhostProxy,
			"dns":               st.DNS,
			"geo":               st.Geo,
			"module_version":    getModuleVersion(),
			"xray_version":      getXrayVersion(),
			"nodes":             st.Nodes,
			"battery_pct":       batPct,
			"battery_status":    batStatus,
			"module_pid":        daemonPID,
			"module_cpu":        modCPU,
			"module_ram":        modRAMBytes,
			"module_ram_str":    modRAMStr,
			"xray_pid":          currentXrayPID,
			"xray_cpu":          xrayCPU,
			"xray_ram":          xrayRAMBytes,
			"xray_ram_str":      xrayRAMStr,
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
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			st := loadState()
			if strings.TrimSpace(req.RemoteDNS) != "" {
				st.DNS.RemoteDNS = strings.TrimSpace(req.RemoteDNS)
			}
			if strings.TrimSpace(req.DirectDNS) != "" {
				st.DNS.DirectDNS = strings.TrimSpace(req.DirectDNS)
			}
			if strings.TrimSpace(req.QueryStrategy) != "" {
				st.DNS.QueryStrategy = strings.TrimSpace(req.QueryStrategy)
			}
			_ = saveState(st)
			log.Printf("[passwall-droid] updated DNS settings: remote=%s direct=%s strategy=%s",
				st.DNS.RemoteDNS, st.DNS.DirectDNS, st.DNS.QueryStrategy)
			_ = restartProxyEngine()
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
				BypassIran    *bool    `json:"bypass_iran"`
				BypassCN      *bool    `json:"bypass_cn"`
				BlockAds      *bool    `json:"block_ads"`
				DirectDomains []string `json:"direct_domains"`
				DirectIPs     []string `json:"direct_ips"`
				ProxyDomains  []string `json:"proxy_domains"`
				ProxyIPs      []string `json:"proxy_ips"`
				BlockDomains  []string `json:"block_domains"`
				BlockIPs      []string `json:"block_ips"`
				GeoIPURL      string   `json:"geoip_url"`
				GeoSiteURL    string   `json:"geosite_url"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body: " + err.Error()})
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
			_ = saveState(st)
			log.Printf("[passwall-droid] updated geo routing rules (bypass_iran=%v bypass_cn=%v block_ads=%v)",
				st.Geo.IsBypassIran(), st.Geo.IsBypassCN(), st.Geo.IsBlockAds())

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
		var req struct {
			Action  string `json:"action"` // "import", "select", "delete", "edit", "update"
			URI     string `json:"uri"`
			ID      string `json:"id"`
			Name    string `json:"name"`
			Address string `json:"address"`
			Port    int    `json:"port"`
			SNI     string `json:"sni"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch req.Action {
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
				_ = restartProxyEngine()
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

	case "start":
		if pid, ok := isRunning(); ok {
			fmt.Printf("Already running (PID %d)\n", pid)
			return
		}
	default:
		fmt.Printf("Usage: %s [start|stop|status|reset-config|update-geo]\n", filepath.Base(os.Args[0]))
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
.hidden{display:none}
.modal-bg{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.75);display:flex;align-items:center;justify-content:center;z-index:999;padding:12px}
.modal-card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px;width:100%;max-width:440px;box-sizing:border-box}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin-bottom:10px}
.stat-box{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:8px}
.stat-val{font-size:13px;font-weight:700;color:#38bdf8;margin-top:2px}
.stat-lbl{font-size:11px;color:#94a3b8}
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

  <div class="header">
    <div class="title" style="font-size:13px">Saved Nodes</div>
    <div class="row">
      <button class="btn-amber btn-sm" onclick="pingAll(false)">Ping All</button>
      <button class="btn-green btn-sm" onclick="pingAll(true)">Fastest</button>
    </div>
  </div>
  <div id="nodeList"></div>
</div>

<div id="p-dns" class="card hidden">
  <div class="title" style="font-size:13px;margin-bottom:6px">DNS Configuration</div>
  <div class="meta" style="margin-bottom:10px">Internal Xray DNS resolver for phone &amp; tethered devices. Direct DNS resolves proxy domains and domestic traffic; Remote DNS handles proxied/blocked sites.</div>

  <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:#cbd5e1">Remote DNS (Proxied / Foreign)</div>
  <input id="dnsRemoteInput" type="text" placeholder="tcp://1.1.1.1">
  <div class="row" style="margin-bottom:10px;flex-wrap:wrap;gap:4px">
    <button class="btn-sm" onclick="setDNSField('dnsRemoteInput','tcp://1.1.1.1')">1.1.1.1 (TCP)</button>
    <button class="btn-sm" onclick="setDNSField('dnsRemoteInput','1.1.1.1')">1.1.1.1 (UDP)</button>
    <button class="btn-sm" onclick="setDNSField('dnsRemoteInput','tcp://8.8.8.8')">8.8.8.8 (TCP)</button>
    <button class="btn-sm" onclick="setDNSField('dnsRemoteInput','https://1.1.1.1/dns-query')">Cloudflare DoH</button>
    <button class="btn-sm" onclick="setDNSField('dnsRemoteInput','https://dns.google/dns-query')">Google DoH</button>
  </div>

  <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:#cbd5e1">Direct DNS (Domestic / Node Resolution)</div>
  <input id="dnsDirectInput" type="text" placeholder="1.1.1.1">
  <div class="row" style="margin-bottom:10px;flex-wrap:wrap;gap:4px">
    <button class="btn-sm" onclick="setDNSField('dnsDirectInput','1.1.1.1')">1.1.1.1 (Cloudflare UDP)</button>
    <button class="btn-sm" onclick="setDNSField('dnsDirectInput','localhost')">localhost (System DNS)</button>
    <button class="btn-sm" onclick="setDNSField('dnsDirectInput','10.202.10.202')">Shecan (10.202.10.202)</button>
    <button class="btn-sm" onclick="setDNSField('dnsDirectInput','77.88.8.8')">Yandex (77.88.8.8)</button>
    <button class="btn-sm" onclick="setDNSField('dnsDirectInput','223.5.5.5')">AliDNS (223.5.5.5)</button>
  </div>

  <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:#cbd5e1">Query Strategy</div>
  <select id="dnsStrategySel" style="margin-bottom:12px">
    <option value="UseIPv4">UseIPv4 (Recommended - Prevents IPv6 timeouts)</option>
    <option value="UseIP">UseIP (Both IPv4 and IPv6)</option>
    <option value="UseIPv6">UseIPv6 (IPv6 Preferred)</option>
  </select>

  <button class="btn-green" style="width:100%" onclick="saveDNS()">Save &amp; Apply DNS</button>
</div>

<div id="p-geo" class="card hidden">
  <div class="title" style="font-size:13px;margin-bottom:6px">Geo Routing &amp; Rules Settings</div>
  <div class="meta" style="margin-bottom:10px">Manage Geosite/GeoIP rule policies for Rule Mode. Bypass domestic services, block ads and trackers, configure custom routing domains and IP lists, and update Geo databases.</div>

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

<div id="nodeEditModal" class="modal-bg hidden">
  <div class="modal-card">
    <div class="header" style="margin-bottom:10px">
      <div class="title" style="font-size:14px">Edit Proxy Node</div>
      <button class="btn-sm" onclick="closeEditNode()">✕</button>
    </div>
    <input type="hidden" id="editNodeId">
    <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:#cbd5e1">Node Name</div>
    <input id="editNodeName" type="text" placeholder="Node Alias">
    <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:#cbd5e1">Server Address</div>
    <input id="editNodeAddress" type="text" placeholder="example.com or 1.2.3.4">
    <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:#cbd5e1">Port</div>
    <input id="editNodePort" type="number" min="1" max="65535" placeholder="443">
    <div style="font-size:12px;font-weight:600;margin-bottom:4px;color:#cbd5e1">TLS / Reality SNI (Optional)</div>
    <input id="editNodeSNI" type="text" placeholder="serverName / SNI (optional)">
    <div style="font-size:12px;font-weight:600;margin:6px 0 4px;color:#cbd5e1">Replace from Share URI (Optional)</div>
    <input id="editNodeURI" type="text" placeholder="vless://... or trojan://... (optional)">
    <div class="row" style="margin-top:10px">
      <button class="btn-green" style="flex:1" onclick="saveEditNode()">Save Changes</button>
      <button style="flex:1" onclick="closeEditNode()">Cancel</button>
    </div>
  </div>
</div>

<script>
var cachedApps = [];
var selectedUIDMap = {};
var subInitialized = false;
var dnsInitialized = false;
var checkingConn = false;
var connCheckedOnce = false;

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

function loadDNS() {
  req("GET", "/api/dns", null, function(code, text) {
    if (code !== 200) { return; }
    var d = JSON.parse(text);
    document.getElementById("dnsRemoteInput").value = d.remote_dns || "tcp://1.1.1.1";
    document.getElementById("dnsDirectInput").value = d.direct_dns || "1.1.1.1";
    document.getElementById("dnsStrategySel").value = d.query_strategy || "UseIPv4";
    dnsInitialized = true;
  });
}

function saveDNS() {
  var r = document.getElementById("dnsRemoteInput").value;
  var d = document.getElementById("dnsDirectInput").value;
  var s = document.getElementById("dnsStrategySel").value;
  showMsg("Applying DNS settings and reloading engine...");
  req("POST", "/api/dns", {remote_dns: r, direct_dns: d, query_strategy: s}, function(code, text) {
    if (code === 200) {
      showMsg("DNS updated and proxy engine restarted.");
      refreshStatus();
    } else {
      var err = JSON.parse(text);
      showMsg("DNS error: " + (err.error || text));
    }
  });
}

function loadGeo() {
  req("GET", "/api/geo", null, function(code, text) {
    if (code !== 200) { return; }
    var d = JSON.parse(text);
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
      document.getElementById("dnsRemoteInput").value = d.dns.remote_dns || "tcp://1.1.1.1";
      document.getElementById("dnsDirectInput").value = d.dns.direct_dns || "1.1.1.1";
      document.getElementById("dnsStrategySel").value = d.dns.query_strategy || "UseIPv4";
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
      '<button class="btn-sm" onclick="pingOne(\'' + n.id + '\')">Ping</button>' +
      '<button class="btn-blue btn-sm" onclick="openEditNode(\'' + esc(n.id) + '\')">Edit</button>' +
      (sel ? '' : '<button class="btn-blue btn-sm" onclick="nodeAct(\'select\',\'' + n.id + '\')">Use</button>') +
      '<button class="btn-red btn-sm" onclick="nodeAct(\'delete\',\'' + n.id + '\')">X</button>' +
      '</div></div>';
  }
  box.innerHTML = html;
}

function esc(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
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

function openEditNode(id) {
  var node = null;
  for (var i = 0; i < cachedNodes.length; i++) {
    if (cachedNodes[i].id === id) { node = cachedNodes[i]; break; }
  }
  if (!node) return;
  document.getElementById("editNodeId").value = node.id;
  document.getElementById("editNodeName").value = node.name || "";
  document.getElementById("editNodeAddress").value = node.address || "";
  document.getElementById("editNodePort").value = node.port || 443;
  document.getElementById("editNodeURI").value = "";

  var sni = "";
  if (node.outbound && node.outbound.streamSettings) {
    var ss = node.outbound.streamSettings;
    if (ss.tlsSettings && ss.tlsSettings.serverName) {
      sni = ss.tlsSettings.serverName;
    } else if (ss.realitySettings && ss.realitySettings.serverName) {
      sni = ss.realitySettings.serverName;
    }
  }
  document.getElementById("editNodeSNI").value = sni;
  document.getElementById("nodeEditModal").className = "modal-bg";
}

function closeEditNode() {
  document.getElementById("nodeEditModal").className = "modal-bg hidden";
}

function saveEditNode() {
  var id = document.getElementById("editNodeId").value;
  var name = document.getElementById("editNodeName").value;
  var addr = document.getElementById("editNodeAddress").value;
  var port = parseInt(document.getElementById("editNodePort").value, 10) || 0;
  var sni = document.getElementById("editNodeSNI").value;
  var uri = document.getElementById("editNodeURI").value;

  showMsg("Saving node changes...");
  req("POST", "/api/nodes", {
    action: "edit",
    id: id,
    name: name,
    address: addr,
    port: port,
    sni: sni,
    uri: uri
  }, function(code, text) {
    if (code === 200) {
      closeEditNode();
      showMsg("Node updated successfully.");
      refreshStatus();
    } else {
      var err = text;
      try { err = JSON.parse(text).error || text; } catch(e){}
      showMsg("Error: " + err);
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

refreshStatus();
schedulePoll();
</script>
</body>
</html>
`

