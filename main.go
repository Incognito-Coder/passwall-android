package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
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

const (
	BaseDir       = "/data/adb/modules/passwall-android"
	XrayBin       = BaseDir + "/bin/xray"
	BaseConfig    = BaseDir + "/config/config.json"
	StateFile     = BaseDir + "/config/state.json"
	RuntimeConfig = "/dev/passwall-xray.json"
	AssetDir      = BaseDir + "/config"
	LogFile       = "/data/adb/passwall-android.log"
	PidFile       = "/dev/passwall-droid.pid"
	PackagesFile  = "/data/system/packages.list"
	WebListenAddr = "127.0.0.1:9090"

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

type PanelState struct {
	ProxyMode       string        `json:"proxy_mode"`        // "rule", "global", "direct"
	ActiveNode      string        `json:"active_node"`
	SubURL          string        `json:"sub_url"`
	SubInsecure     bool          `json:"sub_insecure"`      // Ignore SSL/TLS cert errors
	AutoUpdateHours int           `json:"auto_update_hours"` // 0 = disabled
	LastSubUpdate   string        `json:"last_sub_update"`
	AppFilterMode   string        `json:"app_filter_mode"` // "bypass" or "proxy"
	SelectedUIDs    []int         `json:"selected_uids"`
	Nodes           []NodeProfile `json:"nodes"`
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
	_ = os.WriteFile(path, []byte(val), 0644)
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

func loadState() PanelState {
	stateMu.Lock()
	defer stateMu.Unlock()

	st := PanelState{
		ProxyMode:     "rule",
		AppFilterMode: "bypass",
		SelectedUIDs:  []int{},
		Nodes:         []NodeProfile{},
	}
	if data, err := os.ReadFile(StateFile); err == nil {
		_ = json.Unmarshal(data, &st)
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
	return st
}

func saveState(st PanelState) error {
	stateMu.Lock()
	defer stateMu.Unlock()

	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(StateFile, data, 0644)
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

func prepareRuntimeConfig(tproxySupported bool) error {
	raw, err := os.ReadFile(BaseConfig)
	if err != nil {
		return err
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("invalid base config.json: %v", err)
	}

	st := loadState()

	if inbounds, ok := cfg["inbounds"].([]interface{}); ok {
		for _, item := range inbounds {
			inb, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if tag, _ := inb["tag"].(string); tag == "tproxy-in" {
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

	defaultOutbound := "proxy"
	if st.ProxyMode == "direct" {
		defaultOutbound = "direct"
	}

	var rules []interface{}
	rules = append(rules, map[string]interface{}{
		"type":        "field",
		"inboundTag":  []string{"tproxy-in"},
		"port":        53,
		"outboundTag": "dns-out",
	})

	if st.ProxyMode == "rule" {
		rules = append(rules,
			map[string]interface{}{
				"type":        "field",
				"domain":      []string{"geosite:category-ads-all"},
				"outboundTag": "block",
			},
			map[string]interface{}{
				"type":        "field",
				"ip":          []string{"geoip:private", "geoip:ir"},
				"outboundTag": "direct",
			},
			map[string]interface{}{
				"type":        "field",
				"domain":      []string{"domain:ir", "geosite:ir"},
				"outboundTag": "direct",
			},
		)
	} else {
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"ip":          []string{"geoip:private"},
			"outboundTag": "direct",
		})
	}

	rules = append(rules, map[string]interface{}{
		"type":        "field",
		"network":     "tcp,udp",
		"outboundTag": defaultOutbound,
	})

	routing, _ := cfg["routing"].(map[string]interface{})
	if routing == nil {
		routing = map[string]interface{}{"domainStrategy": "IPIfNonMatch"}
		cfg["routing"] = routing
	}
	routing["rules"] = rules

	finalBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(RuntimeConfig, finalBytes, 0644)
}

func configureKernelAndTether() {
	writeSysctl("/proc/sys/net/ipv4/ip_forward", "1")
	writeSysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0")
	writeSysctl("/proc/sys/net/ipv4/conf/default/rp_filter", "0")

	if DisableIPv6 {
		writeSysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1")
		writeSysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1")
	} else {
		writeSysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1")
	}

	runCmdIgnoreErr("settings", "put", "global", "tether_offload_disabled", "1")
	runCmdIgnoreErr("ndc", "tether", "offload", "set", "false")
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

	_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_OUT",
		"-m", "owner", "--gid-owner", strconv.Itoa(XrayGID), "-j", "RETURN")
	_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_OUT",
		"-m", "mark", "--mark", BypassHex+"/"+BypassHex, "-j", "RETURN")

	for _, proto := range []string{"tcp", "udp"} {
		_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_PRE",
			"-p", proto, "--dport", "53",
			"-j", "TPROXY", "--on-port", tproxyTarget, "--on-ip", "127.0.0.1", "--tproxy-mark", markSpec)

		_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_OUT",
			"-p", proto, "--dport", "53",
			"-j", "MARK", "--set-xmark", markSpec)
	}

	for _, cidr := range bypassCIDRsV4 {
		_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_PRE", "-d", cidr, "-j", "RETURN")
		_ = runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_OUT", "-d", cidr, "-j", "RETURN")
	}

	if BlockQUIC {
		_ = runCmd("iptables", "-I", "FORWARD", "-p", "udp", "--dport", "443", "-j", "DROP")
		_ = runCmd("iptables", "-I", "OUTPUT", "-m", "owner", "!", "--gid-owner", strconv.Itoa(XrayGID),
			"-p", "udp", "--dport", "443", "-j", "REJECT")
	}

	for _, proto := range []string{"tcp", "udp"} {
		if err := runCmd("iptables", "-t", "mangle", "-A", "PASSWALL_PRE",
			"-p", proto,
			"-j", "TPROXY", "--on-port", tproxyTarget, "--on-ip", "127.0.0.1", "--tproxy-mark", markSpec); err != nil {
			return err
		}
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

	if err := runCmd("iptables", "-t", "mangle", "-A", "PREROUTING", "-j", "PASSWALL_PRE"); err != nil {
		return err
	}
	return runCmd("iptables", "-t", "mangle", "-A", "OUTPUT", "-j", "PASSWALL_OUT")
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
			"-p", proto, "--dport", "53", "-j", "REDIRECT", "--to-ports", redirPort)
		_ = runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_OUT",
			"-p", proto, "--dport", "53", "-j", "REDIRECT", "--to-ports", redirPort)
	}

	for _, cidr := range bypassCIDRsV4 {
		_ = runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_PRE", "-d", cidr, "-j", "RETURN")
		_ = runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_OUT", "-d", cidr, "-j", "RETURN")
	}

	if BlockQUIC {
		_ = runCmd("iptables", "-I", "FORWARD", "-p", "udp", "--dport", "443", "-j", "DROP")
		_ = runCmd("iptables", "-I", "OUTPUT", "-m", "owner", "!", "--gid-owner", strconv.Itoa(XrayGID),
			"-p", "udp", "--dport", "443", "-j", "REJECT")
	}

	if err := runCmd("iptables", "-t", "nat", "-A", "PASSWALL_NAT_PRE",
		"-p", "tcp", "-j", "REDIRECT", "--to-ports", redirPort); err != nil {
		return err
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

	if err := runCmd("iptables", "-t", "nat", "-A", "PREROUTING", "-j", "PASSWALL_NAT_PRE"); err != nil {
		return err
	}
	return runCmd("iptables", "-t", "nat", "-A", "OUTPUT", "-j", "PASSWALL_NAT_OUT")
}

func cleanupIptables() {
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

	runCmdIgnoreErr("iptables", "-D", "FORWARD", "-p", "udp", "--dport", "443", "-j", "DROP")
	runCmdIgnoreErr("iptables", "-D", "OUTPUT", "-m", "owner", "!", "--gid-owner", strconv.Itoa(XrayGID),
		"-p", "udp", "--dport", "443", "-j", "REJECT")
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
		cmd := exec.Command(XrayBin, "run", "-c", RuntimeConfig)
		cmd.Env = append(os.Environ(),
			"XRAY_LOCATION_ASSET="+AssetDir,
			"GOGC=40",
			"GOMEMLIMIT=48MiB",
		)
		cmd.Stdout = logSink
		cmd.Stderr = logSink

		configureProcessCredentials(cmd, XrayGID)

		if err := cmd.Start(); err != nil {
			log.Printf("[passwall-droid] xray start error: %v; retrying in 3s", err)
			time.Sleep(3 * time.Second)
			continue
		}

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
			return
		case err := <-waitCh:
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
	cleanupIptables()
	cleanupPolicyRouting()
	engineActive = false
	log.Println("[passwall-droid] proxy engine stopped")
}

func restartProxyEngine() error {
	stopProxyEngine()
	return startProxyEngine()
}

func watchdogLoop() {
	ticker := time.NewTicker(15 * time.Second)
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
		if pin := q.Get("pinSHA256"); pin != "" {
			tlsSettings["pinnedPeerCertificateSha256"] = pin
		}

		hysteriaSettings := map[string]interface{}{
			"version": 2,
			"auth":    auth,
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
			ss["finalmask"] = map[string]interface{}{
				"udp": []interface{}{
					map[string]interface{}{
						"type": obfsType,
						"settings": map[string]interface{}{
							"password": obfsPass,
						},
					},
				},
			}
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

func measureNodeLatency(n NodeProfile) int {
	target := net.JoinHostPort(n.Address, strconv.Itoa(n.Port))
	dialer := directDialer(4 * time.Second)

	start := time.Now()
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		if n.Protocol == "hysteria2" || n.Protocol == "hysteria" {
			uConn, uErr := dialer.Dial("udp", target)
			if uErr != nil {
				return -1
			}
			_ = uConn.Close()
			ms := int(time.Since(start).Milliseconds())
			if ms < 1 {
				ms = 1
			}
			return ms
		}
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
		resp := map[string]interface{}{
			"running":           active,
			"daemon_pid":        os.Getpid(),
			"net_mode":          netMode,
			"proxy_mode":        st.ProxyMode,
			"active_node":       st.ActiveNode,
			"sub_url":           st.SubURL,
			"auto_update_hours": st.AutoUpdateHours,
			"last_sub_update":   st.LastSubUpdate,
			"app_filter_mode":   st.AppFilterMode,
			"selected_uids":     st.SelectedUIDs,
			"nodes":             st.Nodes,
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
		_ = restartProxyEngine()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
			Action string `json:"action"` // "import", "select", "delete"
			URI    string `json:"uri"`
			ID     string `json:"id"`
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
				RawJSON string `json:"raw_json"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			var testObj interface{}
			if err := json.Unmarshal([]byte(req.RawJSON), &testObj); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
				return
			}
			var pretty bytes.Buffer
			_ = json.Indent(&pretty, []byte(req.RawJSON), "", "  ")
			if err := os.WriteFile(BaseConfig, pretty.Bytes(), 0644); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
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

	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			_ = os.WriteFile(LogFile, []byte(""), 0644)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
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
			fmt.Printf("Running (PID %d, Mode: %s, WebUI: http://%s)\n", pid, mode, WebListenAddr)
			os.Exit(0)
		}
		fmt.Println("Stopped")
		os.Exit(1)

	case "start":
		if pid, ok := isRunning(); ok {
			fmt.Printf("Already running (PID %d)\n", pid)
			return
		}
	default:
		fmt.Printf("Usage: %s [start|stop|status]\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	log.SetOutput(logSink)
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
body{font-family:-apple-system,Roboto,sans-serif;background:#0f172a;color:#e2e8f0;padding:10px;line-height:1.4}
.card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:12px;margin-bottom:10px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.title{font-size:16px;font-weight:700;color:#f8fafc}
.badge{padding:3px 9px;border-radius:12px;font-size:11px;font-weight:700}
.on{background:#065f46;color:#6ee7b7}
.off{background:#7f1d1d;color:#fca5a5}
.meta{font-size:12px;color:#94a3b8;margin-bottom:8px}
.row{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
button{border:none;border-radius:7px;padding:8px 11px;font-size:12px;font-weight:600;cursor:pointer;color:#fff;background:#334155}
button:active{opacity:.8}
.btn-green{background:#059669}
.btn-red{background:#dc2626}
.btn-blue{background:#2563eb}
.btn-amber{background:#d97706}
.btn-active{background:#0284c7;box-shadow:0 0 0 2px #38bdf8}
.tabs{display:flex;gap:5px;margin-bottom:10px}
.tab{flex:1;text-align:center;padding:8px 4px;background:#1e293b;border:1px solid #334155;border-radius:8px;font-size:12px;font-weight:600;color:#94a3b8}
.tab.active{background:#2563eb;color:#fff;border-color:#2563eb}
input,select,textarea{width:100%;background:#0f172a;border:1px solid #334155;border-radius:7px;color:#f8fafc;padding:8px;font-size:13px;margin-bottom:8px}
textarea{font-family:monospace;font-size:12px;min-height:220px}
.node-item{display:flex;justify-content:space-between;align-items:center;background:#0f172a;border:1px solid #334155;border-radius:7px;padding:8px;margin-bottom:6px}
.node-item.selected{border-color:#38bdf8;background:#0c4a6e}
.node-info{font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:58%}
.node-sub{font-size:11px;color:#94a3b8}
.lat{font-size:11px;font-weight:700;padding:2px 6px;border-radius:5px;background:#1e293b}
.lat-ok{color:#34d399}
.lat-slow{color:#fbbf24}
.lat-err{color:#f87171}
.app-list{max-height:300px;overflow-y:auto;border:1px solid #334155;border-radius:7px;background:#0f172a;padding:6px;margin-bottom:8px}
.app-row{display:flex;justify-content:space-between;align-items:center;padding:6px 4px;border-bottom:1px solid #1e293b;font-size:12px}
.app-row input[type=checkbox]{width:18px;height:18px;margin:0}
pre{background:#090d16;border:1px solid #1e293b;border-radius:7px;padding:10px;font-size:11px;color:#cbd5e1;overflow-x:auto;max-height:320px;white-space:pre-wrap;word-break:break-all}
.msg{font-size:12px;color:#38bdf8;margin-top:6px;min-height:16px}
.hidden{display:none}
</style>
</head>
<body>

<div class="card">
  <div class="header">
    <div class="title">Passwall Android</div>
    <span id="statusBadge" class="badge off">LOADING</span>
  </div>
  <div class="meta" id="metaLine">Netfilter: -- | PID: --</div>
  <div class="row">
    <button class="btn-green" onclick="ctrl('start')">Start</button>
    <button class="btn-blue" onclick="ctrl('restart')">Restart</button>
    <button class="btn-red" onclick="ctrl('stop')">Stop</button>
  </div>
  <div class="msg" id="toast"></div>
</div>

<div class="card">
  <div class="title" style="font-size:13px;margin-bottom:6px">Routing Mode</div>
  <div class="row">
    <button id="mode-rule" onclick="setMode('rule')">Rule (Bypass IR/LAN)</button>
    <button id="mode-global" onclick="setMode('global')">Global</button>
    <button id="mode-direct" onclick="setMode('direct')">Direct</button>
  </div>
</div>

<div class="tabs">
  <div class="tab active" id="t-nodes" onclick="showTab('nodes')">Nodes &amp; Sub</div>
  <div class="tab" id="t-apps" onclick="showTab('apps')">Apps</div>
  <div class="tab" id="t-config" onclick="showTab('config')">Config</div>
  <div class="tab" id="t-logs" onclick="showTab('logs')">Logs</div>
</div>

<div id="p-nodes" class="card">
  <div class="title" style="font-size:13px;margin-bottom:6px">Subscription URL (Direct WAN Fetch)</div>
  <input id="subUrlInput" type="text" placeholder="https://example.com/sub/...">
  <div class="row" style="margin-bottom:8px">
    <label style="display:flex;align-items:center;gap:6px;font-size:12px;color:#cbd5e1;cursor:pointer">
      <input id="subInsecureChk" type="checkbox" style="width:auto;margin:0"> Ignore SSL / TLS certificate errors
    </label>
  </div>
  <div class="row" style="margin-bottom:10px">
    <select id="subAutoSel" style="width:auto;margin:0;flex:1">
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
      <button class="btn-amber" style="padding:5px 9px;font-size:11px" onclick="pingAll(false)">Ping All</button>
      <button class="btn-green" style="padding:5px 9px;font-size:11px" onclick="pingAll(true)">Fastest</button>
    </div>
  </div>
  <div id="nodeList"></div>
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
  </div>
</div>

<div id="p-logs" class="card hidden">
  <div class="header">
    <div class="title" style="font-size:13px">Runtime Logs</div>
    <button class="btn-red" style="padding:5px 10px;font-size:11px" onclick="clearLogs()">Clear</button>
  </div>
  <pre id="logBox">Loading logs...</pre>
</div>

<script>
var cachedApps = [];
var selectedUIDMap = {};
var subInitialized = false;

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
  var tabs = ["nodes", "apps", "config", "logs"];
  for (var i = 0; i < tabs.length; i++) {
    var t = tabs[i];
    document.getElementById("t-" + t).className = (t === name) ? "tab active" : "tab";
    document.getElementById("p-" + t).className = (t === name) ? "card" : "card hidden";
  }
  if (name === "apps") { loadApps(); }
  if (name === "config") { loadConfig(); }
  if (name === "logs") { loadLogs(); }
}

function refreshStatus() {
  req("GET", "/api/status", null, function(code, text) {
    if (code !== 200) { return; }
    var d = JSON.parse(text);
    var b = document.getElementById("statusBadge");
    b.innerHTML = d.running ? "RUNNING" : "STOPPED";
    b.className = d.running ? "badge on" : "badge off";
    document.getElementById("metaLine").innerHTML =
      "Netfilter: " + d.net_mode + " | PID: " + d.daemon_pid;

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
    document.getElementById("subMeta").innerHTML =
      "Last updated: " + (d.last_sub_update || "Never");

    renderNodes(d.nodes || [], d.active_node || "");
  });
}

function renderNodes(nodes, activeId) {
  var box = document.getElementById("nodeList");
  if (!nodes.length) {
    box.innerHTML = '<div class="meta">No saved nodes. Using outbound from config.json.</div>';
    return;
  }
  var html = "";
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
      '<button style="padding:5px 7px;font-size:11px" onclick="pingOne(\'' + n.id + '\')">Ping</button>' +
      (sel ? '' : '<button class="btn-blue" style="padding:5px 8px;font-size:11px" onclick="nodeAct(\'select\',\'' + n.id + '\')">Use</button>') +
      '<button class="btn-red" style="padding:5px 7px;font-size:11px" onclick="nodeAct(\'delete\',\'' + n.id + '\')">X</button>' +
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
  showMsg("Switching to " + mode + " mode...");
  req("POST", "/api/mode", {proxy_mode: mode}, function(code) {
    if (code === 200) { showMsg("Active mode: " + mode.toUpperCase()); }
    refreshStatus();
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

refreshStatus();
setInterval(function() {
  refreshStatus();
  if (document.getElementById("p-logs").className === "card") { loadLogs(); }
}, 4000);
</script>
</body>
</html>
`
