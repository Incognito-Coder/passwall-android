package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDecodeBase64Flexible(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standard padded",
			input:    base64.StdEncoding.EncodeToString([]byte("hello world")),
			expected: "hello world",
		},
		{
			name:     "unpadded",
			input:    base64.RawStdEncoding.EncodeToString([]byte("testing 12345")),
			expected: "testing 12345",
		},
		{
			name:     "url safe characters with whitespace",
			input:    "  " + base64.RawURLEncoding.EncodeToString([]byte("url-safe+bytes_test")) + "  \n",
			expected: "url-safe+bytes_test",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeBase64Flexible(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tc.expected {
				t.Errorf("got %q, expected %q", string(got), tc.expected)
			}
		})
	}
}

func TestParseShareURIVless(t *testing.T) {
	t.Run("VLESS Reality TCP", func(t *testing.T) {
		uri := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@198.51.100.1:443?security=reality&sni=test.org&fp=chrome&pbk=abcdef123456&sid=1234&type=tcp&flow=xtls-rprx-vision#MyRealityNode"
		node, err := parseShareURI(uri, "manual")
		if err != nil {
			t.Fatalf("parseShareURI failed: %v", err)
		}

		if node.Protocol != "vless" {
			t.Errorf("expected protocol vless, got %s", node.Protocol)
		}
		if node.Address != "198.51.100.1" || node.Port != 443 {
			t.Errorf("unexpected addr:port %s:%d", node.Address, node.Port)
		}
		if node.Name != "MyRealityNode" {
			t.Errorf("unexpected node name %s", node.Name)
		}

		ob := node.Outbound
		if ob["protocol"] != "vless" {
			t.Errorf("outbound protocol mismatch: %v", ob["protocol"])
		}

		streamSettings, ok := ob["streamSettings"].(map[string]interface{})
		if !ok || streamSettings["security"] != "reality" {
			t.Fatalf("expected reality security, got: %v", streamSettings)
		}

		rs, _ := streamSettings["realitySettings"].(map[string]interface{})
		if rs["publicKey"] != "abcdef123456" || rs["serverName"] != "test.org" {
			t.Errorf("reality settings mismatch: %v", rs)
		}
	})

	t.Run("VLESS WebSocket TLS", func(t *testing.T) {
		uri := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:8443?security=tls&sni=cdn.example.com&type=ws&path=%2Fchat#WsNode"
		node, err := parseShareURI(uri, "sub")
		if err != nil {
			t.Fatalf("parseShareURI failed: %v", err)
		}

		if node.Protocol != "vless" || node.Port != 8443 {
			t.Errorf("unexpected protocol or port: %s:%d", node.Protocol, node.Port)
		}

		ss, _ := node.Outbound["streamSettings"].(map[string]interface{})
		if ss["network"] != "ws" || ss["security"] != "tls" {
			t.Errorf("stream settings mismatch: %v", ss)
		}
		ws, _ := ss["wsSettings"].(map[string]interface{})
		if ws["path"] != "/chat" {
			t.Errorf("ws path mismatch: %v", ws)
		}
	})

	t.Run("VLESS xhttp / splithttp", func(t *testing.T) {
		uri := "vless://uuid1@1.2.3.4:443?security=tls&type=xhttp&path=%2Fxhttp-path&host=xh.example.com#XhttpNode"
		node, err := parseShareURI(uri, "manual")
		if err != nil {
			t.Fatalf("parseShareURI xhttp failed: %v", err)
		}

		ss, _ := node.Outbound["streamSettings"].(map[string]interface{})
		if ss["network"] != "xhttp" {
			t.Errorf("expected network xhttp, got %v", ss["network"])
		}
	})
}

func TestParseShareURITrojan(t *testing.T) {
	uri := "trojan://mypassword@trojan.example.com:443?security=tls&sni=trojan.example.com#TrojanNode"
	node, err := parseShareURI(uri, "manual")
	if err != nil {
		t.Fatalf("parseShareURI trojan failed: %v", err)
	}

	if node.Protocol != "trojan" {
		t.Errorf("expected trojan protocol, got %s", node.Protocol)
	}
	if node.Address != "trojan.example.com" || node.Port != 443 {
		t.Errorf("unexpected addr:port %s:%d", node.Address, node.Port)
	}

	ob := node.Outbound
	settings, ok := ob["settings"].(map[string]interface{})
	if !ok {
		t.Fatalf("settings not found")
	}
	servers, ok := settings["servers"].([]interface{})
	if !ok || len(servers) == 0 {
		t.Fatalf("servers empty")
	}
	srv := servers[0].(map[string]interface{})
	if srv["password"] != "mypassword" {
		t.Errorf("expected password mypassword, got %v", srv["password"])
	}
}

func TestParseShareURIVmess(t *testing.T) {
	vmessJSON := map[string]interface{}{
		"v":    "2",
		"ps":   "VmessServer",
		"add":  "vmess.example.com",
		"port": 443,
		"id":   "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		"aid":  0,
		"net":  "ws",
		"type": "none",
		"host": "vmess.example.com",
		"path": "/ws",
		"tls":  "tls",
		"sni":  "vmess.example.com",
	}
	rawJSON, _ := json.Marshal(vmessJSON)
	uri := "vmess://" + base64.StdEncoding.EncodeToString(rawJSON)

	node, err := parseShareURI(uri, "sub")
	if err != nil {
		t.Fatalf("parseShareURI vmess failed: %v", err)
	}

	if node.Protocol != "vmess" {
		t.Errorf("expected vmess, got %s", node.Protocol)
	}
	if node.Address != "vmess.example.com" || node.Port != 443 {
		t.Errorf("unexpected addr:port %s:%d", node.Address, node.Port)
	}
	if node.Name != "VmessServer" {
		t.Errorf("unexpected name: %s", node.Name)
	}
}

func TestParseShareURIShadowsocks(t *testing.T) {
	t.Run("Standard Base64 Creds", func(t *testing.T) {
		creds := base64.URLEncoding.EncodeToString([]byte("aes-256-gcm:secretpassword"))
		uri := "ss://" + creds + "@ss.example.com:8388#ShadowsocksNode"

		node, err := parseShareURI(uri, "manual")
		if err != nil {
			t.Fatalf("parseShareURI ss failed: %v", err)
		}

		if node.Protocol != "shadowsocks" {
			t.Errorf("expected protocol shadowsocks, got %s", node.Protocol)
		}
		if node.Address != "ss.example.com" || node.Port != 8388 {
			t.Errorf("unexpected addr:port %s:%d", node.Address, node.Port)
		}
		if node.Name != "ShadowsocksNode" {
			t.Errorf("unexpected name: %s", node.Name)
		}

		ob := node.Outbound
		settings := ob["settings"].(map[string]interface{})
		servers := settings["servers"].([]interface{})
		srv := servers[0].(map[string]interface{})
		if srv["method"] != "aes-256-gcm" || srv["password"] != "secretpassword" {
			t.Errorf("unexpected ss creds: %v", srv)
		}
	})

	t.Run("Legacy Full-Base64 format", func(t *testing.T) {
		fullPayload := base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:p@ss!@192.0.2.1:8888"))
		uri := "ss://" + fullPayload + "#LegacySS"

		node, err := parseShareURI(uri, "sub")
		if err != nil {
			t.Fatalf("parse legacy ss failed: %v", err)
		}

		if node.Address != "192.0.2.1" || node.Port != 8888 {
			t.Errorf("unexpected addr:port %s:%d", node.Address, node.Port)
		}
	})
}

func TestCappedLogWriter(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	writer := &CappedLogWriter{path: logPath}

	msg := []byte("test log entry line\n")
	n, err := writer.Write(msg)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if n != len(msg) {
		t.Errorf("expected %d bytes written, got %d", len(msg), n)
	}

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log failed: %v", err)
	}
	if string(content) != string(msg) {
		t.Errorf("expected %q, got %q", string(msg), string(content))
	}
}

func TestParseShareURIHysteria(t *testing.T) {
	t.Run("Hysteria 2 Standard", func(t *testing.T) {
		uri := "hysteria2://mypassword@hy2.example.com:443?sni=sni.example.com&insecure=1&alpn=h3#MyHysteria2Node"
		node, err := parseShareURI(uri, "manual")
		if err != nil {
			t.Fatalf("parseShareURI failed: %v", err)
		}

		if node.Protocol != "hysteria2" {
			t.Errorf("expected protocol hysteria2, got %s", node.Protocol)
		}
		if node.Address != "hy2.example.com" || node.Port != 443 {
			t.Errorf("unexpected addr:port %s:%d", node.Address, node.Port)
		}
		if node.Name != "MyHysteria2Node" {
			t.Errorf("unexpected name %s", node.Name)
		}

		ob := node.Outbound
		if ob["protocol"] != "hysteria" {
			t.Errorf("outbound protocol mismatch: %v", ob["protocol"])
		}

		ss, _ := ob["streamSettings"].(map[string]interface{})
		if ss["network"] != "hysteria" || ss["security"] != "tls" {
			t.Fatalf("stream settings mismatch: %v", ss)
		}

		tlsSet, _ := ss["tlsSettings"].(map[string]interface{})
		if tlsSet["serverName"] != "sni.example.com" || tlsSet["allowInsecure"] != true {
			t.Errorf("tls settings mismatch: %v", tlsSet)
		}
		if tlsSet["fingerprint"] != "chrome" {
			t.Errorf("expected fingerprint chrome, got %v", tlsSet["fingerprint"])
		}

		hySet, _ := ss["hysteriaSettings"].(map[string]interface{})
		if hySet["auth"] != "mypassword" || hySet["version"] != 2 {
			t.Errorf("hysteria settings mismatch: %v", hySet)
		}
		if hySet["udpIdleTimeout"] != 60 {
			t.Errorf("expected udpIdleTimeout 60, got %v", hySet["udpIdleTimeout"])
		}
	})

	t.Run("Hysteria 2 with Obfuscation & hy2 scheme", func(t *testing.T) {
		uri := "hy2://token123@198.51.100.5:8443?obfs=salamander&obfs-password=mask12345#ObfsHy2"
		node, err := parseShareURI(uri, "sub")
		if err != nil {
			t.Fatalf("parseShareURI hy2 failed: %v", err)
		}

		if node.Protocol != "hysteria2" || node.Port != 8443 {
			t.Errorf("expected hysteria2:8443, got %s:%d", node.Protocol, node.Port)
		}

		ss, _ := node.Outbound["streamSettings"].(map[string]interface{})
		finalmask, ok := ss["finalmask"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected finalmask for obfuscation, got: %v", ss)
		}
		udpArr, _ := finalmask["udp"].([]interface{})
		if len(udpArr) == 0 {
			t.Fatalf("finalmask udp empty")
		}
		udpEntry := udpArr[0].(map[string]interface{})
		if udpEntry["type"] != "salamander" {
			t.Errorf("expected salamander type, got %v", udpEntry["type"])
		}
		if udpmasks, ok := ss["udpmasks"].([]interface{}); !ok || len(udpmasks) == 0 {
			t.Errorf("expected udpmasks array in streamSettings for compatibility")
		}
	})

	t.Run("Hysteria 1 / legacy format with port range hopping", func(t *testing.T) {
		uri := "hysteria://hy.server.net:20000-40000?auth=legacyauth&insecure=1#LegacyHysteria"
		node, err := parseShareURI(uri, "manual")
		if err != nil {
			t.Fatalf("parse legacy hysteria failed: %v", err)
		}

		if node.Port != 20000 {
			t.Errorf("expected base hopping port 20000, got %d", node.Port)
		}

		ss := node.Outbound["streamSettings"].(map[string]interface{})
		hySet := ss["hysteriaSettings"].(map[string]interface{})
		if hySet["auth"] != "legacyauth" {
			t.Errorf("expected legacyauth, got %v", hySet["auth"])
		}
	})
}

func TestUpdateSubscriptionWithInsecureSSL(t *testing.T) {
	payload := "vless://uuid@1.2.3.4:443?security=none#Node1\nhy2://pass@5.6.7.8:443#Node2\n"
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer ts.Close()

	// 1. With insecure=false, self-signed certificate should fail verification
	_, err := updateSubscription(ts.URL, false)
	if err == nil {
		t.Fatal("expected SSL verification error when insecure=false, but got nil")
	}

	// 2. With insecure=true, it should bypass SSL verification and succeed
	count, err := updateSubscription(ts.URL, true)
	if err != nil {
		t.Fatalf("unexpected error with insecure=true: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 imported nodes, got %d", count)
	}
}

func TestExtractHost(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"tcp://1.1.1.1", "1.1.1.1"},
		{"tcp://1.1.1.1:53", "1.1.1.1"},
		{"https://dns.google/dns-query", "dns.google"},
		{"https://1.1.1.1:443/dns-query", "1.1.1.1"},
		{"223.5.5.5", "223.5.5.5"},
		{"10.202.10.202:53", "10.202.10.202"},
		{"77.88.8.8", "77.88.8.8"},
		{"  tcp://8.8.8.8  ", "8.8.8.8"},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := extractHost(tc.input)
			if got != tc.expected {
				t.Errorf("extractHost(%q) = %q, expected %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestLoadStateDNSDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	origState := StateFile
	defer func() { StateFile = origState }()

	StateFile = filepath.Join(tmpDir, "state.json")

	st := loadState()
	if st.DNS.RemoteDNS != "tcp://1.1.1.1" {
		t.Errorf("expected default remote DNS tcp://1.1.1.1, got %q", st.DNS.RemoteDNS)
	}
	if st.DNS.DirectDNS != "1.1.1.1" {
		t.Errorf("expected default direct DNS 1.1.1.1, got %q", st.DNS.DirectDNS)
	}
	if st.DNS.QueryStrategy != "UseIPv4" {
		t.Errorf("expected default query strategy UseIPv4, got %q", st.DNS.QueryStrategy)
	}
}

func TestPrepareRuntimeConfigRoutingModes(t *testing.T) {
	tmpDir := t.TempDir()
	origBase := BaseConfig
	origState := StateFile
	origRuntime := RuntimeConfig
	defer func() {
		BaseConfig = origBase
		StateFile = origState
		RuntimeConfig = origRuntime
	}()

	baseCfgPath := filepath.Join(tmpDir, "config.json")
	statePath := filepath.Join(tmpDir, "state.json")
	runtimePath := filepath.Join(tmpDir, "runtime.json")

	BaseConfig = baseCfgPath
	StateFile = statePath
	RuntimeConfig = runtimePath

	baseContent := `{
		"inbounds": [
			{
				"tag": "tproxy-in",
				"listen": "127.0.0.1",
				"port": 12345,
				"protocol": "dokodemo-door",
				"streamSettings": {
					"sockopt": {"tproxy": "tproxy"}
				}
			}
		],
		"outbounds": [
			{"tag": "proxy", "protocol": "vless"},
			{"tag": "direct", "protocol": "freedom"}
		],
		"routing": {"domainStrategy": "IPIfNonMatch", "rules": []}
	}`
	if err := os.WriteFile(baseCfgPath, []byte(baseContent), 0644); err != nil {
		t.Fatalf("failed to write base config: %v", err)
	}

	testNode := NodeProfile{
		ID:       "node-domain-1",
		Name:     "DomainNode",
		Protocol: "vless",
		Address:  "myproxy.vpnserver.com",
		Port:     443,
		Outbound: map[string]interface{}{
			"tag":      "proxy",
			"protocol": "vless",
		},
	}

	t.Run("Rule Mode with Active Domain Node", func(t *testing.T) {
		st := PanelState{
			ProxyMode:  "rule",
			ActiveNode: "node-domain-1",
			DNS: DNSConfig{
				RemoteDNS:     "tcp://1.1.1.1",
				DirectDNS:     "10.202.10.202",
				QueryStrategy: "UseIPv4",
			},
			Nodes: []NodeProfile{testNode},
		}
		if err := saveState(st); err != nil {
			t.Fatalf("saveState failed: %v", err)
		}

		if err := prepareRuntimeConfig(true); err != nil {
			t.Fatalf("prepareRuntimeConfig failed: %v", err)
		}

		data, err := os.ReadFile(runtimePath)
		if err != nil {
			t.Fatalf("read runtime config failed: %v", err)
		}

		var cfg map[string]interface{}
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatalf("unmarshal runtime config failed: %v", err)
		}

		// Verify inbounds listen 0.0.0.0 for hotspot support
		inbounds := cfg["inbounds"].([]interface{})
		tproxyIn := inbounds[0].(map[string]interface{})
		if tproxyIn["listen"] != "0.0.0.0" {
			t.Errorf("expected tproxy-in listen 0.0.0.0, got %v", tproxyIn["listen"])
		}

		// Verify outbound direct has mark set
		outbounds := cfg["outbounds"].([]interface{})
		var directOb map[string]interface{}
		for _, ob := range outbounds {
			m := ob.(map[string]interface{})
			if m["tag"] == "direct" {
				directOb = m
				break
			}
		}
		if directOb == nil {
			t.Fatalf("direct outbound not found")
		}
		ss := directOb["streamSettings"].(map[string]interface{})
		sockopt := ss["sockopt"].(map[string]interface{})
		if int(sockopt["mark"].(float64)) != BypassMark {
			t.Errorf("expected bypass mark %d, got %v", BypassMark, sockopt["mark"])
		}

		// Verify DNS configuration includes active node domain in direct resolution
		dnsCfg := cfg["dns"].(map[string]interface{})
		if dnsCfg["queryStrategy"] != "UseIPv4" {
			t.Errorf("expected queryStrategy UseIPv4, got %v", dnsCfg["queryStrategy"])
		}
		servers := dnsCfg["servers"].([]interface{})
		directEntry := servers[0].(map[string]interface{})
		domains := directEntry["domains"].([]interface{})
		foundNodeDomain := false
		foundCategoryIR := false
		for _, d := range domains {
			if d == "myproxy.vpnserver.com" {
				foundNodeDomain = true
			}
			if d == "geosite:category-ir" {
				foundCategoryIR = true
			}
		}
		if !foundNodeDomain {
			t.Errorf("expected node domain in direct DNS domains, got: %v", domains)
		}
		if !foundCategoryIR {
			t.Errorf("expected geosite:category-ir in direct DNS domains, got: %v", domains)
		}

		// Verify routing rules: DNS intercepted, direct DNS routed direct, node domain routed direct
		routing := cfg["routing"].(map[string]interface{})
		rules := routing["rules"].([]interface{})
		foundDNSOut := false
		foundDirectDNSRule := false
		foundNodeDomainRule := false
		foundCategoryIRRule := false

		for _, r := range rules {
			rm := r.(map[string]interface{})
			if rm["outboundTag"] == "dns-out" {
				foundDNSOut = true
			}
			if ips, ok := rm["ip"].([]interface{}); ok {
				for _, ip := range ips {
					if ip == "10.202.10.202" && rm["outboundTag"] == "direct" && rm["port"] == "53" {
						foundDirectDNSRule = true
					}
				}
			}
			if doms, ok := rm["domain"].([]interface{}); ok {
				for _, dom := range doms {
					if dom == "myproxy.vpnserver.com" && rm["outboundTag"] == "direct" {
						foundNodeDomainRule = true
					}
					if dom == "geosite:category-ir" && rm["outboundTag"] == "direct" {
						foundCategoryIRRule = true
					}
				}
			}
		}

		if !foundDNSOut {
			t.Error("expected port 53 dns-out interception rule")
		}
		if !foundDirectDNSRule {
			t.Error("expected direct DNS IP direct routing rule with port 53")
		}
		if !foundNodeDomainRule {
			t.Error("expected proxy node domain direct routing rule to prevent deadlock")
		}
		if !foundCategoryIRRule {
			t.Error("expected geosite:category-ir in routing direct domains")
		}
	})

	t.Run("Global Mode Routing", func(t *testing.T) {
		st := PanelState{
			ProxyMode:  "global",
			ActiveNode: "node-domain-1",
			DNS: DNSConfig{
				RemoteDNS:     "tcp://1.1.1.1",
				DirectDNS:     "223.5.5.5",
				QueryStrategy: "UseIPv4",
			},
			Nodes: []NodeProfile{testNode},
		}
		if err := saveState(st); err != nil {
			t.Fatalf("saveState failed: %v", err)
		}
		if err := prepareRuntimeConfig(true); err != nil {
			t.Fatalf("prepareRuntimeConfig failed: %v", err)
		}

		data, _ := os.ReadFile(runtimePath)
		var cfg map[string]interface{}
		_ = json.Unmarshal(data, &cfg)

		routing := cfg["routing"].(map[string]interface{})
		rules := routing["rules"].([]interface{})
		foundPrivateDirect := false
		for _, r := range rules {
			rm := r.(map[string]interface{})
			if ips, ok := rm["ip"].([]interface{}); ok {
				for _, ip := range ips {
					if ip == "geoip:private" && rm["outboundTag"] == "direct" {
						foundPrivateDirect = true
					}
				}
			}
		}
		if !foundPrivateDirect {
			t.Error("expected geoip:private direct rule in global mode")
		}
	})

	t.Run("Direct Mode Routing", func(t *testing.T) {
		st := PanelState{
			ProxyMode:  "direct",
			ActiveNode: "node-domain-1",
			DNS: DNSConfig{
				RemoteDNS:     "tcp://1.1.1.1",
				DirectDNS:     "223.5.5.5",
				QueryStrategy: "UseIPv4",
			},
			Nodes: []NodeProfile{testNode},
		}
		if err := saveState(st); err != nil {
			t.Fatalf("saveState failed: %v", err)
		}
		if err := prepareRuntimeConfig(true); err != nil {
			t.Fatalf("prepareRuntimeConfig failed: %v", err)
		}

		data, _ := os.ReadFile(runtimePath)
		var cfg map[string]interface{}
		_ = json.Unmarshal(data, &cfg)

		routing := cfg["routing"].(map[string]interface{})
		rules := routing["rules"].([]interface{})
		fallthroughRule := rules[len(rules)-1].(map[string]interface{})
		if fallthroughRule["outboundTag"] != "direct" {
			t.Errorf("expected fallthrough outboundTag direct in direct mode, got %v", fallthroughRule["outboundTag"])
		}
	})
}

func TestGetModuleVersion(t *testing.T) {
	tmpDir := t.TempDir()
	origBaseDir := BaseDir
	origAppVer := AppVersion
	defer func() {
		BaseDir = origBaseDir
		AppVersion = origAppVer
	}()

	BaseDir = tmpDir

	// 1. When module.prop exists
	propContent := "id=passwall-android\nname=Passwall\nversion=v1.2.9\nversionCode=129\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "module.prop"), []byte(propContent), 0644); err != nil {
		t.Fatalf("failed to write module.prop: %v", err)
	}
	if v := getModuleVersion(); v != "v1.2.9" {
		t.Errorf("expected version v1.2.9 from module.prop, got %q", v)
	}

	// 2. When module.prop does not exist, fall back to AppVersion
	_ = os.Remove(filepath.Join(tmpDir, "module.prop"))
	AppVersion = "v2.0.0-custom"
	if v := getModuleVersion(); v != "v2.0.0-custom" {
		t.Errorf("expected fallback to AppVersion v2.0.0-custom, got %q", v)
	}
}

func TestGetXrayVersion(t *testing.T) {
	origXray := XrayBin
	defer func() {
		XrayBin = origXray
		invalidateXrayVersion()
	}()

	invalidateXrayVersion()

	// 1. Non-existent binary returns "Unknown"
	XrayBin = "/non/existent/xray/bin"
	if v := getXrayVersion(); v != "Unknown" {
		t.Errorf("expected Unknown for missing binary, got %q", v)
	}
}

func TestApiStatusIncludesVersions(t *testing.T) {
	tmpDir := t.TempDir()
	origBaseDir := BaseDir
	origState := StateFile
	defer func() {
		BaseDir = origBaseDir
		StateFile = origState
	}()

	BaseDir = tmpDir
	StateFile = filepath.Join(tmpDir, "state.json")

	propContent := "id=passwall-android\nversion=v1.2.3\nversionCode=123\n"
	_ = os.WriteFile(filepath.Join(tmpDir, "module.prop"), []byte(propContent), 0644)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := loadState()
		resp := map[string]interface{}{
			"running":        false,
			"module_version": getModuleVersion(),
			"xray_version":   getXrayVersion(),
			"dns":            st.DNS,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var res map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal status response failed: %v", err)
	}

	if res["module_version"] != "v1.2.3" {
		t.Errorf("expected module_version v1.2.3, got %v", res["module_version"])
	}
	if _, ok := res["xray_version"]; !ok {
		t.Error("expected xray_version field in status response")
	}
}

func TestPersistentStateBackupAndRestore(t *testing.T) {
	tmpDir := t.TempDir()
	origState := StateFile
	origPersistDir := PersistDir
	origPersistState := PersistStateFile
	defer func() {
		StateFile = origState
		PersistDir = origPersistDir
		PersistStateFile = origPersistState
	}()

	StateFile = filepath.Join(tmpDir, "modules", "passwall-android", "config", "state.json")
	PersistDir = filepath.Join(tmpDir, "persist", "passwall")
	PersistStateFile = filepath.Join(PersistDir, "state.json")

	// 1. User configures state
	customState := PanelState{
		ProxyMode:     "global",
		ActiveNode:    "custom-node-123",
		SubURL:        "https://mysub.link/all",
		SubInsecure:   true,
		AppFilterMode: "proxy",
		SelectedUIDs:  []int{10150, 10151},
		DNS: DNSConfig{
			RemoteDNS:     "https://dns.google/dns-query",
			DirectDNS:     "10.202.10.202",
			QueryStrategy: "UseIP",
		},
		Nodes: []NodeProfile{
			{ID: "custom-node-123", Name: "MyPersistentNode", Protocol: "vless", Address: "vpn.test.org", Port: 443},
		},
	}

	if err := saveState(customState); err != nil {
		t.Fatalf("saveState failed: %v", err)
	}

	// Verify it was saved to both active StateFile and PersistStateFile
	if _, err := os.Stat(StateFile); err != nil {
		t.Fatalf("StateFile not created: %v", err)
	}
	if _, err := os.Stat(PersistStateFile); err != nil {
		t.Fatalf("PersistStateFile not created: %v", err)
	}

	// 2. Simulate module update from ZIP: modules/passwall-android directory is replaced / state.json is removed
	_ = os.Remove(StateFile)
	if _, err := os.Stat(StateFile); !os.IsNotExist(err) {
		t.Fatal("expected StateFile to be deleted")
	}

	// 3. Call loadState() -> should automatically restore from PersistStateFile without losing anything
	restoredState := loadState()
	if restoredState.ActiveNode != "custom-node-123" {
		t.Errorf("expected active node custom-node-123, got %q", restoredState.ActiveNode)
	}
	if restoredState.ProxyMode != "global" {
		t.Errorf("expected proxy mode global, got %q", restoredState.ProxyMode)
	}
	if restoredState.DNS.RemoteDNS != "https://dns.google/dns-query" {
		t.Errorf("expected remote DNS https://dns.google/dns-query, got %q", restoredState.DNS.RemoteDNS)
	}
	if len(restoredState.SelectedUIDs) != 2 || restoredState.SelectedUIDs[0] != 10150 {
		t.Errorf("expected UIDs [10150, 10151], got %v", restoredState.SelectedUIDs)
	}
	if len(restoredState.Nodes) != 1 || restoredState.Nodes[0].Name != "MyPersistentNode" {
		t.Errorf("expected preserved nodes, got %v", restoredState.Nodes)
	}

	// Verify StateFile was recreated from backup
	if _, err := os.Stat(StateFile); err != nil {
		t.Errorf("expected StateFile to be restored on disk: %v", err)
	}
}

func TestPersistentConfigBackupAndRestore(t *testing.T) {
	tmpDir := t.TempDir()
	origBaseConfig := BaseConfig
	origPersistDir := PersistDir
	origPersistBaseConfig := PersistBaseConfig
	defer func() {
		BaseConfig = origBaseConfig
		PersistDir = origPersistDir
		PersistBaseConfig = origPersistBaseConfig
	}()

	BaseConfig = filepath.Join(tmpDir, "modules", "passwall-android", "config", "config.json")
	PersistDir = filepath.Join(tmpDir, "persist", "passwall")
	PersistBaseConfig = filepath.Join(PersistDir, "config.json")

	customJSON := `{"log":{"loglevel":"debug"},"customKey":"customValue"}`
	_ = os.MkdirAll(filepath.Dir(BaseConfig), 0755)
	if err := os.WriteFile(BaseConfig, []byte(customJSON), 0644); err != nil {
		t.Fatalf("failed to write custom base config: %v", err)
	}

	// 1. Sync persistent configs
	syncPersistentConfigs()

	// Verify PersistBaseConfig was backed up
	data, err := os.ReadFile(PersistBaseConfig)
	if err != nil {
		t.Fatalf("PersistBaseConfig not created: %v", err)
	}
	if string(data) != customJSON {
		t.Errorf("expected %q, got %q", customJSON, string(data))
	}

	// 2. Simulate module update wipe: delete BaseConfig
	_ = os.Remove(BaseConfig)

	// 3. syncPersistentConfigs restores BaseConfig from PersistBaseConfig
	syncPersistentConfigs()
	restoredData, err := os.ReadFile(BaseConfig)
	if err != nil {
		t.Fatalf("BaseConfig not restored: %v", err)
	}
	if string(restoredData) != customJSON {
		t.Errorf("expected restored config %q, got %q", customJSON, string(restoredData))
	}
}

func TestLocalhostProxyStateDefaultAndToggle(t *testing.T) {
	tmpDir := t.TempDir()
	origState := StateFile
	origPersistState := PersistStateFile
	origBaseDir := BaseDir
	defer func() {
		StateFile = origState
		PersistStateFile = origPersistState
		BaseDir = origBaseDir
	}()

	StateFile = filepath.Join(tmpDir, "state.json")
	PersistStateFile = filepath.Join(tmpDir, "persist_state.json")
	BaseDir = tmpDir

	// 1. Initial state defaults to LocalhostProxy = true
	st := loadState()
	if !st.LocalhostProxy {
		t.Errorf("expected LocalhostProxy default to be true, got false")
	}

	// 2. Set LocalhostProxy = false and save
	st.LocalhostProxy = false
	if err := saveState(st); err != nil {
		t.Fatalf("saveState failed: %v", err)
	}

	// 3. Reload state and verify LocalhostProxy is false
	reloaded := loadState()
	if reloaded.LocalhostProxy {
		t.Errorf("expected LocalhostProxy to be false after save, got true")
	}

	// 4. Toggle back to true and verify
	reloaded.LocalhostProxy = true
	if err := saveState(reloaded); err != nil {
		t.Fatalf("saveState failed: %v", err)
	}
	reloaded2 := loadState()
	if !reloaded2.LocalhostProxy {
		t.Errorf("expected LocalhostProxy to be true after toggle back, got false")
	}
}

func TestPrepareRuntimeConfigSocksInbound(t *testing.T) {
	tmpDir := t.TempDir()
	origBase := BaseConfig
	origRuntime := RuntimeConfig
	origState := StateFile
	origPersistBase := PersistBaseConfig
	origPersistState := PersistStateFile
	defer func() {
		BaseConfig = origBase
		RuntimeConfig = origRuntime
		StateFile = origState
		PersistBaseConfig = origPersistBase
		PersistStateFile = origPersistState
	}()

	BaseConfig = filepath.Join(tmpDir, "config.json")
	RuntimeConfig = filepath.Join(tmpDir, "runtime.json")
	StateFile = filepath.Join(tmpDir, "state.json")
	PersistBaseConfig = filepath.Join(tmpDir, "persist_config.json")
	PersistStateFile = filepath.Join(tmpDir, "persist_state.json")

	// Config without socks-in inbound
	baseJSON := `{
		"inbounds": [
			{"tag": "tproxy-in", "listen": "0.0.0.0", "port": 12345, "protocol": "dokodemo-door"}
		],
		"outbounds": [
			{"tag": "direct", "protocol": "freedom"}
		]
	}`
	if err := os.WriteFile(BaseConfig, []byte(baseJSON), 0644); err != nil {
		t.Fatalf("failed to write base config: %v", err)
	}

	if err := prepareRuntimeConfig(true); err != nil {
		t.Fatalf("prepareRuntimeConfig failed: %v", err)
	}

	data, err := os.ReadFile(RuntimeConfig)
	if err != nil {
		t.Fatalf("failed to read runtime config: %v", err)
	}

	var generated map[string]interface{}
	if err := json.Unmarshal(data, &generated); err != nil {
		t.Fatalf("invalid runtime json: %v", err)
	}

	inbounds, ok := generated["inbounds"].([]interface{})
	if !ok {
		t.Fatalf("expected inbounds array in generated config")
	}

	hasSocks := false
	for _, item := range inbounds {
		if inb, ok := item.(map[string]interface{}); ok {
			if tag, _ := inb["tag"].(string); tag == "socks-in" {
				hasSocks = true
				if inb["listen"] != "127.0.0.1" || int(inb["port"].(float64)) != 10808 {
					t.Errorf("socks-in config mismatch: listen=%v port=%v", inb["listen"], inb["port"])
				}
			}
		}
	}
	if !hasSocks {
		t.Errorf("expected socks-in inbound to be added to generated runtime config")
	}
}

func TestCheckTargetConnectivity(t *testing.T) {
	// 1. Mock server returning 204 No Content
	mock204 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer mock204.Close()

	client := mock204.Client()
	status204 := checkTargetConnectivity(client, mock204.URL)
	if !status204.Reachable {
		t.Errorf("expected 204 target to be reachable, got false (status: %s)", status204.Status)
	}
	if status204.LatencyMs <= 0 {
		t.Errorf("expected positive latency, got %d", status204.LatencyMs)
	}

	// 2. Mock server returning 200 OK
	mock200 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer mock200.Close()

	status200 := checkTargetConnectivity(client, mock200.URL)
	if !status200.Reachable {
		t.Errorf("expected 200 target to be reachable, got false")
	}

	// 3. Mock server returning 500 Internal Server Error
	mock500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mock500.Close()

	status500 := checkTargetConnectivity(client, mock500.URL)
	if status500.Reachable {
		t.Errorf("expected 500 target to NOT be reachable, got reachable: true")
	}

	// 4. Invalid unreachable URL
	statusErr := checkTargetConnectivity(client, "http://127.0.0.1:54321/unreachable")
	if statusErr.Reachable {
		t.Errorf("expected unreachable target to return reachable: false")
	}
}

func TestApiLocalhostProxyAndConnectivityEndpoints(t *testing.T) {
	tmpDir := t.TempDir()
	origState := StateFile
	origPersistState := PersistStateFile
	defer func() {
		StateFile = origState
		PersistStateFile = origPersistState
	}()

	StateFile = filepath.Join(tmpDir, "state.json")
	PersistStateFile = filepath.Join(tmpDir, "persist_state.json")

	// 1. Initial status includes localhost_proxy: true
	reqStatus := httptest.NewRequest("GET", "/api/status", nil)
	recStatus := httptest.NewRecorder()

	statusHandler := func(w http.ResponseWriter, r *http.Request) {
		st := loadState()
		resp := map[string]interface{}{
			"running":         false,
			"localhost_proxy": st.LocalhostProxy,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}

	statusHandler(recStatus, reqStatus)
	var statusRes map[string]interface{}
	if err := json.Unmarshal(recStatus.Body.Bytes(), &statusRes); err != nil {
		t.Fatalf("failed to decode status response: %v", err)
	}
	if statusRes["localhost_proxy"] != true {
		t.Errorf("expected localhost_proxy true, got %v", statusRes["localhost_proxy"])
	}

	// 2. POST /api/localhost_proxy to set it to false
	toggleBody := bytes.NewBufferString(`{"localhost_proxy":false}`)
	reqToggle := httptest.NewRequest("POST", "/api/localhost_proxy", toggleBody)
	recToggle := httptest.NewRecorder()

	toggleHandler := func(w http.ResponseWriter, r *http.Request) {
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
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}

	toggleHandler(recToggle, reqToggle)
	if recToggle.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", recToggle.Code)
	}

	// Verify state saved on disk
	st := loadState()
	if st.LocalhostProxy != false {
		t.Errorf("expected state LocalhostProxy to be false, got true")
	}

	// 3. GET /api/connectivity when stopped returns stopped status
	connRes := checkConnectivity()
	if connRes.Google.Reachable || connRes.Github.Reachable {
		t.Errorf("expected connectivity to be false when engine stopped, got %v", connRes)
	}
	if connRes.Google.Status != "Proxy stopped" {
		t.Errorf("expected status 'Proxy stopped', got %q", connRes.Google.Status)
	}
}

func TestDirectDNSCloudflareUDPWithRemoteDNSTCP(t *testing.T) {
	tmpDir := t.TempDir()
	origBase := BaseConfig
	origState := StateFile
	origRuntime := RuntimeConfig
	defer func() {
		BaseConfig = origBase
		StateFile = origState
		RuntimeConfig = origRuntime
	}()

	BaseConfig = filepath.Join(tmpDir, "config.json")
	StateFile = filepath.Join(tmpDir, "state.json")
	RuntimeConfig = filepath.Join(tmpDir, "runtime.json")

	baseJSON := `{"inbounds":[{"tag":"tproxy-in","listen":"0.0.0.0","port":12345,"protocol":"dokodemo-door"}],"outbounds":[{"tag":"proxy","protocol":"vless"},{"tag":"direct","protocol":"freedom"}],"routing":{"domainStrategy":"IPIfNonMatch","rules":[]}}`
	if err := os.WriteFile(BaseConfig, []byte(baseJSON), 0644); err != nil {
		t.Fatalf("failed to write base config: %v", err)
	}

	// Direct DNS: 1.1.1.1 (UDP), Remote DNS: tcp://1.1.1.1 (TCP)
	st := PanelState{
		ProxyMode:  "rule",
		ActiveNode: "node1",
		DNS: DNSConfig{
			RemoteDNS:     "tcp://1.1.1.1",
			DirectDNS:     "1.1.1.1",
			QueryStrategy: "UseIPv4",
		},
		Nodes: []NodeProfile{
			{ID: "node1", Name: "Node1", Protocol: "vless", Address: "proxy.server.com", Port: 443, Outbound: map[string]interface{}{"tag": "proxy", "protocol": "vless"}},
		},
	}
	if err := saveState(st); err != nil {
		t.Fatalf("saveState failed: %v", err)
	}

	if err := prepareRuntimeConfig(true); err != nil {
		t.Fatalf("prepareRuntimeConfig failed: %v", err)
	}

	data, err := os.ReadFile(RuntimeConfig)
	if err != nil {
		t.Fatalf("read runtime config failed: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal config failed: %v", err)
	}

	// Verify DNS server ordering: direct DNS is Server 0, remote DNS is Server 1
	dnsCfg := cfg["dns"].(map[string]interface{})
	servers := dnsCfg["servers"].([]interface{})
	server0 := servers[0].(map[string]interface{})
	if server0["address"] != "1.1.1.1" {
		t.Errorf("expected Server 0 to be direct DNS 1.1.1.1, got %v", server0["address"])
	}
	server1 := servers[1].(map[string]interface{})
	if server1["address"] != "tcp://1.1.1.1" {
		t.Errorf("expected Server 1 to be remote DNS tcp://1.1.1.1, got %v", server1["address"])
	}

	// Verify routing rules: direct rule for 1.1.1.1 specifies network "udp" and port "53"
	routing := cfg["routing"].(map[string]interface{})
	rules := routing["rules"].([]interface{})
	foundDirectUDP53 := false
	for _, r := range rules {
		rm := r.(map[string]interface{})
		if rm["outboundTag"] == "direct" && rm["port"] == "53" {
			if ips, ok := rm["ip"].([]interface{}); ok && len(ips) == 1 && ips[0] == "1.1.1.1" {
				if rm["network"] == "udp" {
					foundDirectUDP53 = true
				}
			}
		}
	}
	if !foundDirectUDP53 {
		t.Errorf("expected direct rule for 1.1.1.1 to match port 53 and network udp to prevent hijacking remote TCP DNS")
	}
}

func TestApiModeSwitchAndAutoRestart(t *testing.T) {
	tmpDir := t.TempDir()
	origState := StateFile
	origPersistState := PersistStateFile
	defer func() {
		StateFile = origState
		PersistStateFile = origPersistState
	}()

	StateFile = filepath.Join(tmpDir, "state.json")
	PersistStateFile = filepath.Join(tmpDir, "persist_state.json")

	st := PanelState{
		ProxyMode: "rule",
		Nodes:     []NodeProfile{},
	}
	_ = saveState(st)

	modeBody := bytes.NewBufferString(`{"proxy_mode":"global"}`)
	req := httptest.NewRequest("POST", "/api/mode", modeBody)
	rec := httptest.NewRecorder()

	handler := func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ProxyMode string `json:"proxy_mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s := loadState()
		s.ProxyMode = req.ProxyMode
		_ = saveState(s)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "ok",
			"mode":      req.ProxyMode,
			"restarted": false,
		})
	}

	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	saved := loadState()
	if saved.ProxyMode != "global" {
		t.Errorf("expected mode global, got %s", saved.ProxyMode)
	}
}

func TestProxyOutboundSockoptMark(t *testing.T) {
	tmpDir := t.TempDir()
	origBase := BaseConfig
	origState := StateFile
	origRuntime := RuntimeConfig
	defer func() {
		BaseConfig = origBase
		StateFile = origState
		RuntimeConfig = origRuntime
	}()

	BaseConfig = filepath.Join(tmpDir, "config.json")
	StateFile = filepath.Join(tmpDir, "state.json")
	RuntimeConfig = filepath.Join(tmpDir, "runtime.json")

	baseJSON := `{"inbounds":[],"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[]}}`
	_ = os.WriteFile(BaseConfig, []byte(baseJSON), 0644)

	st := PanelState{
		ProxyMode:  "rule",
		ActiveNode: "hy-1",
		Nodes: []NodeProfile{
			{
				ID:       "hy-1",
				Name:     "HyNode",
				Protocol: "hysteria2",
				Address:  "198.51.100.10",
				Port:     443,
				Outbound: map[string]interface{}{
					"tag":      "proxy",
					"protocol": "hysteria",
					"streamSettings": map[string]interface{}{
						"network": "hysteria",
					},
				},
			},
		},
	}
	_ = saveState(st)

	if err := prepareRuntimeConfig(true); err != nil {
		t.Fatalf("prepareRuntimeConfig failed: %v", err)
	}

	data, err := os.ReadFile(RuntimeConfig)
	if err != nil {
		t.Fatalf("read runtime config failed: %v", err)
	}
	var cfg map[string]interface{}
	_ = json.Unmarshal(data, &cfg)

	outbounds := cfg["outbounds"].([]interface{})
	var proxyOb map[string]interface{}
	for _, ob := range outbounds {
		m := ob.(map[string]interface{})
		if m["tag"] == "proxy" {
			proxyOb = m
			break
		}
	}
	if proxyOb == nil {
		t.Fatalf("expected proxy outbound in generated config")
	}

	ss, ok := proxyOb["streamSettings"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected streamSettings in proxy outbound")
	}
	sockopt, ok := ss["sockopt"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected sockopt in proxy outbound streamSettings")
	}
	if int(sockopt["mark"].(float64)) != BypassMark {
		t.Errorf("expected proxy outbound mark %d, got %v", BypassMark, sockopt["mark"])
	}
}

func TestButtonAndBadgeCSSStyles(t *testing.T) {
	if !strings.Contains(dashboardHTML, "display:inline-flex;align-items:center;justify-content:center") {
		t.Errorf("expected inline-flex vertical centering styles in dashboardHTML")
	}
	if !strings.Contains(dashboardHTML, ".badge-ver") {
		t.Errorf("expected .badge-ver in dashboardHTML")
	}
}

func TestGetAssetDir(t *testing.T) {
	origAsset := AssetDir
	origBase := BaseDir
	defer func() {
		AssetDir = origAsset
		BaseDir = origBase
	}()

	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	_ = os.MkdirAll(binDir, 0755)
	_ = os.WriteFile(filepath.Join(binDir, "geoip.dat"), []byte("test"), 0644)

	AssetDir = binDir
	BaseDir = tmp

	if dir := getAssetDir(); dir != binDir {
		t.Errorf("expected %s, got %s", binDir, dir)
	}

	cfgDir := filepath.Join(tmp, "config")
	_ = os.MkdirAll(cfgDir, 0755)
	_ = os.WriteFile(filepath.Join(cfgDir, "geoip.dat"), []byte("test"), 0644)
	AssetDir = filepath.Join(tmp, "nonexistent")
	_ = os.Remove(filepath.Join(binDir, "geoip.dat"))

	if dir := getAssetDir(); dir != cfgDir {
		t.Errorf("expected %s, got %s", cfgDir, dir)
	}
}

func TestDirectDNSPreservesCustomValue(t *testing.T) {
	tmpDir := t.TempDir()
	origState := StateFile
	origPersistState := PersistStateFile
	defer func() {
		StateFile = origState
		PersistStateFile = origPersistState
	}()
	StateFile = filepath.Join(tmpDir, "state.json")
	PersistStateFile = filepath.Join(tmpDir, "persist.json")

	st := PanelState{
		DNS: DNSConfig{
			DirectDNS: "223.5.5.5",
			RemoteDNS: "tcp://1.1.1.1",
		},
	}
	if err := saveState(st); err != nil {
		t.Fatalf("saveState failed: %v", err)
	}

	loaded := loadState()
	if loaded.DNS.DirectDNS != "223.5.5.5" {
		t.Errorf("expected DirectDNS to remain 223.5.5.5, got %q", loaded.DNS.DirectDNS)
	}

	st.DNS.DirectDNS = "10.202.10.202"
	if err := saveState(st); err != nil {
		t.Fatalf("saveState failed: %v", err)
	}
	loaded = loadState()
	if loaded.DNS.DirectDNS != "10.202.10.202" {
		t.Errorf("expected DirectDNS to remain 10.202.10.202, got %q", loaded.DNS.DirectDNS)
	}
}

func TestActiveNodeAutoSelectionOnBoot(t *testing.T) {
	tmpDir := t.TempDir()
	origState := StateFile
	origPersistState := PersistStateFile
	defer func() {
		StateFile = origState
		PersistStateFile = origPersistState
	}()
	StateFile = filepath.Join(tmpDir, "state.json")
	PersistStateFile = filepath.Join(tmpDir, "persist.json")

	// State with nodes but empty ActiveNode
	st := PanelState{
		ActiveNode: "",
		Nodes: []NodeProfile{
			{ID: "node-first", Name: "First Node", Protocol: "vless"},
			{ID: "node-second", Name: "Second Node", Protocol: "vless"},
		},
	}
	data, _ := json.Marshal(st)
	_ = os.WriteFile(StateFile, data, 0644)
	_ = os.WriteFile(PersistStateFile, data, 0644)

	loaded := loadState()
	if loaded.ActiveNode != "node-first" {
		t.Errorf("expected ActiveNode to auto-fallback to first node 'node-first', got %q", loaded.ActiveNode)
	}

	// State with ActiveNode pointing to non-existent node
	st.ActiveNode = "non-existent-id"
	data, _ = json.Marshal(st)
	_ = os.WriteFile(StateFile, data, 0644)
	_ = os.WriteFile(PersistStateFile, data, 0644)

	loaded = loadState()
	if loaded.ActiveNode != "node-first" {
		t.Errorf("expected ActiveNode pointing to invalid ID to fallback to 'node-first', got %q", loaded.ActiveNode)
	}
}

func TestInboundSniffingConfigured(t *testing.T) {
	tmpDir := t.TempDir()
	origBase := BaseConfig
	origState := StateFile
	origRuntime := RuntimeConfig
	defer func() {
		BaseConfig = origBase
		StateFile = origState
		RuntimeConfig = origRuntime
	}()

	BaseConfig = filepath.Join(tmpDir, "config.json")
	StateFile = filepath.Join(tmpDir, "state.json")
	RuntimeConfig = filepath.Join(tmpDir, "runtime.json")

	// Base config with no sniffing on inbounds
	baseJSON := `{"inbounds":[{"tag":"tproxy-in","listen":"0.0.0.0","port":12345,"protocol":"dokodemo-door"}],"outbounds":[{"tag":"proxy","protocol":"vless"},{"tag":"direct","protocol":"freedom"}],"routing":{"domainStrategy":"IPIfNonMatch","rules":[]}}`
	if err := os.WriteFile(BaseConfig, []byte(baseJSON), 0644); err != nil {
		t.Fatalf("failed to write base config: %v", err)
	}

	st := PanelState{
		ProxyMode:  "rule",
		ActiveNode: "node1",
		Nodes: []NodeProfile{
			{ID: "node1", Name: "Node1", Protocol: "vless", Address: "1.2.3.4", Port: 443, Outbound: map[string]interface{}{"tag": "proxy", "protocol": "vless"}},
		},
	}
	_ = saveState(st)

	if err := prepareRuntimeConfig(true); err != nil {
		t.Fatalf("prepareRuntimeConfig failed: %v", err)
	}

	data, err := os.ReadFile(RuntimeConfig)
	if err != nil {
		t.Fatalf("read runtime config failed: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal config failed: %v", err)
	}

	inbounds := cfg["inbounds"].([]interface{})
	var tproxyIn, socksIn map[string]interface{}
	for _, inb := range inbounds {
		m := inb.(map[string]interface{})
		if m["tag"] == "tproxy-in" {
			tproxyIn = m
		}
		if m["tag"] == "socks-in" {
			socksIn = m
		}
	}

	if tproxyIn == nil {
		t.Fatalf("expected tproxy-in inbound")
	}
	sniffT, ok := tproxyIn["sniffing"].(map[string]interface{})
	if !ok || sniffT["enabled"] != true {
		t.Errorf("expected sniffing enabled on tproxy-in, got %v", sniffT)
	}
	if sniffT["routeOnly"] != true {
		t.Errorf("expected routeOnly: true on tproxy-in sniffing")
	}

	if socksIn == nil {
		t.Fatalf("expected socks-in inbound")
	}
	sniffS, ok := socksIn["sniffing"].(map[string]interface{})
	if !ok || sniffS["enabled"] != true {
		t.Errorf("expected sniffing enabled on socks-in, got %v", sniffS)
	}

	// Verify DNS server skipFallback is false
	dnsCfg := cfg["dns"].(map[string]interface{})
	servers := dnsCfg["servers"].([]interface{})
	server0 := servers[0].(map[string]interface{})
	if server0["skipFallback"] == true {
		t.Errorf("expected skipFallback to be false for direct DNS server")
	}

	// Verify domainStrategy is IPIfNonMatch
	routing := cfg["routing"].(map[string]interface{})
	if routing["domainStrategy"] != "IPIfNonMatch" {
		t.Errorf("expected domainStrategy IPIfNonMatch, got %v", routing["domainStrategy"])
	}
}

func TestWebListenAddrIsAllInterfaces(t *testing.T) {
	if WebListenAddr != "0.0.0.0:9090" {
		t.Errorf("expected WebListenAddr to be 0.0.0.0:9090, got %q", WebListenAddr)
	}
}

func TestCSSVerticalCenteringStyles(t *testing.T) {
	if !strings.Contains(dashboardHTML, "line-height:1") {
		t.Errorf("expected line-height:1 in dashboardHTML")
	}
	if !strings.Contains(dashboardHTML, "appearance:none;-webkit-appearance:none") {
		t.Errorf("expected appearance:none in dashboardHTML")
	}
	if !strings.Contains(dashboardHTML, ".btn-sm") {
		t.Errorf("expected .btn-sm class in dashboardHTML")
	}
}

func TestFreedomDomainStrategyMigration(t *testing.T) {
	tmpDir := t.TempDir()
	origBase := BaseConfig
	origState := StateFile
	origRuntime := RuntimeConfig
	defer func() {
		BaseConfig = origBase
		StateFile = origState
		RuntimeConfig = origRuntime
	}()

	BaseConfig = filepath.Join(tmpDir, "config.json")
	StateFile = filepath.Join(tmpDir, "state.json")
	RuntimeConfig = filepath.Join(tmpDir, "runtime.json")

	// Legacy base config with deprecated settings.domainStrategy in freedom outbound
	baseJSON := `{
		"inbounds": [{"tag":"tproxy-in","listen":"0.0.0.0","port":12345,"protocol":"dokodemo-door"}],
		"outbounds": [
			{"tag":"proxy","protocol":"vless"},
			{
				"tag":"direct",
				"protocol":"freedom",
				"settings":{
					"domainStrategy":"UseIPv4"
				}
			}
		],
		"routing": {"domainStrategy":"IPIfNonMatch","rules":[]}
	}`
	if err := os.WriteFile(BaseConfig, []byte(baseJSON), 0644); err != nil {
		t.Fatalf("failed to write base config: %v", err)
	}

	st := PanelState{
		ProxyMode:  "rule",
		ActiveNode: "node1",
		Nodes: []NodeProfile{
			{ID: "node1", Name: "Node1", Protocol: "vless", Address: "1.2.3.4", Port: 443, Outbound: map[string]interface{}{"tag": "proxy", "protocol": "vless"}},
		},
	}
	_ = saveState(st)

	if err := prepareRuntimeConfig(true); err != nil {
		t.Fatalf("prepareRuntimeConfig failed: %v", err)
	}

	data, err := os.ReadFile(RuntimeConfig)
	if err != nil {
		t.Fatalf("read runtime config failed: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal config failed: %v", err)
	}

	outbounds := cfg["outbounds"].([]interface{})
	var directOb map[string]interface{}
	for _, ob := range outbounds {
		m := ob.(map[string]interface{})
		if m["tag"] == "direct" {
			directOb = m
			break
		}
	}
	if directOb == nil {
		t.Fatalf("expected direct outbound in config")
	}

	// 1. Deprecated domainStrategy in settings MUST be removed
	if settings, ok := directOb["settings"].(map[string]interface{}); ok {
		if _, exists := settings["domainStrategy"]; exists {
			t.Errorf("deprecated freedom.domainStrategy should have been removed from settings, but was found: %v", settings["domainStrategy"])
		}
	}

	// 2. domainStrategy MUST be present in streamSettings.sockopt
	ss, ok := directOb["streamSettings"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected streamSettings in direct outbound")
	}
	sockopt, ok := ss["sockopt"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected sockopt in streamSettings")
	}
	if sockopt["domainStrategy"] != "UseIPv4" {
		t.Errorf("expected sockopt.domainStrategy to be 'UseIPv4', got %v", sockopt["domainStrategy"])
	}
}

func TestDefaultBaseConfigJSONValid(t *testing.T) {
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(DefaultBaseConfigJSON), &cfg); err != nil {
		t.Fatalf("DefaultBaseConfigJSON is not valid JSON: %v", err)
	}

	// Verify freedom outbound has sockopt.domainStrategy
	outbounds, ok := cfg["outbounds"].([]interface{})
	if !ok {
		t.Fatalf("outbounds not found in default config")
	}
	var directOb map[string]interface{}
	for _, ob := range outbounds {
		m := ob.(map[string]interface{})
		if m["tag"] == "direct" {
			directOb = m
			break
		}
	}
	if directOb == nil {
		t.Fatalf("direct outbound not found")
	}
	if settings, ok := directOb["settings"].(map[string]interface{}); ok {
		if _, exists := settings["domainStrategy"]; exists {
			t.Errorf("DefaultBaseConfigJSON has deprecated freedom.domainStrategy in settings")
		}
	}
}

func TestResetBaseConfig(t *testing.T) {
	tmpDir := t.TempDir()
	origBase := BaseConfig
	origPersistBase := PersistBaseConfig
	origState := StateFile
	origPersistState := PersistStateFile
	origPersistDir := PersistDir
	defer func() {
		BaseConfig = origBase
		PersistBaseConfig = origPersistBase
		StateFile = origState
		PersistStateFile = origPersistState
		PersistDir = origPersistDir
	}()

	BaseConfig = filepath.Join(tmpDir, "config.json")
	PersistDir = filepath.Join(tmpDir, "persist")
	PersistBaseConfig = filepath.Join(PersistDir, "config.json")
	StateFile = filepath.Join(tmpDir, "state.json")
	PersistStateFile = filepath.Join(PersistDir, "state.json")

	// Corrupt or write customized config.json and active state
	_ = os.WriteFile(BaseConfig, []byte(`{"custom":"bad-config"}`), 0644)
	st := PanelState{ActiveNode: "node-123"}
	_ = saveState(st)

	if err := resetBaseConfig(); err != nil {
		t.Fatalf("resetBaseConfig failed: %v", err)
	}

	// Verify BaseConfig was restored
	baseData, err := os.ReadFile(BaseConfig)
	if err != nil {
		t.Fatalf("read BaseConfig failed: %v", err)
	}
	var testObj map[string]interface{}
	if err := json.Unmarshal(baseData, &testObj); err != nil {
		t.Fatalf("restored config is invalid JSON: %v", err)
	}
	if _, ok := testObj["inbounds"]; !ok {
		t.Errorf("restored config missing inbounds")
	}

	// Verify PersistBaseConfig was restored
	persistData, err := os.ReadFile(PersistBaseConfig)
	if err != nil {
		t.Fatalf("read PersistBaseConfig failed: %v", err)
	}
	if string(persistData) != string(baseData) {
		t.Errorf("PersistBaseConfig does not match BaseConfig")
	}

	// Verify active node was cleared
	loadedSt := loadState()
	if loadedSt.ActiveNode != "" {
		t.Errorf("expected ActiveNode to be reset to empty, got %q", loadedSt.ActiveNode)
	}
}

func TestApiConfigReset(t *testing.T) {
	tmpDir := t.TempDir()
	origBase := BaseConfig
	origPersistBase := PersistBaseConfig
	origState := StateFile
	origPersistState := PersistStateFile
	origPersistDir := PersistDir
	defer func() {
		BaseConfig = origBase
		PersistBaseConfig = origPersistBase
		StateFile = origState
		PersistStateFile = origPersistState
		PersistDir = origPersistDir
	}()

	BaseConfig = filepath.Join(tmpDir, "config.json")
	PersistDir = filepath.Join(tmpDir, "persist")
	PersistBaseConfig = filepath.Join(PersistDir, "config.json")
	StateFile = filepath.Join(tmpDir, "state.json")
	PersistStateFile = filepath.Join(PersistDir, "state.json")

	// Corrupt BaseConfig first
	_ = os.WriteFile(BaseConfig, []byte(`{"corrupted":true}`), 0644)
	_ = saveState(PanelState{ActiveNode: "old-node"})

	// Test 1: POST /api/config with {"action":"reset"}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req struct {
				Action  string `json:"action"`
				RawJSON string `json:"raw_json"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Action == "reset" {
				if err := resetBaseConfig(); err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
				return
			}
		}
	})
	mux.HandleFunc("/api/config/reset", func(w http.ResponseWriter, r *http.Request) {
		if err := resetBaseConfig(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/config", strings.NewReader(`{"action":"reset"}`))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/config action:reset, got %d", rec.Code)
	}

	data, _ := os.ReadFile(BaseConfig)
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil || cfg["inbounds"] == nil {
		t.Fatalf("BaseConfig was not reset properly: %s", string(data))
	}

	// Test 2: POST /api/config/reset
	_ = os.WriteFile(BaseConfig, []byte(`{"custom":123}`), 0644)
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/config/reset", nil)
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/config/reset, got %d", rec2.Code)
	}
	data2, _ := os.ReadFile(BaseConfig)
	if strings.Contains(string(data2), `"custom"`) {
		t.Errorf("expected config to be reset, but still contains custom")
	}
}

func TestPrepareRuntimeConfigPreservesUserRules(t *testing.T) {
	tmpDir := t.TempDir()
	origBase := BaseConfig
	origState := StateFile
	origRuntime := RuntimeConfig
	defer func() {
		BaseConfig = origBase
		StateFile = origState
		RuntimeConfig = origRuntime
	}()

	BaseConfig = filepath.Join(tmpDir, "config.json")
	StateFile = filepath.Join(tmpDir, "state.json")
	RuntimeConfig = filepath.Join(tmpDir, "runtime.json")

	// Base config with a custom domain routing rule
	customBase := `{
		"inbounds": [{"tag": "tproxy-in", "listen": "0.0.0.0", "port": 12345, "protocol": "dokodemo-door"}],
		"outbounds": [{"tag": "proxy", "protocol": "vless"}, {"tag": "direct", "protocol": "freedom"}],
		"routing": {
			"domainStrategy": "IPIfNonMatch",
			"rules": [
				{
					"type": "field",
					"domain": ["customdomain.example.com"],
					"outboundTag": "proxy"
				}
			]
		}
	}`
	if err := os.WriteFile(BaseConfig, []byte(customBase), 0644); err != nil {
		t.Fatalf("failed to write BaseConfig: %v", err)
	}

	st := PanelState{
		ProxyMode:  "rule",
		ActiveNode: "node1",
		Nodes: []NodeProfile{
			{ID: "node1", Name: "Node1", Protocol: "vless", Address: "1.2.3.4", Port: 443, Outbound: map[string]interface{}{"tag": "proxy", "protocol": "vless"}},
		},
	}
	_ = saveState(st)

	if err := prepareRuntimeConfig(true); err != nil {
		t.Fatalf("prepareRuntimeConfig failed: %v", err)
	}

	data, err := os.ReadFile(RuntimeConfig)
	if err != nil {
		t.Fatalf("read runtime config failed: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal runtime config failed: %v", err)
	}

	routing, ok := cfg["routing"].(map[string]interface{})
	if !ok {
		t.Fatalf("routing object missing in runtime config")
	}
	rules, ok := routing["rules"].([]interface{})
	if !ok {
		t.Fatalf("rules array missing in runtime config")
	}

	foundCustom := false
	for _, r := range rules {
		rMap := r.(map[string]interface{})
		if domains, ok := rMap["domain"].([]interface{}); ok {
			for _, d := range domains {
				if d == "customdomain.example.com" {
					foundCustom = true
					if rMap["outboundTag"] != "proxy" {
						t.Errorf("expected outboundTag 'proxy' for custom domain rule, got %v", rMap["outboundTag"])
					}
					break
				}
			}
		}
	}

	if !foundCustom {
		t.Errorf("custom user domain routing rule was not preserved in runtime config")
	}
}

func TestWebUIConfigResetButton(t *testing.T) {
	if !strings.Contains(dashboardHTML, `onclick="resetConfig()"`) {
		t.Errorf("expected Reset to Default button in dashboardHTML")
	}
	if !strings.Contains(dashboardHTML, `function resetConfig()`) {
		t.Errorf("expected resetConfig() function in dashboardHTML")
	}
	if !strings.Contains(dashboardHTML, `/api/config/reset`) {
		t.Errorf("expected /api/config/reset call in dashboardHTML")
	}
}

func TestCheckGeositeTags(t *testing.T) {
	geositePath := "dist/passwall-android/bin/geosite.dat"
	data, err := os.ReadFile(geositePath)
	if err != nil {
		t.Skip("geosite.dat not present in dist")
	}
	
	foundTags := map[string]bool{}
	for i := 0; i < len(data)-10; i++ {
		if data[i] == 0x0a {
			l := int(data[i+1])
			if l > 0 && l < 30 && i+2+l <= len(data) {
				tag := string(data[i+2 : i+2+l])
				isAlphanum := true
				for _, c := range tag {
					if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '@') {
						isAlphanum = false
						break
					}
				}
				if isAlphanum && len(tag) >= 2 {
					foundTags[strings.ToLower(tag)] = true
				}
			}
		}
	}
	for tag := range foundTags {
		if strings.Contains(tag, "ir") || strings.Contains(tag, "ad") || strings.Contains(tag, "geo") || tag == "cn" {
			t.Logf("Relevant Geosite Tag: %s", tag)
		}
	}
}

func TestGoogleComRoutingAndDNSResolution(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "passwall-google-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldBase := BaseConfig
	oldPersistBase := PersistBaseConfig
	oldState := StateFile
	oldPersistState := PersistStateFile
	oldRuntime := RuntimeConfig
	defer func() {
		BaseConfig = oldBase
		PersistBaseConfig = oldPersistBase
		StateFile = oldState
		PersistStateFile = oldPersistState
		RuntimeConfig = oldRuntime
	}()

	BaseConfig = filepath.Join(tmpDir, "config.json")
	PersistBaseConfig = filepath.Join(tmpDir, "persist_config.json")
	StateFile = filepath.Join(tmpDir, "state.json")
	PersistStateFile = filepath.Join(tmpDir, "persist_state.json")
	RuntimeConfig = filepath.Join(tmpDir, "runtime.json")

	if err := resetBaseConfig(); err != nil {
		t.Fatalf("resetBaseConfig failed: %v", err)
	}

	st := PanelState{
		ProxyMode:  "rule",
		ActiveNode: "node-google-test",
		DNS: DNSConfig{
			RemoteDNS:     "tcp://1.1.1.1",
			DirectDNS:     "223.5.5.5",
			QueryStrategy: "UseIPv4",
		},
		Nodes: []NodeProfile{
			{
				ID:       "node-google-test",
				Name:     "Fast Node",
				Protocol: "vless",
				Address:  "my-proxy.com",
				Port:     443,
				Outbound: map[string]interface{}{
					"tag":      "proxy",
					"protocol": "vless",
					"settings": map[string]interface{}{},
				},
			},
		},
	}
	if err := saveState(st); err != nil {
		t.Fatalf("saveState failed: %v", err)
	}

	// Test TPROXY mode
	if err := prepareRuntimeConfig(true); err != nil {
		t.Fatalf("prepareRuntimeConfig(tproxy) failed: %v", err)
	}

	data, err := os.ReadFile(RuntimeConfig)
	if err != nil {
		t.Fatalf("read runtime config failed: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal runtime config failed: %v", err)
	}

	// 1. Check DNS servers
	dnsCfg := cfg["dns"].(map[string]interface{})
	servers := dnsCfg["servers"].([]interface{})
	if len(servers) < 2 {
		t.Fatalf("expected at least 2 dns servers, got %d", len(servers))
	}

	// Verify no geosite:geolocation-!cn exists anywhere in DNS servers
	for i, s := range servers {
		if sMap, ok := s.(map[string]interface{}); ok {
			if doms, ok := sMap["domains"].([]interface{}); ok {
				for _, d := range doms {
					if d == "geosite:geolocation-!cn" {
						t.Fatalf("DNS server %d contains fatal tag geosite:geolocation-!cn", i)
					}
				}
			}
		}
	}

	// 2. Check dedicated dns-in inbound
	inbounds := cfg["inbounds"].([]interface{})
	hasDNSIn := false
	for _, inb := range inbounds {
		m := inb.(map[string]interface{})
		if m["tag"] == "dns-in" {
			hasDNSIn = true
			if m["port"].(float64) != 1053 {
				t.Errorf("expected dns-in port 1053, got %v", m["port"])
			}
			break
		}
	}
	if !hasDNSIn {
		t.Fatalf("dns-in inbound not found in inbounds")
	}

	// 3. Check routing rules
	routing := cfg["routing"].(map[string]interface{})
	rules := routing["rules"].([]interface{})

	hasDNSInRouting := false
	hasDirectDomestic := false
	hasFallbackProxy := false

	for _, r := range rules {
		rm := r.(map[string]interface{})
		// Check dns-in rule
		if inTags, ok := rm["inboundTag"].([]interface{}); ok {
			for _, tag := range inTags {
				if tag == "dns-in" && rm["outboundTag"] == "dns-out" {
					hasDNSInRouting = true
				}
			}
		}
		// Check direct domestic rule
		if doms, ok := rm["domain"].([]interface{}); ok {
			for _, d := range doms {
				if d == "domain:ir" || d == "geosite:ir" {
					if rm["outboundTag"] == "direct" {
						hasDirectDomestic = true
					}
				}
			}
		}
		// Check fallthrough defaultOutbound rule
		if rm["network"] == "tcp,udp" && rm["outboundTag"] == "proxy" {
			hasFallbackProxy = true
		}
	}

	if !hasDNSInRouting {
		t.Errorf("dns-in routing rule to dns-out not found")
	}
	if !hasDirectDomestic {
		t.Errorf("domestic routing rule to direct outbound not found")
	}
	if !hasFallbackProxy {
		t.Errorf("fallthrough rule routing to proxy outbound (for google.com) not found")
	}

	// 4. Test when no nodes are imported or mode is direct: fallback must safely be direct
	st.Nodes = nil
	st.ActiveNode = ""
	_ = saveState(st)
	if err := prepareRuntimeConfig(false); err != nil {
		t.Fatalf("prepareRuntimeConfig(redirect without nodes) failed: %v", err)
	}

	dataNoNode, _ := os.ReadFile(RuntimeConfig)
	var cfgNoNode map[string]interface{}
	_ = json.Unmarshal(dataNoNode, &cfgNoNode)

	routingNoNode := cfgNoNode["routing"].(map[string]interface{})
	rulesNoNode := routingNoNode["rules"].([]interface{})
	lastRule := rulesNoNode[len(rulesNoNode)-1].(map[string]interface{})
	if lastRule["outboundTag"] != "direct" {
		t.Errorf("expected fallthrough outbound to be direct when no nodes are imported, got %v", lastRule["outboundTag"])
	}
}

func TestWebUIGeoTabExists(t *testing.T) {
	// Verify Geo Rules tab and panel elements exist in dashboardHTML
	checks := []string{
		`id="t-geo" onclick="showTab('geo')">Geo Rules</div>`,
		`id="p-geo" class="card hidden"`,
		`id="geoBypassIranChk"`,
		`id="geoBypassCNChk"`,
		`id="geoBlockAdsChk"`,
		`id="geoDirectDomains"`,
		`id="geoDirectIPs"`,
		`id="geoProxyDomains"`,
		`id="geoProxyIPs"`,
		`id="geoBlockDomains"`,
		`id="geoBlockIPs"`,
		`id="btnUpdateGeo"`,
		`id="geoIpUrlInput"`,
		`id="geoSiteUrlInput"`,
		`function loadGeo()`,
		`function saveGeo()`,
		`function updateGeoDatabases()`,
		`function setGeoPreset(`,
		`/api/geo`,
		`/api/geo/update`,
	}

	for _, str := range checks {
		if !strings.Contains(dashboardHTML, str) {
			t.Errorf("dashboardHTML missing expected element: %s", str)
		}
	}

	// Verify showTab handles "geo"
	if !strings.Contains(dashboardHTML, `"geo"`) || !strings.Contains(dashboardHTML, `name === "geo"`) {
		t.Errorf("showTab does not properly support 'geo' tab")
	}
}

func TestGeoConfigDefaultsAndLoadState(t *testing.T) {
	tmpDir := t.TempDir()
	origState := StateFile
	origPersist := PersistStateFile
	defer func() {
		StateFile = origState
		PersistStateFile = origPersist
	}()

	StateFile = filepath.Join(tmpDir, "state.json")
	PersistStateFile = filepath.Join(tmpDir, "persist_state.json")

	st := loadState()
	if !st.Geo.IsBypassIran() {
		t.Errorf("expected default IsBypassIran to be true")
	}
	if !st.Geo.IsBypassCN() {
		t.Errorf("expected default IsBypassCN to be true")
	}
	if !st.Geo.IsBlockAds() {
		t.Errorf("expected default IsBlockAds to be true")
	}
	if st.Geo.DirectDomains == nil || len(st.Geo.DirectDomains) != 0 {
		t.Errorf("expected empty non-nil DirectDomains slice")
	}
	if st.Geo.DirectIPs == nil || len(st.Geo.DirectIPs) != 0 {
		t.Errorf("expected empty non-nil DirectIPs slice")
	}
	if st.Geo.ProxyDomains == nil || len(st.Geo.ProxyDomains) != 0 {
		t.Errorf("expected empty non-nil ProxyDomains slice")
	}
	if st.Geo.ProxyIPs == nil || len(st.Geo.ProxyIPs) != 0 {
		t.Errorf("expected empty non-nil ProxyIPs slice")
	}
	if st.Geo.BlockDomains == nil || len(st.Geo.BlockDomains) != 0 {
		t.Errorf("expected empty non-nil BlockDomains slice")
	}
	if st.Geo.BlockIPs == nil || len(st.Geo.BlockIPs) != 0 {
		t.Errorf("expected empty non-nil BlockIPs slice")
	}
	if !strings.Contains(st.Geo.GeoIPURL, "geoip.dat") {
		t.Errorf("expected default GeoIPURL containing geoip.dat, got %s", st.Geo.GeoIPURL)
	}
	if !strings.Contains(st.Geo.GeoSiteURL, "geosite.dat") {
		t.Errorf("expected default GeoSiteURL containing geosite.dat, got %s", st.Geo.GeoSiteURL)
	}
}

func TestApiGeoGetAndPost(t *testing.T) {
	tmpDir := t.TempDir()
	origState := StateFile
	origPersist := PersistStateFile
	origBase := BaseConfig
	origRuntime := RuntimeConfig
	origAsset := AssetDir
	defer func() {
		StateFile = origState
		PersistStateFile = origPersist
		BaseConfig = origBase
		RuntimeConfig = origRuntime
		AssetDir = origAsset
	}()

	StateFile = filepath.Join(tmpDir, "state.json")
	PersistStateFile = filepath.Join(tmpDir, "persist_state.json")
	BaseConfig = filepath.Join(tmpDir, "config.json")
	RuntimeConfig = filepath.Join(tmpDir, "runtime.json")
	AssetDir = filepath.Join(tmpDir, "bin")
	_ = os.MkdirAll(AssetDir, 0755)
	_ = os.WriteFile(BaseConfig, []byte(DefaultBaseConfigJSON), 0644)

	mux := http.NewServeMux()
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
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		http.Error(w, "GET or POST required", http.StatusMethodNotAllowed)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// 1. GET /api/geo
	resp, err := http.Get(server.URL + "/api/geo")
	if err != nil {
		t.Fatalf("GET /api/geo failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	var getRes map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&getRes)
	if getRes["bypass_iran"] != true || getRes["bypass_cn"] != true || getRes["block_ads"] != true {
		t.Errorf("expected default booleans to be true, got %v", getRes)
	}

	// 2. POST /api/geo with custom settings
	bFalse := false
	postBody := map[string]interface{}{
		"bypass_iran":    true,
		"bypass_cn":      bFalse,
		"block_ads":      bFalse,
		"direct_domains": []string{"custom-direct.com", "geosite:category-tech-ir"},
		"direct_ips":     []string{"192.168.10.0/24", "geoip:ir"},
		"proxy_domains":  []string{"geosite:google", "blocked-service.com"},
		"proxy_ips":      []string{"geoip:telegram", "91.108.4.0/22"},
		"block_domains":  []string{"tracker.test", "ads.example.com"},
		"block_ips":      []string{"198.51.100.44"},
		"geoip_url":      "https://example.com/geoip.dat",
		"geosite_url":    "https://example.com/geosite.dat",
	}
	bodyBytes, _ := json.Marshal(postBody)
	postResp, err := http.Post(server.URL+"/api/geo", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("POST /api/geo failed: %v", err)
	}
	defer postResp.Body.Close()
	if postResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on POST, got %d", postResp.StatusCode)
	}

	// 3. Verify state updated
	stUpdated := loadState()
	if !stUpdated.Geo.IsBypassIran() {
		t.Errorf("expected IsBypassIran to be true")
	}
	if stUpdated.Geo.IsBypassCN() {
		t.Errorf("expected IsBypassCN to be false")
	}
	if stUpdated.Geo.IsBlockAds() {
		t.Errorf("expected IsBlockAds to be false")
	}
	if len(stUpdated.Geo.DirectDomains) != 2 || stUpdated.Geo.DirectDomains[0] != "custom-direct.com" {
		t.Errorf("unexpected DirectDomains: %v", stUpdated.Geo.DirectDomains)
	}
	if len(stUpdated.Geo.ProxyDomains) != 2 || stUpdated.Geo.ProxyDomains[0] != "geosite:google" {
		t.Errorf("unexpected ProxyDomains: %v", stUpdated.Geo.ProxyDomains)
	}
	if len(stUpdated.Geo.BlockDomains) != 2 || stUpdated.Geo.BlockDomains[0] != "tracker.test" {
		t.Errorf("unexpected BlockDomains: %v", stUpdated.Geo.BlockDomains)
	}
	if stUpdated.Geo.GeoIPURL != "https://example.com/geoip.dat" {
		t.Errorf("unexpected GeoIPURL: %s", stUpdated.Geo.GeoIPURL)
	}
}

func TestPrepareRuntimeConfigGeoRulesCustomization(t *testing.T) {
	tmpDir := t.TempDir()
	origState := StateFile
	origPersist := PersistStateFile
	origBase := BaseConfig
	origRuntime := RuntimeConfig
	defer func() {
		StateFile = origState
		PersistStateFile = origPersist
		BaseConfig = origBase
		RuntimeConfig = origRuntime
	}()

	StateFile = filepath.Join(tmpDir, "state.json")
	PersistStateFile = filepath.Join(tmpDir, "persist_state.json")
	BaseConfig = filepath.Join(tmpDir, "config.json")
	RuntimeConfig = filepath.Join(tmpDir, "runtime.json")

	_ = os.WriteFile(BaseConfig, []byte(DefaultBaseConfigJSON), 0644)

	bFalse := false
	bTrue := true
	st := PanelState{
		ProxyMode:  "rule",
		ActiveNode: "node-1",
		Nodes: []NodeProfile{
			{
				ID:       "node-1",
				Name:     "Test Node",
				Protocol: "vless",
				Address:  "vpn.example.com",
				Port:     443,
			},
		},
		DNS: DNSConfig{
			RemoteDNS:     "tcp://1.1.1.1",
			DirectDNS:     "1.1.1.1",
			QueryStrategy: "UseIPv4",
		},
		Geo: GeoConfig{
			BypassIran:    &bTrue,
			BypassCN:      &bFalse, // China bypass disabled
			BlockAds:      &bFalse, // Ad block disabled
			DirectDomains: []string{"custom-direct.org"},
			DirectIPs:     []string{"10.50.0.0/16"},
			ProxyDomains:  []string{"force-proxy.org"},
			ProxyIPs:      []string{"93.184.216.34"},
			BlockDomains:  []string{"custom-blocked.com"},
			BlockIPs:      []string{"198.51.100.88"},
		},
	}
	if err := saveState(st); err != nil {
		t.Fatalf("saveState failed: %v", err)
	}

	if err := prepareRuntimeConfig(true); err != nil {
		t.Fatalf("prepareRuntimeConfig failed: %v", err)
	}

	raw, err := os.ReadFile(RuntimeConfig)
	if err != nil {
		t.Fatalf("read runtime config failed: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal runtime config failed: %v", err)
	}

	// Verify DNS direct resolution includes custom-direct.org and does NOT include geosite:cn
	dnsCfg := cfg["dns"].(map[string]interface{})
	servers := dnsCfg["servers"].([]interface{})
	directServer := servers[0].(map[string]interface{})
	directDoms := directServer["domains"].([]interface{})
	hasCustomDirectDNS := false
	hasCNDNS := false
	for _, d := range directDoms {
		if d == "custom-direct.org" {
			hasCustomDirectDNS = true
		}
		if d == "geosite:cn" {
			hasCNDNS = true
		}
	}
	if !hasCustomDirectDNS {
		t.Errorf("expected custom-direct.org in direct DNS server domains: %v", directDoms)
	}
	if hasCNDNS {
		t.Errorf("geosite:cn should not be in direct DNS when BypassCN is false: %v", directDoms)
	}

	// Verify routing rules
	routing := cfg["routing"].(map[string]interface{})
	rules := routing["rules"].([]interface{})

	foundCustomDirectDom := false
	foundCustomDirectIP := false
	foundForceProxyDom := false
	foundForceProxyIP := false
	foundCustomBlockDom := false
	foundCustomBlockIP := false
	foundDefaultAds := false
	foundCNRoute := false

	for _, r := range rules {
		rm := r.(map[string]interface{})
		tag := rm["outboundTag"]
		if doms, ok := rm["domain"].([]interface{}); ok {
			for _, d := range doms {
				if d == "custom-direct.org" && tag == "direct" {
					foundCustomDirectDom = true
				}
				if d == "force-proxy.org" && tag == "proxy" {
					foundForceProxyDom = true
				}
				if d == "custom-blocked.com" && tag == "block" {
					foundCustomBlockDom = true
				}
				if d == "geosite:category-ads-all" {
					foundDefaultAds = true
				}
				if d == "geosite:cn" {
					foundCNRoute = true
				}
			}
		}
		if ips, ok := rm["ip"].([]interface{}); ok {
			for _, ip := range ips {
				if ip == "10.50.0.0/16" && tag == "direct" {
					foundCustomDirectIP = true
				}
				if ip == "93.184.216.34" && tag == "proxy" {
					foundForceProxyIP = true
				}
				if ip == "198.51.100.88" && tag == "block" {
					foundCustomBlockIP = true
				}
			}
		}
	}

	if !foundCustomDirectDom {
		t.Errorf("expected custom-direct.org routed to direct outbound")
	}
	if !foundCustomDirectIP {
		t.Errorf("expected 10.50.0.0/16 routed to direct outbound")
	}
	if !foundForceProxyDom {
		t.Errorf("expected force-proxy.org routed to proxy outbound")
	}
	if !foundForceProxyIP {
		t.Errorf("expected 93.184.216.34 routed to proxy outbound")
	}
	if !foundCustomBlockDom {
		t.Errorf("expected custom-blocked.com routed to block outbound")
	}
	if !foundCustomBlockIP {
		t.Errorf("expected 198.51.100.88 routed to block outbound")
	}
	if foundDefaultAds {
		t.Errorf("geosite:category-ads-all should not be present when BlockAds is false")
	}
	if foundCNRoute {
		t.Errorf("geosite:cn should not be in routing rules when BypassCN is false")
	}
}

func TestGetGeoAssetInfoAndFormatBytes(t *testing.T) {
	// 1. Test formatBytes
	if fb := formatBytes(500); fb != "500 B" {
		t.Errorf("expected '500 B', got %s", fb)
	}
	if fb := formatBytes(2048); fb != "2.00 KB" {
		t.Errorf("expected '2.00 KB', got %s", fb)
	}
	if fb := formatBytes(1048576 * 3); fb != "3.00 MB" {
		t.Errorf("expected '3.00 MB', got %s", fb)
	}

	// 2. Test getGeoAssetInfo with non-existent assets
	tmpDir := t.TempDir()
	origAsset := AssetDir
	defer func() { AssetDir = origAsset }()
	AssetDir = tmpDir

	infoNone := getGeoAssetInfo()
	if infoNone.GeoIP.Exists || infoNone.GeoSite.Exists {
		t.Errorf("expected both assets not to exist in empty temp dir")
	}

	// 3. Test with mock files
	geoipDummy := make([]byte, 2048)
	geositeDummy := make([]byte, 4096)
	_ = os.WriteFile(filepath.Join(tmpDir, "geoip.dat"), geoipDummy, 0644)
	_ = os.WriteFile(filepath.Join(tmpDir, "geosite.dat"), geositeDummy, 0644)

	infoExists := getGeoAssetInfo()
	if !infoExists.GeoIP.Exists || infoExists.GeoIP.SizeBytes != 2048 {
		t.Errorf("expected geoip.dat to exist with size 2048: %+v", infoExists.GeoIP)
	}
	if !infoExists.GeoSite.Exists || infoExists.GeoSite.SizeBytes != 4096 {
		t.Errorf("expected geosite.dat to exist with size 4096: %+v", infoExists.GeoSite)
	}
}

func TestDownloadAndApiGeoUpdate(t *testing.T) {
	tmpDir := t.TempDir()
	origState := StateFile
	origPersist := PersistStateFile
	origAsset := AssetDir
	defer func() {
		StateFile = origState
		PersistStateFile = origPersist
		AssetDir = origAsset
	}()

	StateFile = filepath.Join(tmpDir, "state.json")
	PersistStateFile = filepath.Join(tmpDir, "persist_state.json")
	AssetDir = filepath.Join(tmpDir, "bin")
	_ = os.MkdirAll(AssetDir, 0755)

	// Mock file server serving valid test geo data (>1KB)
	mockIPData := make([]byte, 4096)
	for i := range mockIPData {
		mockIPData[i] = 0xAA
	}
	mockSiteData := make([]byte, 8192)
	for i := range mockSiteData {
		mockSiteData[i] = 0xBB
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/geoip.dat":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(mockIPData)
		case "/geosite.dat":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(mockSiteData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Update geo assets using server URLs
	err := updateGeoAssets(server.URL+"/geoip.dat", server.URL+"/geosite.dat")
	if err != nil {
		t.Fatalf("updateGeoAssets failed: %v", err)
	}

	// Verify files downloaded
	ipBytes, err := os.ReadFile(filepath.Join(AssetDir, "geoip.dat"))
	if err != nil || len(ipBytes) != 4096 {
		t.Fatalf("geoip.dat not downloaded properly, size: %d, err: %v", len(ipBytes), err)
	}

	siteBytes, err := os.ReadFile(filepath.Join(AssetDir, "geosite.dat"))
	if err != nil || len(siteBytes) != 8192 {
		t.Fatalf("geosite.dat not downloaded properly, size: %d, err: %v", len(siteBytes), err)
	}

	// Verify state saved with last_geo_update
	st := loadState()
	if st.Geo.LastGeoUpdate == "" {
		t.Errorf("expected LastGeoUpdate timestamp to be set")
	}
	if st.Geo.GeoIPURL != server.URL+"/geoip.dat" {
		t.Errorf("unexpected GeoIPURL: %s", st.Geo.GeoIPURL)
	}
}

func TestApiNodesEditAction(t *testing.T) {
	tmpDir := t.TempDir()
	origState := StateFile
	origPersist := PersistStateFile
	defer func() {
		StateFile = origState
		PersistStateFile = origPersist
		invalidateStateCache()
	}()

	StateFile = filepath.Join(tmpDir, "state.json")
	PersistStateFile = filepath.Join(tmpDir, "persist_state.json")
	invalidateStateCache()

	node, err := parseShareURI("vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none&security=reality&sni=orig.sni.com&fp=chrome&pbk=12345&sid=abcdef&type=tcp#TestNode", "manual")
	if err != nil {
		t.Fatalf("failed to parse initial share URI: %v", err)
	}
	st := loadState()
	st.Nodes = []NodeProfile{node}
	st.ActiveNode = node.ID
	if err := saveState(st); err != nil {
		t.Fatalf("failed to save initial state: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/nodes", func(w http.ResponseWriter, r *http.Request) {
		st := loadState()
		var req struct {
			Action  string `json:"action"`
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
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// 1. Edit Name, Address, Port, SNI
	editBody := map[string]interface{}{
		"action":  "edit",
		"id":      node.ID,
		"name":    "Updated-Node-Alias",
		"address": "new-server.org",
		"port":    8443,
		"sni":     "new.sni.com",
	}
	bodyBytes, _ := json.Marshal(editBody)
	req := httptest.NewRequest(http.MethodPost, "/api/nodes", bytes.NewReader(bodyBytes))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on node edit, got %d: %s", rr.Code, rr.Body.String())
	}

	stAfter := loadState()
	if len(stAfter.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(stAfter.Nodes))
	}
	updated := stAfter.Nodes[0]
	if updated.Name != "Updated-Node-Alias" {
		t.Errorf("expected updated name, got %s", updated.Name)
	}
	if updated.Address != "new-server.org" {
		t.Errorf("expected updated address, got %s", updated.Address)
	}
	if updated.Port != 8443 {
		t.Errorf("expected updated port 8443, got %d", updated.Port)
	}

	settings, _ := updated.Outbound["settings"].(map[string]interface{})
	vnext, _ := settings["vnext"].([]interface{})
	vObj, _ := vnext[0].(map[string]interface{})
	if vObj["address"] != "new-server.org" || vObj["port"] != 8443 {
		t.Errorf("expected outbound vnext to be updated, got: %v", vObj)
	}

	ss, _ := updated.Outbound["streamSettings"].(map[string]interface{})
	reality, _ := ss["realitySettings"].(map[string]interface{})
	if reality["serverName"] != "new.sni.com" {
		t.Errorf("expected reality serverName to be updated, got: %v", reality)
	}

	// 2. Edit non-existent node returns 404
	badBody := map[string]interface{}{
		"action": "edit",
		"id":     "non-existent-id",
		"name":   "Bad",
	}
	badBytes, _ := json.Marshal(badBody)
	reqBad := httptest.NewRequest(http.MethodPost, "/api/nodes", bytes.NewReader(badBytes))
	rrBad := httptest.NewRecorder()
	mux.ServeHTTP(rrBad, reqBad)
	if rrBad.Code != http.StatusNotFound {
		t.Errorf("expected 404 for missing node, got %d", rrBad.Code)
	}
}

func TestApiLogsDownload(t *testing.T) {
	tmpDir := t.TempDir()
	origLog := LogFile
	defer func() { LogFile = origLog }()

	LogFile = filepath.Join(tmpDir, "test.log")
	logContent := "2026-11-20 00:00:01 [info] passwall started\n2026-11-20 00:00:02 [info] connected to proxy\n"
	if err := os.WriteFile(LogFile, []byte(logContent), 0644); err != nil {
		t.Fatalf("failed to write mock log: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
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
		data, _ := os.ReadFile(LogFile)
		_, _ = w.Write(data)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/logs?download=1", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}
	disp := rr.Header().Get("Content-Disposition")
	if !strings.Contains(disp, "attachment; filename=\"passwall-runtime-") {
		t.Errorf("unexpected Content-Disposition header: %s", disp)
	}
	if rr.Body.String() != logContent {
		t.Errorf("downloaded logs mismatch: got %q, want %q", rr.Body.String(), logContent)
	}
}

func TestApiStatusResourceMetricsAndBattery(t *testing.T) {
	tmpDir := t.TempDir()
	origState := StateFile
	defer func() {
		StateFile = origState
		invalidateStateCache()
	}()
	StateFile = filepath.Join(tmpDir, "state.json")
	invalidateStateCache()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
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
			"running":        true,
			"daemon_pid":     daemonPID,
			"battery_pct":    batPct,
			"battery_status": batStatus,
			"module_pid":     daemonPID,
			"module_cpu":     modCPU,
			"module_ram":     modRAMBytes,
			"module_ram_str": modRAMStr,
			"xray_pid":       currentXrayPID,
			"xray_cpu":       xrayCPU,
			"xray_ram":       xrayRAMBytes,
			"xray_ram_str":   xrayRAMStr,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}

	var res map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}

	if _, ok := res["battery_pct"]; !ok {
		t.Error("expected battery_pct field in status response")
	}
	if _, ok := res["module_cpu"]; !ok {
		t.Error("expected module_cpu field in status response")
	}
	if _, ok := res["module_ram_str"]; !ok {
		t.Error("expected module_ram_str field in status response")
	}
	if _, ok := res["xray_cpu"]; !ok {
		t.Error("expected xray_cpu field in status response")
	}
	if _, ok := res["xray_ram_str"]; !ok {
		t.Error("expected xray_ram_str field in status response")
	}
}

func TestWriteSysctlOptimization(t *testing.T) {
	tmpDir := t.TempDir()
	sysctlPath := filepath.Join(tmpDir, "ip_forward")

	writeSysctl(sysctlPath, "1")
	data, err := os.ReadFile(sysctlPath)
	if err != nil || strings.TrimSpace(string(data)) != "1" {
		t.Fatalf("expected initial write to be 1, got %s, err %v", string(data), err)
	}

	stat1, err := os.Stat(sysctlPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}

	time.Sleep(20 * time.Millisecond)

	writeSysctl(sysctlPath, "1")
	stat2, err := os.Stat(sysctlPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if !stat1.ModTime().Equal(stat2.ModTime()) {
		t.Errorf("expected writeSysctl with identical value to skip write, modtime changed from %v to %v", stat1.ModTime(), stat2.ModTime())
	}

	writeSysctl(sysctlPath, "0")
	data2, _ := os.ReadFile(sysctlPath)
	if strings.TrimSpace(string(data2)) != "0" {
		t.Errorf("expected updated value 0, got %s", string(data2))
	}
}

func TestWebUIStatusTabAndEditModalElements(t *testing.T) {
	checks := []string{
		`id="t-status" onclick="showTab('status')">Status</div>`,
		`id="p-status" class="card"`,
		`id="statBattery"`,
		`id="statModule"`,
		`id="statXray"`,
		`id="statCardBattery"`,
		`id="statCardModuleCPU"`,
		`id="statCardXrayCPU"`,
		`id="nodeEditModal" class="modal-bg hidden"`,
		`.hidden{display:none !important}`,
		`.modal-bg.hidden{display:none !important}`,
		`m.style.display = "none"`,
		`m.style.display = "flex"`,
		`id="editNodeName"`,
		`id="editNodeAddress"`,
		`id="editNodePort"`,
		`function openEditNode(`,
		`function closeEditNode()`,
		`function saveEditNode()`,
		`function downloadLogs()`,
		`document.addEventListener("visibilitychange"`,
		`Rule`,
	}

	for _, str := range checks {
		if !strings.Contains(dashboardHTML, str) {
			t.Errorf("dashboardHTML missing expected element: %s", str)
		}
	}
}

func setupIsolatedTestEnv(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	origBaseDir := BaseDir
	origBase := BaseConfig
	origPersistBase := PersistBaseConfig
	origState := StateFile
	origPersistState := PersistStateFile
	origPersistDir := PersistDir
	origRuntime := RuntimeConfig
	origXray := XrayBin

	t.Cleanup(func() {
		BaseDir = origBaseDir
		BaseConfig = origBase
		PersistBaseConfig = origPersistBase
		StateFile = origState
		PersistStateFile = origPersistState
		PersistDir = origPersistDir
		RuntimeConfig = origRuntime
		XrayBin = origXray
		invalidateStateCache()
		invalidateModuleVersion()
		invalidateXrayVersion()
	})

	BaseDir = filepath.Join(tmpDir, "mod")
	PersistDir = filepath.Join(tmpDir, "persist")
	BaseConfig = filepath.Join(BaseDir, "config", "config.json")
	PersistBaseConfig = filepath.Join(PersistDir, "config.json")
	StateFile = filepath.Join(BaseDir, "config", "state.json")
	PersistStateFile = filepath.Join(PersistDir, "state.json")
	RuntimeConfig = filepath.Join(tmpDir, "runtime.json")
	XrayBin = "/nonexistent/xray"

	_ = os.MkdirAll(filepath.Dir(BaseConfig), 0755)
	_ = os.MkdirAll(PersistDir, 0755)
	_ = os.WriteFile(BaseConfig, []byte(DefaultBaseConfigJSON), 0644)
	_ = os.WriteFile(PersistBaseConfig, []byte(DefaultBaseConfigJSON), 0644)
	invalidateStateCache()
	return tmpDir
}

func TestBackupAndRestoreAPIAndBundle(t *testing.T) {
	setupIsolatedTestEnv(t)

	// 1. Populate non-default state & custom base config
	bypassIranFalse := false
	node, err := parseShareURI("vless://11111111-2222-3333-4444-555555555555@vpn.example.org:80?type=ws&security=none&path=%2Fws#PlainWS", "manual")
	if err != nil {
		t.Fatalf("parseShareURI failed: %v", err)
	}
	st := PanelState{
		ProxyMode:          "global",
		ActiveNode:         node.ID,
		SubURL:             "https://sub.example.org/feed",
		SubInsecure:        true,
		AutoUpdateHours:    12,
		LastSubUpdate:      "2026-11-25 10:00",
		AppFilterMode:      "proxy",
		SelectedUIDs:       []int{10101, 10202},
		LocalhostProxy:     false,
		AllowInsecureVless: true,
		DNS: DNSConfig{
			RemoteDNS:     "https://dns.google/dns-query",
			DirectDNS:     "10.202.10.202",
			QueryStrategy: "UseIP",
		},
		Geo: GeoConfig{
			BypassIran:   &bypassIranFalse,
			ProxyDomains: []string{"geosite:openai"},
		},
		Nodes: []NodeProfile{node},
	}
	if err := saveState(st); err != nil {
		t.Fatalf("saveState failed: %v", err)
	}
	customCfg := `{"log":{"loglevel":"info"},"inbounds":[{"tag":"tproxy-in","listen":"0.0.0.0","port":12345,"protocol":"dokodemo-door"}],"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],"routing":{"rules":[{"type":"field","domain":["custom.org"],"outboundTag":"direct"}]}}`
	if err := os.WriteFile(BaseConfig, []byte(customCfg), 0644); err != nil {
		t.Fatalf("write BaseConfig failed: %v", err)
	}

	mux := buildWebMux()

	// 2. Export backup via GET /api/backup?download=1
	reqBk := httptest.NewRequest(http.MethodGet, "/api/backup?download=1", nil)
	rrBk := httptest.NewRecorder()
	mux.ServeHTTP(rrBk, reqBk)
	if rrBk.Code != http.StatusOK {
		t.Fatalf("GET /api/backup failed with %d: %s", rrBk.Code, rrBk.Body.String())
	}
	if disp := rrBk.Header().Get("Content-Disposition"); !strings.Contains(disp, "passwall-backup-") {
		t.Errorf("unexpected Content-Disposition: %q", disp)
	}
	backupBytes := rrBk.Body.Bytes()

	// 3. Wipe state and reset base config
	if err := resetBaseConfig(); err != nil {
		t.Fatalf("resetBaseConfig failed: %v", err)
	}
	_ = saveState(PanelState{ProxyMode: "direct", LocalhostProxy: true, Nodes: []NodeProfile{}})

	// 4. Restore backup via POST /api/restore
	reqRes := httptest.NewRequest(http.MethodPost, "/api/restore", bytes.NewReader(backupBytes))
	rrRes := httptest.NewRecorder()
	mux.ServeHTTP(rrRes, reqRes)
	if rrRes.Code != http.StatusOK {
		t.Fatalf("POST /api/restore failed with %d: %s", rrRes.Code, rrRes.Body.String())
	}

	restored := loadState()
	if restored.ProxyMode != "global" {
		t.Errorf("expected ProxyMode global, got %s", restored.ProxyMode)
	}
	if restored.LocalhostProxy != false {
		t.Errorf("expected LocalhostProxy false to be preserved")
	}
	if !restored.AllowInsecureVless {
		t.Errorf("expected AllowInsecureVless true to be preserved")
	}
	if len(restored.Nodes) != 1 || restored.Nodes[0].ID != node.ID {
		t.Errorf("expected restored node %s, got %+v", node.ID, restored.Nodes)
	}
	if restored.Geo.IsBypassIran() {
		t.Errorf("expected BypassIran false to be preserved")
	}
	if len(restored.Geo.ProxyDomains) != 1 || restored.Geo.ProxyDomains[0] != "geosite:openai" {
		t.Errorf("expected ProxyDomains preserved, got %+v", restored.Geo.ProxyDomains)
	}
	if len(restored.SelectedUIDs) != 2 || restored.SelectedUIDs[1] != 10202 {
		t.Errorf("expected SelectedUIDs preserved, got %v", restored.SelectedUIDs)
	}

	cfgBytes, err := os.ReadFile(BaseConfig)
	if err != nil || !strings.Contains(string(cfgBytes), "custom.org") {
		t.Errorf("expected custom BaseConfig to be restored, got: %s (err=%v)", string(cfgBytes), err)
	}
	persistCfgBytes, err := os.ReadFile(PersistBaseConfig)
	if err != nil || !strings.Contains(string(persistCfgBytes), "custom.org") {
		t.Errorf("expected PersistBaseConfig to be restored")
	}

	// 5. Also verify multipart/form-data upload and raw state.json restore & invalid payload errors
	_ = saveState(PanelState{ProxyMode: "rule", LocalhostProxy: true, Nodes: []NodeProfile{}})
	var mpBuf bytes.Buffer
	mw := multipart.NewWriter(&mpBuf)
	fw, err := mw.CreateFormFile("file", "backup.json")
	if err != nil {
		t.Fatalf("CreateFormFile failed: %v", err)
	}
	_, _ = fw.Write(backupBytes)
	_ = mw.Close()

	reqMp := httptest.NewRequest(http.MethodPost, "/api/restore", &mpBuf)
	reqMp.Header.Set("Content-Type", mw.FormDataContentType())
	rrMp := httptest.NewRecorder()
	mux.ServeHTTP(rrMp, reqMp)
	if rrMp.Code != http.StatusOK {
		t.Fatalf("multipart /api/restore failed with %d: %s", rrMp.Code, rrMp.Body.String())
	}
	if stAfter := loadState(); stAfter.ProxyMode != "global" || !stAfter.AllowInsecureVless {
		t.Errorf("multipart restore did not restore expected fields: %+v", stAfter)
	}

	// Invalid restore input returns 400
	reqBad := httptest.NewRequest(http.MethodPost, "/api/restore", strings.NewReader(`{"format":"unknown","version":99}`))
	rrBad := httptest.NewRecorder()
	mux.ServeHTTP(rrBad, reqBad)
	if rrBad.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid backup format, got %d", rrBad.Code)
	}
}

func TestVlessSecurityBypassHelpersAndRuntimeBridge(t *testing.T) {
	setupIsolatedTestEnv(t)

	// 1. Address classification matching Xray-core
	privateCases := []string{
		"127.0.0.1", "10.0.0.5", "172.16.10.1", "192.168.1.100", "169.254.1.1",
		"::1", "fc00::1", "fe80::1",
		"localhost", "mybox.local", "gateway.lan", "vpn.internal", "app.home.arpa", "myhost",
	}
	for _, addr := range privateCases {
		if !isPrivateOrLocalAddress(addr) {
			t.Errorf("expected %q to be treated as private/local address", addr)
		}
	}

	publicCases := []string{
		"1.2.3.4", "198.51.100.25", "2001:4860:4860::8888",
		"vpn.myserver.org", "cdn.cloudflare-site.net",
	}
	for _, addr := range publicCases {
		if isPrivateOrLocalAddress(addr) {
			t.Errorf("expected %q to require transport security (public address)", addr)
		}
	}

	// 2. Public plain VLESS WS node without TLS or encryption
	plainNode, err := parseShareURI("vless://b831381d-6324-4d53-ad4f-8cda48b30811@vpn.myserver.org:80?type=ws&security=none&path=%2Fws#PlainVless", "manual")
	if err != nil {
		t.Fatalf("parseShareURI failed: %v", err)
	}
	st := PanelState{
		ProxyMode:          "rule",
		ActiveNode:         plainNode.ID,
		AllowInsecureVless: false,
		LocalhostProxy:     true,
		Nodes:              []NodeProfile{plainNode},
	}
	_ = saveState(st)

	// Switcher OFF -> no bridge injected
	if err := prepareRuntimeConfig(true); err != nil {
		t.Fatalf("prepareRuntimeConfig failed: %v", err)
	}
	rawOff, _ := os.ReadFile(RuntimeConfig)
	var cfgOff map[string]interface{}
	_ = json.Unmarshal(rawOff, &cfgOff)
	for _, item := range cfgOff["inbounds"].([]interface{}) {
		inb := item.(map[string]interface{})
		if strings.HasPrefix(fmt.Sprintf("%v", inb["tag"]), "vless-plain-bridge-") {
			t.Fatalf("did not expect bridge inbound when AllowInsecureVless is false")
		}
	}

	// Switcher ON via API -> bridge injected cleanly without mutating saved NodeProfile
	mux := buildWebMux()
	reqSw := httptest.NewRequest(http.MethodPost, "/api/vless_insecure", strings.NewReader(`{"allow_insecure_vless":true}`))
	rrSw := httptest.NewRecorder()
	mux.ServeHTTP(rrSw, reqSw)
	if rrSw.Code != http.StatusOK {
		t.Fatalf("POST /api/vless_insecure failed: %d %s", rrSw.Code, rrSw.Body.String())
	}

	// Check /api/status reports both allow_insecure_vless and vless_insecure_needed
	reqSt := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rrSt := httptest.NewRecorder()
	mux.ServeHTTP(rrSt, reqSt)
	var stResp map[string]interface{}
	_ = json.Unmarshal(rrSt.Body.Bytes(), &stResp)
	if stResp["allow_insecure_vless"] != true || stResp["vless_insecure_needed"] != true {
		t.Errorf("unexpected status flags: allow=%v needed=%v", stResp["allow_insecure_vless"], stResp["vless_insecure_needed"])
	}

	if err := prepareRuntimeConfig(true); err != nil {
		t.Fatalf("prepareRuntimeConfig with bypass failed: %v", err)
	}
	rawOn, _ := os.ReadFile(RuntimeConfig)
	var cfgOn map[string]interface{}
	_ = json.Unmarshal(rawOn, &cfgOn)

	// Verify bridge inbound and proxy outbound rewrite
	var bridgeInbound map[string]interface{}
	for _, item := range cfgOn["inbounds"].([]interface{}) {
		inb := item.(map[string]interface{})
		if inb["tag"] == "vless-plain-bridge-0" {
			bridgeInbound = inb
			break
		}
	}
	if bridgeInbound == nil {
		t.Fatalf("expected vless-plain-bridge-0 inbound in runtime config")
	}
	bSettings := bridgeInbound["settings"].(map[string]interface{})
	if bSettings["address"] != "vpn.myserver.org" || int(bSettings["port"].(float64)) != 80 {
		t.Errorf("unexpected bridge target: %+v", bSettings)
	}
	bridgePort := int(bridgeInbound["port"].(float64))

	var proxyOb map[string]interface{}
	for _, item := range cfgOn["outbounds"].([]interface{}) {
		ob := item.(map[string]interface{})
		if ob["tag"] == "proxy" {
			proxyOb = ob
			break
		}
	}
	pVnext := proxyOb["settings"].(map[string]interface{})["vnext"].([]interface{})[0].(map[string]interface{})
	if pVnext["address"] != "127.0.0.1" || int(pVnext["port"].(float64)) != bridgePort {
		t.Errorf("expected proxy outbound rewritten to 127.0.0.1:%d, got %+v", bridgePort, pVnext)
	}
	pWS := proxyOb["streamSettings"].(map[string]interface{})["wsSettings"].(map[string]interface{})
	if pWS["host"] != "vpn.myserver.org" {
		t.Errorf("expected wsSettings.host preserved as vpn.myserver.org, got %v", pWS["host"])
	}

	// Verify first routing rule routes vless-plain-bridge-0 to direct
	rules := cfgOn["routing"].(map[string]interface{})["rules"].([]interface{})
	firstRule := rules[0].(map[string]interface{})
	if firstRule["outboundTag"] != "direct" {
		t.Errorf("expected first rule to route bridge to direct, got %+v", firstRule)
	}

	// Verify original saved NodeProfile was NOT mutated
	stSaved := loadState()
	origVnext := stSaved.Nodes[0].Outbound["settings"].(map[string]interface{})["vnext"].([]interface{})[0].(map[string]interface{})
	if origVnext["address"] != "vpn.myserver.org" {
		t.Errorf("saved node outbound was mutated! got %v", origVnext["address"])
	}

	// 3. Verify VLESS with encryption or TLS or private IP is NOT bridged even with switcher ON
	encNode, err := parseShareURI("vless://b831381d-6324-4d53-ad4f-8cda48b30811@vpn.myserver.org:80?encryption=mlkem768x25519plus.native.1rtt.abc&security=none#EncVless", "manual")
	if err != nil {
		t.Fatalf("parseShareURI encrypted vless failed: %v", err)
	}
	if _, _, _, needs := vlessOutboundNeedsSecurityBypass(encNode.Outbound); needs {
		t.Errorf("expected VLESS with mlkem768 encryption not to require security bypass")
	}
	privNode, _ := parseShareURI("vless://b831381d-6324-4d53-ad4f-8cda48b30811@192.168.1.50:80?security=none#PrivVless", "manual")
	if _, _, _, needs := vlessOutboundNeedsSecurityBypass(privNode.Outbound); needs {
		t.Errorf("expected VLESS on private IP 192.168.1.50 not to require security bypass")
	}
}

func TestFullNodeEditorCreateEditExportAndRawJSON(t *testing.T) {
	setupIsolatedTestEnv(t)
	mux := buildWebMux()

	// 1. Create a new VLESS + xhttp + Reality node from scratch using full_edit fields
	createPayload := `{
		"action": "create",
		"full_edit": true,
		"name": "FullVlessNode",
		"protocol": "vless",
		"address": "node1.example.org",
		"port": 443,
		"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
		"flow": "",
		"encryption": "none",
		"network": "xhttp",
		"host": "cdn.example.org",
		"path": "/xhttp-v1",
		"xhttp_mode": "packet-up",
		"security": "reality",
		"sni": "www.microsoft.com",
		"fp": "chrome",
		"pbk": "REALITY_PUB_KEY",
		"sid": "a1b2",
		"spx": "/spx",
		"activate": true
	}`
	reqCr := httptest.NewRequest(http.MethodPost, "/api/nodes", strings.NewReader(createPayload))
	rrCr := httptest.NewRecorder()
	mux.ServeHTTP(rrCr, reqCr)
	if rrCr.Code != http.StatusOK {
		t.Fatalf("create full node failed: %d %s", rrCr.Code, rrCr.Body.String())
	}
	var crResp map[string]interface{}
	_ = json.Unmarshal(rrCr.Body.Bytes(), &crResp)
	nodeID, _ := crResp["id"].(string)
	if nodeID == "" {
		t.Fatalf("expected created node id")
	}

	st := loadState()
	if len(st.Nodes) != 1 || st.ActiveNode != nodeID {
		t.Fatalf("expected 1 active node %s, got %+v", nodeID, st)
	}
	created := st.Nodes[0]
	ss := created.Outbound["streamSettings"].(map[string]interface{})
	if ss["network"] != "xhttp" || ss["security"] != "reality" {
		t.Errorf("unexpected streamSettings: %+v", ss)
	}
	xh := ss["xhttpSettings"].(map[string]interface{})
	if xh["path"] != "/xhttp-v1" || xh["host"] != "cdn.example.org" || xh["mode"] != "packet-up" {
		t.Errorf("unexpected xhttpSettings: %+v", xh)
	}

	// 2. Edit node protocol & transport via full_edit (convert to Trojan + gRPC + TLS)
	editPayload := fmt.Sprintf(`{
		"action": "edit",
		"full_edit": true,
		"id": %q,
		"name": "EditedTrojanNode",
		"protocol": "trojan",
		"address": "trojan.example.org",
		"port": 8443,
		"password": "super-secret-password",
		"network": "grpc",
		"service_name": "myGrpcSvc",
		"grpc_multi_mode": true,
		"grpc_authority": "auth.example.org",
		"security": "tls",
		"sni": "trojan.example.org",
		"fp": "firefox",
		"alpn": "h2,http/1.1",
		"allow_insecure": true
	}`, nodeID)
	reqEd := httptest.NewRequest(http.MethodPost, "/api/nodes", strings.NewReader(editPayload))
	rrEd := httptest.NewRecorder()
	mux.ServeHTTP(rrEd, reqEd)
	if rrEd.Code != http.StatusOK {
		t.Fatalf("full edit failed: %d %s", rrEd.Code, rrEd.Body.String())
	}

	st2 := loadState()
	edited := st2.Nodes[0]
	if edited.Protocol != "trojan" || edited.Address != "trojan.example.org" || edited.Port != 8443 {
		t.Errorf("unexpected edited node metadata: %+v", edited)
	}
	gs := edited.Outbound["streamSettings"].(map[string]interface{})["grpcSettings"].(map[string]interface{})
	if gs["serviceName"] != "myGrpcSvc" || gs["multiMode"] != true || gs["authority"] != "auth.example.org" {
		t.Errorf("unexpected grpcSettings: %+v", gs)
	}

	// 3. Export URI and parse_uri round-trip
	reqExp := httptest.NewRequest(http.MethodPost, "/api/nodes", strings.NewReader(fmt.Sprintf(`{"action":"export_uri","id":%q}`, nodeID)))
	rrExp := httptest.NewRecorder()
	mux.ServeHTTP(rrExp, reqExp)
	if rrExp.Code != http.StatusOK {
		t.Fatalf("export_uri failed: %d %s", rrExp.Code, rrExp.Body.String())
	}
	var expResp map[string]string
	_ = json.Unmarshal(rrExp.Body.Bytes(), &expResp)
	if !strings.HasPrefix(expResp["uri"], "trojan://super-secret-password@trojan.example.org:8443") {
		t.Errorf("unexpected exported URI: %s", expResp["uri"])
	}

	reqParse := httptest.NewRequest(http.MethodPost, "/api/nodes", strings.NewReader(fmt.Sprintf(`{"action":"parse_uri","uri":%q}`, expResp["uri"])))
	rrParse := httptest.NewRecorder()
	mux.ServeHTTP(rrParse, reqParse)
	if rrParse.Code != http.StatusOK {
		t.Fatalf("parse_uri failed: %d %s", rrParse.Code, rrParse.Body.String())
	}

	// 4. Edit via raw Outbound JSON (Hysteria2)
	rawEditPayload := fmt.Sprintf(`{
		"action": "edit",
		"id": %q,
		"name": "RawHy2",
		"outbound": {
			"protocol": "hysteria",
			"settings": {"version": 2, "address": "hy2.example.org", "port": 9443},
			"streamSettings": {
				"network": "hysteria",
				"security": "tls",
				"tlsSettings": {"serverName": "hy2.example.org", "alpn": ["h3"]},
				"hysteriaSettings": {"version": 2, "auth": "hy2pass"}
			}
		}
	}`, nodeID)
	reqRaw := httptest.NewRequest(http.MethodPost, "/api/nodes", strings.NewReader(rawEditPayload))
	rrRaw := httptest.NewRecorder()
	mux.ServeHTTP(rrRaw, reqRaw)
	if rrRaw.Code != http.StatusOK {
		t.Fatalf("raw outbound edit failed: %d %s", rrRaw.Code, rrRaw.Body.String())
	}
	st3 := loadState()
	if st3.Nodes[0].Protocol != "hysteria2" || st3.Nodes[0].Address != "hy2.example.org" || st3.Nodes[0].Port != 9443 {
		t.Errorf("raw outbound sync mismatch: %+v", st3.Nodes[0])
	}
}

func TestWebUINewFeaturesElements(t *testing.T) {
	checks := []string{
		`id="allowInsecureVlessChk"`,
		`id="vlessInsecureAlert"`,
		`function toggleAllowInsecureVless(`,
		`/api/vless_insecure`,
		`id="btnDownloadBackup"`,
		`id="restoreFileInput"`,
		`id="btnRestoreBackup"`,
		`function downloadBackup()`,
		`function restoreBackup()`,
		`/api/backup`,
		`/api/restore`,
		`id="btnNewNode"`,
		`id="editNodeProtocol"`,
		`id="editNodeUUID"`,
		`id="editNodeFlow"`,
		`id="editNodeVlessEncryption"`,
		`id="editNodeNetwork"`,
		`id="editNodeSecurity"`,
		`id="editNodeRealityPBK"`,
		`id="editNodeRawJSON"`,
		`function openCreateNode()`,
		`function setEditTab(`,
		`function duplicateEditNode()`,
		`id="dnsRedirectChk"`,
		`id="dnsRemoteStrategySel"`,
		`id="dnsDirectStrategySel"`,
		`id="geoDomainStrategySel"`,
		`id="geoDomainMatcherSel"`,
		`id="editNodeDomainStrategy"`,
		`function applyDNSUI(`,
	}
	for _, str := range checks {
		if !strings.Contains(dashboardHTML, str) {
			t.Errorf("dashboardHTML missing expected element: %s", str)
		}
	}
}

func TestPasswall2DirectAndRemoteQueryStrategies(t *testing.T) {
	tmpDir := t.TempDir()
	origBase := BaseConfig
	origPersistBase := PersistBaseConfig
	origState := StateFile
	origPersistState := PersistStateFile
	origRuntime := RuntimeConfig
	defer func() {
		BaseConfig = origBase
		PersistBaseConfig = origPersistBase
		StateFile = origState
		PersistStateFile = origPersistState
		RuntimeConfig = origRuntime
	}()

	BaseConfig = filepath.Join(tmpDir, "config.json")
	PersistBaseConfig = filepath.Join(tmpDir, "persist_config.json")
	StateFile = filepath.Join(tmpDir, "state.json")
	PersistStateFile = filepath.Join(tmpDir, "persist_state.json")
	RuntimeConfig = filepath.Join(tmpDir, "runtime.json")
	if err := os.WriteFile(BaseConfig, []byte(DefaultBaseConfigJSON), 0644); err != nil {
		t.Fatalf("write base config: %v", err)
	}

	testNode := NodeProfile{
		ID:       "n1",
		Name:     "Proxy1",
		Protocol: "vless",
		Address:  "vpn.example.com",
		Port:     443,
		Outbound: map[string]interface{}{
			"tag":      "proxy",
			"protocol": "vless",
			"settings": map[string]interface{}{
				"vnext": []interface{}{
					map[string]interface{}{"address": "vpn.example.com", "port": 443, "users": []interface{}{map[string]interface{}{"id": "uuid", "encryption": "none"}}},
				},
			},
			"streamSettings": map[string]interface{}{"network": "tcp", "security": "tls"},
		},
	}

	st := PanelState{
		ProxyMode:  "rule",
		ActiveNode: "n1",
		DNS: DNSConfig{
			RemoteDNS:           "https://1.1.1.1/dns-query",
			DirectDNS:           "10.202.10.202",
			DirectQueryStrategy: "UseIPv6",
			RemoteQueryStrategy: "UseIPv4",
		},
		Nodes: []NodeProfile{testNode},
	}
	if err := saveState(st); err != nil {
		t.Fatalf("saveState: %v", err)
	}
	if err := prepareRuntimeConfig(true); err != nil {
		t.Fatalf("prepareRuntimeConfig: %v", err)
	}

	raw, _ := os.ReadFile(RuntimeConfig)
	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal runtime config: %v", err)
	}

	dnsCfg := cfg["dns"].(map[string]interface{})
	if dnsCfg["queryStrategy"] != "UseIP" {
		t.Errorf("mixed direct=UseIPv6 + remote=UseIPv4 must yield top-level queryStrategy UseIP, got %v", dnsCfg["queryStrategy"])
	}
	servers := dnsCfg["servers"].([]interface{})
	directSrv := servers[0].(map[string]interface{})
	remoteSrv := servers[1].(map[string]interface{})
	directFallbackSrv := servers[2].(map[string]interface{})
	if directSrv["queryStrategy"] != "UseIPv6" {
		t.Errorf("expected direct server[0] queryStrategy UseIPv6, got %v", directSrv["queryStrategy"])
	}
	if remoteSrv["queryStrategy"] != "UseIPv4" {
		t.Errorf("expected remote server[1] queryStrategy UseIPv4, got %v", remoteSrv["queryStrategy"])
	}
	if directFallbackSrv["queryStrategy"] != "UseIPv6" {
		t.Errorf("expected direct fallback server[2] queryStrategy UseIPv6, got %v", directFallbackSrv["queryStrategy"])
	}

	outbounds := cfg["outbounds"].([]interface{})
	foundDirect := false
	for _, ob := range outbounds {
		m := ob.(map[string]interface{})
		if m["tag"] == "direct" {
			foundDirect = true
			sock := m["streamSettings"].(map[string]interface{})["sockopt"].(map[string]interface{})
			if sock["domainStrategy"] != "UseIPv6" {
				t.Errorf("expected direct outbound sockopt.domainStrategy UseIPv6, got %v", sock["domainStrategy"])
			}
		}
	}
	if !foundDirect {
		t.Fatal("direct outbound missing")
	}

	// Same strategy on both sides sets top-level to that shared strategy
	st.DNS.DirectQueryStrategy = "UseIPv6"
	st.DNS.RemoteQueryStrategy = "UseIPv6"
	_ = saveState(st)
	if err := prepareRuntimeConfig(true); err != nil {
		t.Fatalf("prepareRuntimeConfig UseIPv6/UseIPv6: %v", err)
	}
	raw, _ = os.ReadFile(RuntimeConfig)
	_ = json.Unmarshal(raw, &cfg)
	if cfg["dns"].(map[string]interface{})["queryStrategy"] != "UseIPv6" {
		t.Errorf("expected top-level queryStrategy UseIPv6 when both match, got %v", cfg["dns"].(map[string]interface{})["queryStrategy"])
	}

	// Legacy upgrade: only QueryStrategy set in state.json
	legacyPath := filepath.Join(tmpDir, "legacy_state.json")
	StateFile = legacyPath
	PersistStateFile = filepath.Join(tmpDir, "legacy_persist_state.json")
	if err := os.WriteFile(legacyPath, []byte(`{"dns":{"remote_dns":"tcp://8.8.8.8","direct_dns":"223.5.5.5","query_strategy":"UseIP"}}`), 0644); err != nil {
		t.Fatalf("write legacy state: %v", err)
	}
	legacyLoaded := loadState()
	if legacyLoaded.DNS.EffectiveDirectQueryStrategy() != "UseIP" || legacyLoaded.DNS.EffectiveRemoteQueryStrategy() != "UseIP" {
		t.Errorf("legacy QueryStrategy did not propagate: %+v", legacyLoaded.DNS)
	}
	if !legacyLoaded.DNS.IsDNSRedirect() {
		t.Errorf("expected DNSRedirect to default true for legacy state")
	}
}

func TestPasswall2DNSRedirectAndRoutingOptions(t *testing.T) {
	tmpDir := t.TempDir()
	origBase := BaseConfig
	origPersistBase := PersistBaseConfig
	origState := StateFile
	origPersistState := PersistStateFile
	origRuntime := RuntimeConfig
	defer func() {
		BaseConfig = origBase
		PersistBaseConfig = origPersistBase
		StateFile = origState
		PersistStateFile = origPersistState
		RuntimeConfig = origRuntime
	}()

	BaseConfig = filepath.Join(tmpDir, "config.json")
	PersistBaseConfig = filepath.Join(tmpDir, "persist_config.json")
	StateFile = filepath.Join(tmpDir, "state.json")
	PersistStateFile = filepath.Join(tmpDir, "persist_state.json")
	RuntimeConfig = filepath.Join(tmpDir, "runtime.json")
	_ = os.WriteFile(BaseConfig, []byte(DefaultBaseConfigJSON), 0644)

	boolFalse := false
	st := PanelState{
		ProxyMode: "rule",
		DNS: DNSConfig{
			DNSRedirect: &boolFalse,
		},
		Geo: GeoConfig{
			DomainStrategy: "IPOnDemand",
			DomainMatcher:  "linear",
		},
	}
	_ = saveState(st)
	if err := prepareRuntimeConfig(true); err != nil {
		t.Fatalf("prepareRuntimeConfig: %v", err)
	}

	raw, _ := os.ReadFile(RuntimeConfig)
	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	routing := cfg["routing"].(map[string]interface{})
	if routing["domainStrategy"] != "IPOnDemand" {
		t.Errorf("expected routing.domainStrategy IPOnDemand, got %v", routing["domainStrategy"])
	}
	if routing["domainMatcher"] != "linear" {
		t.Errorf("expected routing.domainMatcher linear, got %v", routing["domainMatcher"])
	}

	hasTproxy53DnsOut := false
	hasDnsInDnsOut := false
	for _, r := range routing["rules"].([]interface{}) {
		rm := r.(map[string]interface{})
		if rm["outboundTag"] == "dns-out" {
			if port, _ := rm["port"].(string); port == "53" {
				hasTproxy53DnsOut = true
			}
			if inb, ok := rm["inboundTag"].([]interface{}); ok && len(inb) == 1 && inb[0] == "dns-in" {
				hasDnsInDnsOut = true
			}
		}
	}
	if hasTproxy53DnsOut {
		t.Errorf("expected port 53 tproxy/socks -> dns-out rule to be omitted when dns_redirect=false")
	}
	if !hasDnsInDnsOut {
		t.Errorf("expected dns-in -> dns-out rule to remain even when dns_redirect=false")
	}

	// Re-enable DNSRedirect + AsIs + hybrid
	boolTrue := true
	st.DNS.DNSRedirect = &boolTrue
	st.Geo.DomainStrategy = "AsIs"
	st.Geo.DomainMatcher = "hybrid"
	_ = saveState(st)
	_ = prepareRuntimeConfig(true)

	raw, _ = os.ReadFile(RuntimeConfig)
	_ = json.Unmarshal(raw, &cfg)
	routing = cfg["routing"].(map[string]interface{})
	if routing["domainStrategy"] != "AsIs" || routing["domainMatcher"] != "hybrid" {
		t.Errorf("expected AsIs/hybrid, got %v / %v", routing["domainStrategy"], routing["domainMatcher"])
	}
	hasTproxy53DnsOut = false
	for _, r := range routing["rules"].([]interface{}) {
		rm := r.(map[string]interface{})
		if rm["outboundTag"] == "dns-out" && rm["port"] == "53" {
			hasTproxy53DnsOut = true
		}
	}
	if !hasTproxy53DnsOut {
		t.Errorf("expected port 53 dns-out rule when dns_redirect=true")
	}
}

func TestPasswall2APIsBackupAndSockoptDomainStrategy(t *testing.T) {
	tmpDir := t.TempDir()
	origState := StateFile
	origPersistState := PersistStateFile
	origBase := BaseConfig
	origPersistBase := PersistBaseConfig
	defer func() {
		StateFile = origState
		PersistStateFile = origPersistState
		BaseConfig = origBase
		PersistBaseConfig = origPersistBase
	}()

	StateFile = filepath.Join(tmpDir, "state.json")
	PersistStateFile = filepath.Join(tmpDir, "persist_state.json")
	BaseConfig = filepath.Join(tmpDir, "config.json")
	PersistBaseConfig = filepath.Join(tmpDir, "persist_config.json")
	_ = os.WriteFile(BaseConfig, []byte(DefaultBaseConfigJSON), 0644)

	mux := buildWebMux()

	// 1. Reject invalid DNS strategy
	rrBadDNS := httptest.NewRecorder()
	mux.ServeHTTP(rrBadDNS, httptest.NewRequest(http.MethodPost, "/api/dns", strings.NewReader(`{"direct_query_strategy":"BadVal"}`)))
	if rrBadDNS.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid direct_query_strategy, got %d", rrBadDNS.Code)
	}

	// 2. Save valid Passwall 2 DNS settings
	rrDNS := httptest.NewRecorder()
	mux.ServeHTTP(rrDNS, httptest.NewRequest(http.MethodPost, "/api/dns", strings.NewReader(`{
		"remote_dns":"https://dns.google/dns-query",
		"direct_dns":"77.88.8.8",
		"direct_query_strategy":"UseIP",
		"remote_query_strategy":"UseIPv6",
		"dns_redirect":false
	}`)))
	if rrDNS.Code != http.StatusOK {
		t.Fatalf("POST /api/dns failed: %d %s", rrDNS.Code, rrDNS.Body.String())
	}

	rrDNSGet := httptest.NewRecorder()
	mux.ServeHTTP(rrDNSGet, httptest.NewRequest(http.MethodGet, "/api/dns", nil))
	var dnsResp DNSConfig
	_ = json.Unmarshal(rrDNSGet.Body.Bytes(), &dnsResp)
	if dnsResp.DirectQueryStrategy != "UseIP" || dnsResp.RemoteQueryStrategy != "UseIPv6" || dnsResp.IsDNSRedirect() {
		t.Fatalf("unexpected GET /api/dns response: %+v", dnsResp)
	}

	// 3. Reject invalid Geo routing options
	rrBadGeo := httptest.NewRecorder()
	mux.ServeHTTP(rrBadGeo, httptest.NewRequest(http.MethodPost, "/api/geo", strings.NewReader(`{"domain_strategy":"BadStrategy"}`)))
	if rrBadGeo.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid domain_strategy, got %d", rrBadGeo.Code)
	}
	rrBadMatcher := httptest.NewRecorder()
	mux.ServeHTTP(rrBadMatcher, httptest.NewRequest(http.MethodPost, "/api/geo", strings.NewReader(`{"domain_matcher":"mph-only"}`)))
	if rrBadMatcher.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid domain_matcher, got %d", rrBadMatcher.Code)
	}

	// 4. Save valid DomainStrategy & DomainMatcher via /api/geo
	rrGeo := httptest.NewRecorder()
	mux.ServeHTTP(rrGeo, httptest.NewRequest(http.MethodPost, "/api/geo", strings.NewReader(`{
		"domain_strategy":"IPOnDemand",
		"domain_matcher":"linear"
	}`)))
	if rrGeo.Code != http.StatusOK {
		t.Fatalf("POST /api/geo failed: %d %s", rrGeo.Code, rrGeo.Body.String())
	}
	rrGeoGet := httptest.NewRecorder()
	mux.ServeHTTP(rrGeoGet, httptest.NewRequest(http.MethodGet, "/api/geo", nil))
	var geoResp map[string]interface{}
	_ = json.Unmarshal(rrGeoGet.Body.Bytes(), &geoResp)
	if geoResp["domain_strategy"] != "IPOnDemand" || geoResp["domain_matcher"] != "linear" {
		t.Fatalf("unexpected GET /api/geo domain options: %v", geoResp)
	}

	// 5. Create node with per-node sockopt.domainStrategy even for plain Shadowsocks, then clear it
	rrCreate := httptest.NewRecorder()
	mux.ServeHTTP(rrCreate, httptest.NewRequest(http.MethodPost, "/api/nodes", strings.NewReader(`{
		"action":"create",
		"full_edit":true,
		"name":"SS-Sockopt",
		"protocol":"shadowsocks",
		"address":"ss.example.org",
		"port":8388,
		"password":"secret",
		"ss_method":"aes-256-gcm",
		"network":"tcp",
		"security":"none",
		"sockopt_domain_strategy":"UseIPv4"
	}`)))
	if rrCreate.Code != http.StatusOK {
		t.Fatalf("create ss node failed: %d %s", rrCreate.Code, rrCreate.Body.String())
	}
	stAfterCreate := loadState()
	if len(stAfterCreate.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(stAfterCreate.Nodes))
	}
	createdNode := stAfterCreate.Nodes[0]
	sockDS := createdNode.Outbound["streamSettings"].(map[string]interface{})["sockopt"].(map[string]interface{})["domainStrategy"]
	if sockDS != "UseIPv4" {
		t.Errorf("expected sockopt.domainStrategy UseIPv4 on created node, got %v", sockDS)
	}

	// 6. Backup & Restore preserves all Passwall 2 fields
	rrBkp := httptest.NewRecorder()
	mux.ServeHTTP(rrBkp, httptest.NewRequest(http.MethodGet, "/api/backup", nil))
	if rrBkp.Code != http.StatusOK {
		t.Fatalf("backup failed: %d", rrBkp.Code)
	}
	// Reset state first
	_ = saveState(PanelState{ProxyMode: "direct"})
	rrRes := httptest.NewRecorder()
	mux.ServeHTTP(rrRes, httptest.NewRequest(http.MethodPost, "/api/restore", bytes.NewReader(rrBkp.Body.Bytes())))
	if rrRes.Code != http.StatusOK {
		t.Fatalf("restore failed: %d %s", rrRes.Code, rrRes.Body.String())
	}
	restored := loadState()
	if restored.DNS.DirectQueryStrategy != "UseIP" || restored.DNS.RemoteQueryStrategy != "UseIPv6" || restored.DNS.IsDNSRedirect() {
		t.Errorf("DNS settings not preserved after restore: %+v", restored.DNS)
	}
	if restored.Geo.EffectiveDomainStrategy() != "IPOnDemand" || restored.Geo.EffectiveDomainMatcher() != "linear" {
		t.Errorf("Geo domain strategy/matcher not preserved after restore: %+v", restored.Geo)
	}

	// Clear sockopt_domain_strategy back to Auto ("")
	clearDS := ""
	if err := applyNodeEditRequest(&restored.Nodes[0], NodeEditRequest{
		FullEdit:              true,
		Protocol:              "shadowsocks",
		Address:               "ss.example.org",
		Port:                  8388,
		Password:              "secret",
		SSMethod:              "aes-256-gcm",
		Network:               "tcp",
		Security:              "none",
		SockoptDomainStrategy: &clearDS,
	}); err != nil {
		t.Fatalf("clear sockopt_domain_strategy: %v", err)
	}
	if _, hasSS := restored.Nodes[0].Outbound["streamSettings"]; hasSS {
		t.Errorf("expected streamSettings to be cleaned up when clearing sockopt_domain_strategy on plain shadowsocks, got %v", restored.Nodes[0].Outbound["streamSettings"])
	}
}
