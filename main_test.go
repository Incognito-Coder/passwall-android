package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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

		hySet, _ := ss["hysteriaSettings"].(map[string]interface{})
		if hySet["auth"] != "mypassword" || hySet["version"] != 2 {
			t.Errorf("hysteria settings mismatch: %v", hySet)
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
	if st.DNS.DirectDNS != "223.5.5.5" {
		t.Errorf("expected default direct DNS 223.5.5.5, got %q", st.DNS.DirectDNS)
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
		directEntry := servers[1].(map[string]interface{})
		domains := directEntry["domains"].([]interface{})
		foundNodeDomain := false
		for _, d := range domains {
			if d == "myproxy.vpnserver.com" {
				foundNodeDomain = true
				break
			}
		}
		if !foundNodeDomain {
			t.Errorf("expected node domain in direct DNS domains, got: %v", domains)
		}

		// Verify routing rules: DNS intercepted, direct DNS routed direct, node domain routed direct
		routing := cfg["routing"].(map[string]interface{})
		rules := routing["rules"].([]interface{})
		foundDNSOut := false
		foundDirectDNSRule := false
		foundNodeDomainRule := false

		for _, r := range rules {
			rm := r.(map[string]interface{})
			if rm["outboundTag"] == "dns-out" {
				foundDNSOut = true
			}
			if ips, ok := rm["ip"].([]interface{}); ok {
				for _, ip := range ips {
					if ip == "10.202.10.202" && rm["outboundTag"] == "direct" {
						foundDirectDNSRule = true
					}
				}
			}
			if doms, ok := rm["domain"].([]interface{}); ok {
				for _, dom := range doms {
					if dom == "myproxy.vpnserver.com" && rm["outboundTag"] == "direct" {
						foundNodeDomainRule = true
					}
				}
			}
		}

		if !foundDNSOut {
			t.Error("expected port 53 dns-out interception rule")
		}
		if !foundDirectDNSRule {
			t.Error("expected direct DNS IP direct routing rule")
		}
		if !foundNodeDomainRule {
			t.Error("expected proxy node domain direct routing rule to prevent deadlock")
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

	propContent := "id=passwall-android\nversion=v1.2.1\nversionCode=121\n"
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

	if res["module_version"] != "v1.2.1" {
		t.Errorf("expected module_version v1.2.1, got %v", res["module_version"])
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
