package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
