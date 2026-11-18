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
