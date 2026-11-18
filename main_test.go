package main

import (
	"encoding/base64"
	"encoding/json"
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
