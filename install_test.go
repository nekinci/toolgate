package main

import (
	"os"
	"strings"
	"testing"
)

func TestRenderSystemdIsolated(t *testing.T) {
	p := defaultPlan("linux", "isolated", "/home/me")
	u := renderSystemd(p)
	for _, want := range []string{
		"User=toolgate", "ProtectHome=yes", "ProtectSystem=strict", "NoNewPrivileges=yes",
		"ReadWritePaths=/var/lib/toolgate /var/lib/toolgate-outputs",
		"ExecStart=/usr/local/libexec/toolgate/toolgate serve -addr 127.0.0.1:7777 -data /var/lib/toolgate -key-store file",
		"WantedBy=multi-user.target", "UMask=0077",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
}

func TestRenderSystemdUser(t *testing.T) {
	p := defaultPlan("linux", "user", "/home/me")
	u := renderSystemd(p)
	if strings.Contains(u, "User=") || !strings.Contains(u, "WantedBy=default.target") || !strings.Contains(u, "-data /home/me/.toolgate") {
		t.Fatal(u)
	}
}

func TestSystemdQuote(t *testing.T) {
	if got := systemdQuote("/Library/Application Support/x"); got != `"/Library/Application Support/x"` {
		t.Fatal(got)
	}
	if got := systemdQuote(`a"b$c%d`); got != `"a\"b$$c%%d"` {
		t.Fatal(got)
	}
	if systemdQuote("/usr/bin") != "/usr/bin" {
		t.Fatal("plain word quoted")
	}
}

func TestRenderLaunchdIsolated(t *testing.T) {
	p := defaultPlan("darwin", "isolated", "/Users/me")
	x := renderLaunchd(p)
	for _, want := range []string{
		"<key>UserName</key><string>_toolgate</string>",
		"<string>/Library/Application Support/Toolgate</string>",
		"<key>HOME</key><string>/Library/Application Support/Toolgate</string>",
		"<string>file</string>", "<key>Umask</key><integer>63</integer>",
	} {
		if !strings.Contains(x, want) {
			t.Errorf("plist lacks %q", want)
		}
	}
}

func TestRenderLaunchdUserUsesKeychain(t *testing.T) {
	p := defaultPlan("darwin", "user", "/Users/me")
	p.OwnerHome = "/Users/me"
	x := renderLaunchd(p)
	if strings.Contains(x, "UserName") || !strings.Contains(x, "<string>keychain</string>") || !strings.Contains(x, "<key>HOME</key><string>/Users/me</string>") {
		t.Fatal(x)
	}
}

func TestXMLEscape(t *testing.T) {
	p := defaultPlan("darwin", "user", "/Users/a&b")
	p.OwnerHome = "/Users/a&b"
	if x := renderLaunchd(p); strings.Contains(x, "a&b") || !strings.Contains(x, "a&amp;b") {
		t.Fatal("unescaped &")
	}
}

func TestInstallStepsOrder(t *testing.T) {
	p := defaultPlan("linux", "isolated", "/root")
	p.From, p.Password, p.Owner, p.OwnerHome = "/tmp/export", "x", "me", "/home/me"
	var names []string
	for _, s := range buildSteps(p, true) {
		names = append(names, s.desc)
	}
	all := strings.Join(names, "\n")
	idx := func(sub string) int {
		i := strings.Index(all, sub)
		if i < 0 {
			t.Fatalf("missing step %q in\n%s", sub, all)
		}
		return i
	}
	// the user exists before its directories; the old service is stopped
	// before data moves; old data is deleted only after the migration step;
	// the service starts last.
	if !(idx("create system user") < idx("data directory") &&
		idx("stop the running service") < idx("migrate data") &&
		idx("migrate data") < idx("delete the old per-user data") &&
		idx("delete the old per-user data") < idx("start the service") &&
		idx("start the service") < idx("wait until")) {
		t.Fatalf("bad order:\n%s", all)
	}
}

func TestValidateExportRejectsIncomplete(t *testing.T) {
	if err := validateExport(t.TempDir()); err == nil {
		t.Fatal("empty export accepted")
	}
}

func TestLegacyLayoutKeptOnUpgrade(t *testing.T) {
	old := legacyPlan("darwin", "isolated", "/Users/me")
	if !old.Legacy || old.SvcUser != "_agentgw" || old.Data != "/Library/Application Support/AgentGateway" || old.Label != "dev.local.agent-gateway" {
		t.Fatalf("%+v", old)
	}
	if !strings.Contains(renderLaunchd(old), "<string>dev.local.agent-gateway</string>") {
		t.Fatal("legacy label not rendered")
	}
	if old.Link != "/usr/local/bin/toolgate" {
		t.Fatal("legacy install should get a toolgate link")
	}
	if legacyPlan("linux", "isolated", "/root").Unit != "" {
		t.Fatal("no legacy Linux layout expected")
	}
}

func TestEnvFallback(t *testing.T) {
	t.Setenv("TOOLGATE_X_TEST", "")
	t.Setenv("AGW_X_TEST", "old")
	if envOr("TOOLGATE_X_TEST", "d") != "old" {
		t.Fatal("AGW_ fallback")
	}
	t.Setenv("TOOLGATE_X_TEST", "new")
	if envOr("TOOLGATE_X_TEST", "d") != "new" {
		t.Fatal("TOOLGATE_ wins")
	}
}

func TestDefaultDataDirLegacy(t *testing.T) {
	h := t.TempDir()
	if defaultDataDir(h) != h+"/.toolgate" {
		t.Fatal("fresh home")
	}
	_ = os.Mkdir(h+"/.agent-gateway", 0o700)
	if defaultDataDir(h) != h+"/.agent-gateway" {
		t.Fatal("legacy dir not used")
	}
	_ = os.Mkdir(h+"/.toolgate", 0o700)
	if defaultDataDir(h) != h+"/.toolgate" {
		t.Fatal("new dir must win")
	}
}
