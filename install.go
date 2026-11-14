package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// `toolgate install` sets the gateway up as a background service.
//
// Two layouts:
//
//   - isolated (default when run as root): a dedicated, login-less system
//     user owns the data directory (0700) and runs the service, so agents
//     running as your desktop user can't read the vault, the database, the
//     master key or the gateway's processes. macOS: hidden user _toolgate +
//     LaunchDaemon. Linux: system user toolgate + a hardened systemd unit.
//   - user: runs as you (LaunchAgent / systemd --user), master key in the
//     macOS Keychain or a 0600 file. Simpler, but anything running as you
//     can read the data directory.
//
// Re-running install upgrades the binary and restarts the service; data is
// never touched except for an explicit --from migration. Every step is
// printed first; --dry-run prints the plan and stops.

const (
	launchdLabel    = "io.github.nekinci.toolgate"
	systemdUnitName = "toolgate.service"
)

type installPlan struct {
	OS, Mode  string // darwin|linux, isolated|user
	Label     string // launchd label (macOS)
	UnitName  string // systemd unit (Linux)
	Legacy    bool   // layout of an install made under the old name (agent-gateway)
	Addr      string
	SrcBin    string // binary being installed (normally this executable)
	Bin       string // installed binary
	Link      string // optional symlink on PATH
	Data, Out string
	SvcUser   string // isolated only
	Unit      string // plist or systemd unit path
	KeyStore  string // keychain|file
	Owner     string // desktop user (for cleaning up a per-user install)
	OwnerHome string
	From      string // migration export dir
	Password  string // isolated: initial panel password (never printed)
}

func defaultPlan(goos, mode string, home string) installPlan {
	p := installPlan{OS: goos, Mode: mode, Addr: "127.0.0.1:7777", Label: launchdLabel, UnitName: systemdUnitName}
	switch {
	case goos == "darwin" && mode == "isolated":
		p.SvcUser = "_toolgate"
		p.Data = "/Library/Application Support/Toolgate"
		p.Out = "/Users/Shared/Toolgate/outputs"
		p.Bin = "/usr/local/libexec/toolgate/toolgate"
		p.Link = "/usr/local/bin/toolgate"
		p.Unit = "/Library/LaunchDaemons/" + p.Label + ".plist"
		p.KeyStore = "file"
	case goos == "linux" && mode == "isolated":
		p.SvcUser = "toolgate"
		p.Data = "/var/lib/toolgate"
		p.Out = "/var/lib/toolgate-outputs"
		p.Bin = "/usr/local/libexec/toolgate/toolgate"
		p.Link = "/usr/local/bin/toolgate"
		p.Unit = "/etc/systemd/system/" + p.UnitName
		p.KeyStore = "file"
	case goos == "darwin":
		p.Data = filepath.Join(home, ".toolgate")
		p.Out = filepath.Join(p.Data, "outputs")
		p.Bin = filepath.Join(home, ".local/bin/toolgate")
		p.Unit = filepath.Join(home, "Library/LaunchAgents", p.Label+".plist")
		p.KeyStore = "keychain"
	case goos == "linux":
		p.Data = filepath.Join(home, ".toolgate")
		p.Out = filepath.Join(p.Data, "outputs")
		p.Bin = filepath.Join(home, ".local/bin/toolgate")
		p.Unit = filepath.Join(home, ".config/systemd/user", p.UnitName)
		p.KeyStore = "file"
	}
	return p
}

// Installs made before the rename to toolgate used these names. They keep
// their layout (user, data, label) when upgraded, so nothing has to move;
// only a toolgate link is added next to the old one.
const (
	legacyName  = "agent-gateway"
	legacyLabel = "dev.local.agent-gateway"
)

func legacyPlan(goos, mode, home string) installPlan {
	p := defaultPlan(goos, mode, home)
	p.Legacy, p.Label, p.UnitName = true, legacyLabel, legacyName+".service"
	switch {
	case goos == "darwin" && mode == "isolated":
		p.SvcUser = "_agentgw"
		p.Data = "/Library/Application Support/AgentGateway"
		p.Out = "/Users/Shared/AgentGateway/outputs"
		p.Bin = "/usr/local/libexec/agent-gateway/agent-gateway"
		p.Unit = "/Library/LaunchDaemons/" + p.Label + ".plist"
	case goos == "darwin":
		p.Data = filepath.Join(home, ".agent-gateway")
		p.Out = filepath.Join(p.Data, "outputs")
		p.Bin = filepath.Join(home, ".local/bin/agent-gateway")
		p.Unit = filepath.Join(home, "Library/LaunchAgents", p.Label+".plist")
	default:
		return installPlan{} // the old name never shipped a Linux installer
	}
	return p
}

// planFor returns the layout to install or upgrade: an existing install
// under the old name keeps its layout, otherwise the current one.
func planFor(goos, mode, home string) installPlan {
	cur := defaultPlan(goos, mode, home)
	if !fileExists(cur.Unit) {
		if old := legacyPlan(goos, mode, home); old.Unit != "" && fileExists(old.Unit) {
			return old
		}
	}
	return cur
}

func (p installPlan) port() string {
	_, port, _ := net.SplitHostPort(p.Addr)
	return port
}

func (p installPlan) serveArgs() []string {
	return []string{p.Bin, "serve", "-addr", p.Addr, "-data", p.Data, "-key-store", p.KeyStore, "-output-dir", p.Out}
}

func servicePATH(goos string) string {
	if goos == "darwin" {
		return "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
	}
	return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
}

func xmlEsc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func renderLaunchd(p installPlan) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>` + xmlEsc(p.Label) + `</string>
`)
	home := p.OwnerHome
	if p.Mode == "isolated" {
		home = p.Data
		fmt.Fprintf(&b, "  <key>UserName</key><string>%s</string>\n  <key>GroupName</key><string>%s</string>\n", p.SvcUser, p.SvcUser)
	}
	b.WriteString("  <key>ProgramArguments</key><array>\n")
	for _, a := range p.serveArgs() {
		fmt.Fprintf(&b, "    <string>%s</string>\n", xmlEsc(a))
	}
	path := servicePATH("darwin")
	if p.Mode == "user" {
		path = filepath.Dir(p.Bin) + ":" + path
	}
	fmt.Fprintf(&b, `  </array>
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>%s</string>
    <key>HOME</key><string>%s</string>
  </dict>
  <key>WorkingDirectory</key><string>%s</string>
  <key>Umask</key><integer>63</integer>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict></plist>
`, xmlEsc(path), xmlEsc(home), xmlEsc(p.Data), xmlEsc(filepath.Join(p.Data, "gateway.log")), xmlEsc(filepath.Join(p.Data, "gateway.log")))
	return b.String()
}

// systemdQuote quotes one ExecStart word.
func systemdQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'\\$%;") {
		return s
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", "$$", "%", "%%").Replace(s) + `"`
}

func renderSystemd(p installPlan) string {
	var exec []string
	for _, a := range p.serveArgs() {
		exec = append(exec, systemdQuote(a))
	}
	var b strings.Builder
	b.WriteString("[Unit]\nDescription=Toolgate (local MCP gateway)\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\n")
	b.WriteString("ExecStart=" + strings.Join(exec, " ") + "\n")
	b.WriteString("Restart=on-failure\nRestartSec=2\nUMask=0077\n")
	if p.Mode == "isolated" {
		// The gateway starts upstream MCP servers (npx, uvx, docker…) as
		// children, so the sandbox keeps the toolchains usable: /usr stays
		// readable, only the data and output directories are writable, and
		// every home directory is hidden.
		fmt.Fprintf(&b, `User=%[1]s
Group=%[1]s
Environment=HOME=%[2]s
Environment=PATH=%[3]s
WorkingDirectory=%[2]s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=%[4]s %[5]s
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
`, p.SvcUser, systemdQuote(p.Data), servicePATH("linux"), systemdQuote(p.Data), systemdQuote(p.Out))
	} else {
		fmt.Fprintf(&b, "Environment=PATH=%s:%s\nWorkingDirectory=%s\n\n[Install]\nWantedBy=default.target\n",
			filepath.Dir(p.Bin), servicePATH("linux"), systemdQuote(p.Data))
	}
	return b.String()
}

// ---- execution ----

type step struct {
	desc string
	run  func() error
}

func runCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func cmdOutput(name string, args ...string) string {
	out, _ := exec.Command(name, args...).Output()
	return strings.TrimSpace(string(out))
}

func runSteps(steps []step, dry bool) error {
	for i, s := range steps {
		fmt.Fprintf(os.Stderr, "[%d/%d] %s\n", i+1, len(steps), s.desc)
		if dry || s.run == nil {
			continue
		}
		if err := s.run(); err != nil {
			return fmt.Errorf("step %d (%s) failed: %w\nNothing after this step was done; fix the problem and re-run install", i+1, s.desc, err)
		}
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	if a, b := filepath.Clean(src), filepath.Clean(dst); a == b {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	_ = os.Chmod(tmp, mode)
	return os.Rename(tmp, dst) // atomic: a running service keeps its old inode
}

func lookupIDs(name string) (int, int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return uid, gid, nil
}

func mkdirOwned(dir string, mode os.FileMode, owner string) error {
	if err := os.MkdirAll(dir, mode); err != nil {
		return err
	}
	if err := os.Chmod(dir, mode); err != nil {
		return err
	}
	if owner == "" {
		return nil
	}
	uid, gid, err := lookupIDs(owner)
	if err != nil {
		return err
	}
	return os.Chown(dir, uid, gid)
}

func waitHealthy(port string, d time.Duration) error {
	c := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(d)
	for {
		r, err := c.Get("http://localhost:" + port + "/healthz")
		if err == nil {
			r.Body.Close()
			if r.StatusCode == 200 {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the service did not answer on http://localhost:%s/healthz", port)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// waitDown reports whether nothing answers on port within d.
func waitDown(port string, d time.Duration) bool {
	c := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(d)
	for {
		r, err := c.Get("http://localhost:" + port + "/healthz")
		if err != nil {
			return true
		}
		r.Body.Close()
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// readPassword reads a line without echo (via stty) from the terminal.
func readPassword(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("no terminal to ask for the panel password; use --password-stdin")
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	stty := func(arg string) {
		c := exec.Command("stty", arg)
		c.Stdin = tty
		_ = c.Run()
	}
	stty("-echo")
	defer stty("echo")
	line, err := bufio.NewReader(tty).ReadString('\n')
	fmt.Fprintln(tty)
	return strings.TrimRight(line, "\r\n"), err
}

var macUIDRe = regexp.MustCompile(`^\d+$`)

// macCreateServiceUser creates a hidden, login-less user + group with a
// free id in 450-499.
func macCreateServiceUser(name, home string) error {
	if runCmd("dscl", ".", "-read", "/Users/"+name) == nil {
		return nil
	}
	used := map[string]bool{}
	for _, l := range strings.Split(cmdOutput("dscl", ".", "-list", "/Users", "UniqueID")+"\n"+cmdOutput("dscl", ".", "-list", "/Groups", "PrimaryGroupID"), "\n") {
		if f := strings.Fields(l); len(f) == 2 && macUIDRe.MatchString(f[1]) {
			used[f[1]] = true
		}
	}
	id := ""
	for i := 450; i < 500; i++ {
		if !used[strconv.Itoa(i)] {
			id = strconv.Itoa(i)
			break
		}
	}
	if id == "" {
		return errors.New("no free uid/gid in 450-499")
	}
	cmds := [][]string{
		{"/Groups/" + name}, {"/Groups/" + name, "PrimaryGroupID", id}, {"/Groups/" + name, "RealName", "Toolgate"}, {"/Groups/" + name, "Password", "*"},
		{"/Users/" + name}, {"/Users/" + name, "UniqueID", id}, {"/Users/" + name, "PrimaryGroupID", id},
		{"/Users/" + name, "UserShell", "/usr/bin/false"}, {"/Users/" + name, "NFSHomeDirectory", home},
		{"/Users/" + name, "RealName", "Toolgate"}, {"/Users/" + name, "Password", "*"}, {"/Users/" + name, "IsHidden", "1"},
	}
	for _, c := range cmds {
		if err := runCmd("dscl", append([]string{".", "-create"}, c...)...); err != nil {
			return err
		}
	}
	return nil
}

func linuxCreateServiceUser(name, home string) error {
	if _, err := user.Lookup(name); err == nil {
		return nil
	}
	shell := "/bin/false"
	for _, s := range []string{"/usr/sbin/nologin", "/sbin/nologin"} {
		if _, err := os.Stat(s); err == nil {
			shell = s
			break
		}
	}
	if _, err := exec.LookPath("useradd"); err == nil {
		return runCmd("useradd", "--system", "--user-group", "--home-dir", home, "--no-create-home", "--shell", shell, "--comment", "Toolgate", name)
	}
	if _, err := exec.LookPath("adduser"); err == nil { // busybox / Alpine
		_ = runCmd("addgroup", "-S", name)
		return runCmd("adduser", "-S", "-D", "-H", "-h", home, "-s", shell, "-G", name, name)
	}
	return errors.New("neither useradd nor adduser found; create a system user named " + name + " and re-run")
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func validateExport(dir string) error {
	for _, f := range []string{"gateway.db", "master.key"} {
		if fi, err := os.Stat(filepath.Join(dir, f)); err != nil || fi.Size() == 0 {
			return fmt.Errorf("%s must contain gateway.db and master.key (create it with: toolgate migrate-export -out %s); nothing was changed", dir, dir)
		}
	}
	if _, _, err := readKeyFile(dir); err != nil {
		return fmt.Errorf("%s/master.key looks invalid; nothing was changed", dir)
	}
	return nil
}

func installCmd(args []string) {
	f := flag.NewFlagSet("install", flag.ExitOnError)
	isolated := f.Bool("isolated", false, "run under a dedicated system user (needs root; default when run as root)")
	userMode := f.Bool("user", false, "run as the current user (no root needed)")
	addr := f.String("addr", "127.0.0.1:7777", "listen address (keep it on localhost)")
	from := f.String("from", "", "migrate data exported with `toolgate migrate-export -out DIR` (isolated, empty install only)")
	owner := f.String("owner", "", "desktop user whose per-user install should be stopped (default: $SUDO_USER)")
	removeOld := f.Bool("remove-old-data", false, "after a successful migration, delete the owner's old ~/.toolgate")
	pwStdin := f.Bool("password-stdin", false, "read the initial panel password from the first line of stdin")
	dry := f.Bool("dry-run", false, "print the steps without changing anything")
	_ = f.Parse(args)

	goos := runtime.GOOS
	if goos != "darwin" && goos != "linux" {
		fatal(fmt.Errorf("install supports macOS and Linux; on %s run `toolgate serve` under your own service manager", goos))
	}
	root := os.Geteuid() == 0
	mode := "user"
	if *isolated || (root && !*userMode) {
		mode = "isolated"
	}
	if *isolated && *userMode {
		fatal(errors.New("choose --isolated or --user, not both"))
	}
	if mode == "isolated" && !root && !*dry {
		fatal(errors.New("isolated install needs root: run it with sudo from an administrator account (or use --user)"))
	}
	if mode == "user" && root {
		fatal(errors.New("--user installs for the current user; don't run it with sudo"))
	}
	home, _ := os.UserHomeDir()
	if mode == "user" {
		if iso := planFor(goos, "isolated", home); fileExists(iso.Unit) {
			fatal(fmt.Errorf("an isolated install already exists (%s); upgrade it with sudo toolgate install, or remove it first with sudo toolgate uninstall", iso.Unit))
		}
	}
	p := planFor(goos, mode, home)
	p.Addr, p.From = *addr, *from
	if p.Legacy {
		fmt.Fprintf(os.Stderr, "Found an install made under the old name (%s); upgrading it in place.\n", p.Unit)
	}
	if h, port, err := net.SplitHostPort(p.Addr); err != nil || port == "" || (h != "127.0.0.1" && h != "localhost" && h != "::1") {
		fatal(fmt.Errorf("-addr must be a localhost address like 127.0.0.1:7777"))
	}
	exe, err := os.Executable()
	if err != nil {
		fatal(err)
	}
	if p.SrcBin, err = filepath.EvalSymlinks(exe); err != nil {
		fatal(err)
	}
	p.Owner = *owner
	if p.Owner == "" && mode == "isolated" {
		p.Owner = os.Getenv("SUDO_USER")
	}
	if mode == "user" {
		p.OwnerHome = home
	} else if p.Owner != "" && p.Owner != "root" {
		u, err := user.Lookup(p.Owner)
		if err != nil {
			fatal(fmt.Errorf("user %q not found", p.Owner))
		}
		p.OwnerHome = u.HomeDir
	}
	if p.From != "" {
		if mode != "isolated" {
			fatal(errors.New("--from is for isolated installs"))
		}
		if err := validateExport(p.From); err != nil {
			fatal(err)
		}
	}

	// Ask for everything before changing anything.
	if mode == "isolated" && !*dry {
		if _, err := os.Stat(passwordPath(p.Data)); err != nil {
			if p.Password, err = askNewPassword(*pwStdin); err != nil {
				fatal(err)
			}
		}
	}

	steps := buildSteps(p, *removeOld)
	fmt.Fprintf(os.Stderr, "Installing Toolgate (%s mode, %s)\n", mode, goos)
	if err := runSteps(steps, *dry); err != nil {
		fatal(err)
	}
	if *dry {
		fmt.Fprintln(os.Stderr, "\n(dry run: nothing was changed)")
		return
	}
	printInstallSummary(p)
}

func askNewPassword(fromStdin bool) (string, error) {
	if fromStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		pw := strings.TrimRight(line, "\r\n")
		if len([]rune(pw)) < 8 {
			return "", errors.New("the panel password must be at least 8 characters")
		}
		return pw, nil
	}
	fmt.Fprintln(os.Stderr, "Choose a password for the admin panel (at least 8 characters).")
	for i := 0; i < 3; i++ {
		p1, err := readPassword("Password: ")
		if err != nil {
			return "", err
		}
		p2, err := readPassword("Repeat:   ")
		if err != nil {
			return "", err
		}
		switch {
		case p1 != p2:
			fmt.Fprintln(os.Stderr, "The passwords don't match.")
		case len([]rune(p1)) < 8:
			fmt.Fprintln(os.Stderr, "Too short.")
		default:
			return p1, nil
		}
	}
	return "", errors.New("no password set; nothing was changed")
}

func buildSteps(p installPlan, removeOld bool) []step {
	var s []step
	add := func(desc string, fn func() error) { s = append(s, step{desc, fn}) }
	iso := p.Mode == "isolated"

	if iso {
		if p.OS == "darwin" {
			add("create hidden service user "+p.SvcUser+" (if missing)", func() error { return macCreateServiceUser(p.SvcUser, p.Data) })
		} else {
			add("create system user "+p.SvcUser+" (if missing)", func() error { return linuxCreateServiceUser(p.SvcUser, p.Data) })
		}
		add("data directory "+p.Data+" (owner "+p.SvcUser+", 0700)", func() error { return mkdirOwned(p.Data, 0o700, p.SvcUser) })
		add("output directory "+p.Out+" (readable by everyone, writable by the service)", func() error {
			if err := mkdirOwned(filepath.Dir(p.Out), 0o755, p.SvcUser); err != nil {
				return err
			}
			return mkdirOwned(p.Out, 0o755, p.SvcUser)
		})
	} else {
		add("data directory "+p.Data+" (0700)", func() error { return mkdirOwned(p.Data, 0o700, "") })
	}

	add("install binary "+p.Bin, func() error {
		if err := copyFile(p.SrcBin, p.Bin, 0o755); err != nil {
			return err
		}
		if iso {
			_ = os.Chown(p.Bin, 0, 0)
			_ = os.Chown(filepath.Dir(p.Bin), 0, 0)
			if p.Link != "" {
				_ = os.MkdirAll(filepath.Dir(p.Link), 0o755)
				_ = os.Remove(p.Link)
				return os.Symlink(p.Bin, p.Link)
			}
		}
		return nil
	})

	// Stop whatever runs now (this layout, and on macOS an older per-user
	// LaunchAgent of the owner, which would hold the port).
	add("stop the running service (if any)", func() error {
		stopService(p)
		if iso && p.OS == "darwin" && p.OwnerHome != "" {
			for _, name := range [][2]string{{launchdLabel, "toolgate"}, {legacyLabel, legacyName}} {
				if uid := cmdOutput("id", "-u", p.Owner); uid != "" {
					_ = runCmd("launchctl", "bootout", "gui/"+uid+"/"+name[0])
				}
				_ = os.Remove(filepath.Join(p.OwnerHome, "Library/LaunchAgents", name[0]+".plist"))
				_ = os.Remove(filepath.Join(p.OwnerHome, ".local/bin", name[1]))
			}
		}
		if iso && p.OS == "linux" && p.Owner != "" {
			// a per-user unit of the owner, if any
			_ = runCmd("systemctl", "--machine="+p.Owner+"@", "--user", "disable", "--now", p.UnitName)
		}
		return nil
	})

	if p.From != "" {
		add("migrate data from "+p.From, func() error {
			if _, err := os.Stat(filepath.Join(p.Data, "gateway.db")); err == nil {
				fmt.Fprintf(os.Stderr, "      %s already has data; migration skipped and %s kept\n", p.Data, p.From)
				return nil
			}
			uid, gid, err := lookupIDs(p.SvcUser)
			if err != nil {
				return err
			}
			for _, name := range []string{"gateway.db", "master.key", "claude-directory.json"} {
				src := filepath.Join(p.From, name)
				if _, err := os.Stat(src); err != nil {
					continue
				}
				dst := filepath.Join(p.Data, name)
				if err := copyFile(src, dst, 0o600); err != nil {
					return err
				}
				if err := os.Chown(dst, uid, gid); err != nil {
					return err
				}
			}
			// The export holds the master key in plain text: remove it only
			// now that the copy succeeded.
			return os.RemoveAll(p.From)
		})
		if removeOld && p.OwnerHome != "" {
			old := filepath.Join(p.OwnerHome, ".toolgate")
			if !fileExists(old) {
				old = filepath.Join(p.OwnerHome, "."+legacyName)
			}
			add("delete the old per-user data "+old, func() error {
				if _, err := os.Stat(filepath.Join(p.Data, "gateway.db")); err != nil {
					return errors.New("no data in the new location; refusing to delete the old copy")
				}
				return os.RemoveAll(old)
			})
		}
	}

	if p.Password != "" {
		add("set the admin panel password", func() error {
			if err := SetPassword(p.Data, p.Password); err != nil {
				return err
			}
			uid, gid, err := lookupIDs(p.SvcUser)
			if err != nil {
				return err
			}
			return os.Chown(passwordPath(p.Data), uid, gid)
		})
	}

	switch p.OS {
	case "darwin":
		add("write "+p.Unit, func() error {
			if err := os.MkdirAll(filepath.Dir(p.Unit), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(p.Unit, []byte(renderLaunchd(p)), 0o644); err != nil {
				return err
			}
			if iso {
				return os.Chown(p.Unit, 0, 0)
			}
			return nil
		})
		add("start the service (launchd "+p.Label+")", func() error {
			return runCmd("launchctl", "bootstrap", launchdDomain(p), p.Unit)
		})
	case "linux":
		add("write "+p.Unit, func() error {
			if err := os.MkdirAll(filepath.Dir(p.Unit), 0o755); err != nil {
				return err
			}
			return os.WriteFile(p.Unit, []byte(renderSystemd(p)), 0o644)
		})
		add("start the service (systemd "+p.UnitName+")", func() error {
			sc := systemctl(p)
			if err := runCmd(sc[0], append(sc[1:], "daemon-reload")...); err != nil {
				return err
			}
			if err := runCmd(sc[0], append(sc[1:], "enable", p.UnitName)...); err != nil {
				return err
			}
			return runCmd(sc[0], append(sc[1:], "restart", p.UnitName)...)
		})
	}
	add("wait until http://localhost:"+p.port()+" answers", func() error {
		if err := waitHealthy(p.port(), 20*time.Second); err != nil {
			return fmt.Errorf("%v; see %s", err, logHint(p))
		}
		return nil
	})
	return s
}

func launchdDomain(p installPlan) string {
	if p.Mode == "isolated" {
		return "system"
	}
	return "gui/" + strconv.Itoa(os.Getuid())
}

func systemctl(p installPlan) []string {
	if p.Mode == "isolated" {
		return []string{"systemctl"}
	}
	return []string{"systemctl", "--user"}
}

func stopService(p installPlan) {
	switch p.OS {
	case "darwin":
		_ = runCmd("launchctl", "bootout", launchdDomain(p)+"/"+p.Label)
	case "linux":
		sc := systemctl(p)
		_ = runCmd(sc[0], append(sc[1:], "stop", p.UnitName)...)
	}
}

func logHint(p installPlan) string {
	if p.OS == "linux" {
		if p.Mode == "isolated" {
			return "journalctl -u " + strings.TrimSuffix(p.UnitName, ".service")
		}
		return "journalctl --user -u " + strings.TrimSuffix(p.UnitName, ".service")
	}
	if p.Mode == "isolated" {
		return `sudo tail "` + filepath.Join(p.Data, "gateway.log") + `"`
	}
	return filepath.Join(p.Data, "gateway.log")
}

func printInstallSummary(p installPlan) {
	ui := "http://localhost:" + p.port() + "/ui/"
	fmt.Fprintf(os.Stderr, "\nToolgate is running: %s\n", ui)
	if p.Mode == "isolated" {
		fmt.Fprintf(os.Stderr, `  • Sign in to the panel with the password you chose.
  • Data: %s (only %s can read it)
  • Files made by built-in tools: %s
  • Logs: %s
  • Connect an agent: panel → Agents → Connect gives a one-time pairing
    command, so the token goes straight into the client's config.
`, p.Data, p.SvcUser, p.Out, logHint(p))
		if p.OS == "darwin" && p.From != "" {
			fmt.Fprintln(os.Stderr, "  • The old per-user Keychain entry is no longer used; as "+p.Owner+" you can remove it with:\n      security delete-generic-password -s toolgate -a master-key")
		}
		return
	}
	fmt.Fprintf(os.Stderr, `  • Open the panel: toolgate admin-url   (prints a sign-in link)
  • Data: %s     Logs: %s
  • The first agent (claude-code) and its registration command are in %s
  • This mode runs as you: other programs running as you can read the data
    directory. Use "sudo toolgate install" for the isolated layout.
`, p.Data, logHint(p), filepath.Join(p.Data, "first-run.txt"))
	if p.OS == "linux" {
		fmt.Fprintln(os.Stderr, "  • To keep it running after you log out:  loginctl enable-linger $USER")
	}
	if _, err := exec.LookPath("toolgate"); err != nil {
		fmt.Fprintf(os.Stderr, "  • %s is not on your PATH; add it to use the commands above.\n", filepath.Dir(p.Bin))
	}
}

// ---- uninstall / status ----

func detectInstalls() []installPlan {
	home, _ := os.UserHomeDir()
	var out []installPlan
	for _, mode := range []string{"isolated", "user"} {
		for _, p := range []installPlan{defaultPlan(runtime.GOOS, mode, home), legacyPlan(runtime.GOOS, mode, home)} {
			p.OwnerHome = home
			if p.Unit != "" && fileExists(p.Unit) {
				out = append(out, p)
			}
		}
	}
	return out
}

func uninstallCmd(args []string) {
	f := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := f.Bool("purge", false, "also delete the data directory (vault, database, master key) and the service user. Cannot be undone")
	dry := f.Bool("dry-run", false, "print the steps without changing anything")
	_ = f.Parse(args)
	root := os.Geteuid() == 0
	var steps []step
	found := false
	for _, p := range detectInstalls() {
		if (p.Mode == "isolated") != root {
			fmt.Fprintf(os.Stderr, "found the %s install (%s); run uninstall %s to remove it\n", p.Mode, p.Unit, map[bool]string{true: "with sudo", false: "without sudo, as its user"}[p.Mode == "isolated"])
			continue
		}
		found = true
		p := p
		stopped := false
		steps = append(steps,
			step{"stop the service", func() error {
				stopService(p)
				if p.OS == "linux" {
					sc := systemctl(p)
					_ = runCmd(sc[0], append(sc[1:], "disable", p.UnitName)...)
				}
				if !waitDown(p.port(), 10*time.Second) {
					return errors.New("the gateway still answers; not removing anything")
				}
				stopped = true
				return nil
			}},
			step{"remove " + p.Unit, func() error {
				if err := os.Remove(p.Unit); err != nil && !os.IsNotExist(err) {
					return err
				}
				if p.OS == "linux" {
					sc := systemctl(p)
					_ = runCmd(sc[0], append(sc[1:], "daemon-reload")...)
				}
				return nil
			}},
			step{"remove the binary " + p.Bin, func() error {
				for _, l := range []string{p.Link, "/usr/local/bin/" + legacyName} {
					if t, _ := os.Readlink(l); l != "" && t == p.Bin {
						_ = os.Remove(l)
					}
				}
				if p.Mode == "isolated" {
					return os.RemoveAll(filepath.Dir(p.Bin))
				}
				if err := os.Remove(p.Bin); err != nil && !os.IsNotExist(err) {
					return err
				}
				return nil
			}},
		)
		if *purge {
			steps = append(steps, step{"delete data " + p.Data, func() error {
				if !stopped {
					return errors.New("service not confirmed stopped")
				}
				if p.Mode == "user" && p.OS == "darwin" {
					for _, svc := range []string{keychainService, legacyKeychainService} {
						_ = runCmd("security", "delete-generic-password", "-s", svc, "-a", keychainAccount)
					}
				}
				if p.Mode == "isolated" {
					if err := os.RemoveAll(p.Out); err != nil {
						return err
					}
					_ = os.Remove(filepath.Dir(p.Out)) // only if empty
				}
				return os.RemoveAll(p.Data)
			}})
			if p.Mode == "isolated" {
				steps = append(steps, step{"delete the service user " + p.SvcUser, func() error {
					if p.OS == "darwin" {
						_ = runCmd("dscl", ".", "-delete", "/Users/"+p.SvcUser)
						_ = runCmd("dscl", ".", "-delete", "/Groups/"+p.SvcUser)
						return nil
					}
					if _, err := exec.LookPath("userdel"); err == nil {
						return runCmd("userdel", p.SvcUser)
					}
					return runCmd("deluser", p.SvcUser)
				}})
			}
		}
	}
	if !found {
		fmt.Fprintln(os.Stderr, "nothing to uninstall here")
		return
	}
	if err := runSteps(steps, *dry); err != nil {
		fatal(err)
	}
	if *dry {
		fmt.Fprintln(os.Stderr, "(dry run: nothing was changed)")
	} else if !*purge {
		fmt.Fprintln(os.Stderr, "uninstalled; data kept (use --purge to delete it)")
	}
}

func statusCmd(args []string) {
	f := flag.NewFlagSet("status", flag.ExitOnError)
	addr := f.String("addr", envOr("TOOLGATE_ADDR", "127.0.0.1:7777"), "address to probe")
	_ = f.Parse(args)
	installs := detectInstalls()
	if len(installs) == 0 {
		fmt.Println("no service install found (toolgate install sets one up)")
	}
	for _, p := range installs {
		fmt.Printf("%s install: %s\n  binary: %s\n  data:   %s\n", p.Mode, p.Unit, p.Bin, p.Data)
	}
	_, port, _ := net.SplitHostPort(*addr)
	if waitHealthy(port, time.Second) == nil {
		fmt.Printf("gateway answers on http://localhost:%s\n", port)
	} else {
		fmt.Printf("nothing answers on http://localhost:%s\n", port)
		os.Exit(1)
	}
}
