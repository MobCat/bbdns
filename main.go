//!env/go1.24.4 (windows/amd64)
//MobCat (2026)

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"bufio"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"path/filepath"

	"github.com/miekg/dns"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddress  string                 `yaml:"listen_address"`
	PassthroughDNS string                 `yaml:"passthrough_dns"`
	DefaultRedirect string                `yaml:"default"`
	Redirects      map[string]interface{} `yaml:"redirects"`
	MaxLogs        int                    `yaml:"max_logs"`
	
	// Processed redirects map (internal use)
	redirectMap    map[string]string
}

type DNSServer struct {
	config       *Config
	dnsClient    *dns.Client
	cache        map[string][]net.IP // hostname -> IPs cache
	reverseCache map[string]string   // IP -> hostname cache
	
	// Stats
	requestCount    atomic.Int64
	passthroughCount atomic.Int64
	redirectCount   atomic.Int64
	
	// State
	paused     atomic.Bool
	pausedMux  sync.RWMutex
	
	// Log buffer
	logBuffer []string
	logMux    sync.Mutex
}

func loadConfig(filename string) (*Config, error) {
	// Load config yaml
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Set defaults if something was not loaded
	if config.ListenAddress == "" {
		config.ListenAddress = ":53"
	}
	if config.PassthroughDNS == "" {
		config.PassthroughDNS = "8.8.8.8:53"
	}
	if !strings.Contains(config.PassthroughDNS, ":") {
		config.PassthroughDNS += ":53"
	}
	if config.MaxLogs == 0 {
		config.MaxLogs = 20
	}

	// Process redirects: convert interface{} map to string map
	config.redirectMap = make(map[string]string)
	for hostname, target := range config.Redirects {
		switch v := target.(type) {
		case string:
			// Explicit redirect target specified
			config.redirectMap[hostname] = v
		case nil:
			// No target specified, use default if available
			if config.DefaultRedirect != "" {
				config.redirectMap[hostname] = config.DefaultRedirect
			} else {
				return nil, fmt.Errorf("redirect for '%s' has no target and no default is set", hostname)
			}
		default:
			return nil, fmt.Errorf("invalid redirect value for '%s': must be a string or null", hostname)
		}
	}

	return &config, nil
}

func GetLocalIP() string {
	// Get local IP address of this computer to display on stats bar
	// Yes I keep forgetting my own ip, and this may need to be reword to show public ip if the dns port is open
    addrs, err := net.InterfaceAddrs()
    if err != nil {
        return ""
    }
    for _, address := range addrs {
        // check the address type and if it is not a loopback the display it
        if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            if ipnet.IP.To4() != nil {
                return ipnet.IP.String()
            }
        }
    }
    return ""
}

func NewDNSServer(config *Config) *DNSServer {
	return &DNSServer{
		config: config,
		dnsClient: &dns.Client{
			Timeout: 5 * time.Second,
		},
		cache:        make(map[string][]net.IP),
		reverseCache: make(map[string]string),
		logBuffer:    make([]string, 0, config.MaxLogs),
	}
}

// Add log to buffer
func (s *DNSServer) addLog(msg string) {
	s.logMux.Lock()
	defer s.logMux.Unlock()
	
	// Add timestamp
	logLine := time.Now().Format("15:04:05") + " " + msg
	
	s.logBuffer = append(s.logBuffer, logLine)
	
	// Keep only last MaxLogs entries
	if len(s.logBuffer) > s.config.MaxLogs {
		s.logBuffer = s.logBuffer[len(s.logBuffer)-s.config.MaxLogs:]
	}
}

// Get logs for display
func (s *DNSServer) getLogs() []string {
	s.logMux.Lock()
	defer s.logMux.Unlock()
	
	result := make([]string, len(s.logBuffer))
	copy(result, s.logBuffer)
	return result
}

// Resolve a hostname using passthrough DNS
func (s *DNSServer) resolveHostname(hostname string) ([]net.IP, error) {
	// Check cache first
	if ips, ok := s.cache[hostname]; ok {
		return ips, nil
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
	msg.RecursionDesired = true

	resp, _, err := s.dnsClient.Exchange(msg, s.config.PassthroughDNS)
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %w", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query failed with code: %d", resp.Rcode)
	}

	var ips []net.IP
	for _, answer := range resp.Answer {
		if a, ok := answer.(*dns.A); ok {
			ips = append(ips, a.A)
			// Update reverse cache
			s.reverseCache[a.A.String()] = hostname
		}
	}

	// Cache the results
	if len(ips) > 0 {
		s.cache[hostname] = ips
	}

	return ips, nil
}

// Handle DNS query
func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	// Increment request counter
	s.requestCount.Add(1)
	
	// Check if paused
	if s.paused.Load() {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(msg)
		return
	}
	
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	// Log the incoming request
	clientAddr := w.RemoteAddr().String()
	if len(r.Question) > 0 {
		q := r.Question[0]
		queryType := dns.TypeToString[q.Qtype]
		fixname := strings.TrimSuffix(q.Name, ".")
		s.addLog(fmt.Sprintf("[REQUEST]  %s - %s - %s Record", clientAddr, fixname, queryType))
	} else {
		s.addLog(fmt.Sprintf("[REQUEST]  %s - (no questions)", clientAddr))
	}

	// Check if this hostname should be redirected
	var shouldRedirect bool
	var redirectTarget string
	if len(r.Question) > 0 {
		hostname := strings.TrimSuffix(r.Question[0].Name, ".")
		if target, exists := s.config.redirectMap[hostname]; exists {
			shouldRedirect = true
			redirectTarget = target
			s.redirectCount.Add(1)
			s.addLog(fmt.Sprintf("[REDIRECT] %s - %s -> %s", clientAddr, hostname, redirectTarget))
		}
	}

	if shouldRedirect && len(r.Question) > 0 {
		// Build our own response instead of forwarding
		msg.Authoritative = true
		
		// Determine if redirectTarget is an IP or hostname
		targetIP := net.ParseIP(redirectTarget)
		if targetIP == nil {
			// It's a hostname, resolve it
			ips, err := s.resolveHostname(redirectTarget)
			if err != nil {
				s.addLog(fmt.Sprintf("[ERROR]    %s - Failed to resolve redirect target %s: %v", clientAddr, redirectTarget, err))
				// Fall back to passthrough DNS
				shouldRedirect = false
			} else if len(ips) > 0 {
				targetIP = ips[0]
			}
		}

		if targetIP != nil {
			// Create A record with the redirect IP
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: targetIP,
			}
			msg.Answer = append(msg.Answer, rr)
			//Left here for debug, but its otherwise unsecrey log data, just check where the -> ended up.
			//s.addLog(fmt.Sprintf("[RESPONSE] %s - Redirected to IP: %s", clientAddr, targetIP.String()))
			w.WriteMsg(msg)
			return
		}
	}

	// Forward to passthrough DNS (either no redirect or redirect failed)
	s.passthroughCount.Add(1)
	resp, _, err := s.dnsClient.Exchange(r, s.config.PassthroughDNS)
	if err != nil {
		s.addLog(fmt.Sprintf("[ERROR]    %s - Failed to forward DNS query: %v", clientAddr, err))
		msg.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(msg)
		return
	}

	// Log the response from passthrough DNS
	if len(r.Question) > 0 {
		q := r.Question[0]
		var ips []string
		for _, answer := range resp.Answer {
			if a, ok := answer.(*dns.A); ok {
				ips = append(ips, a.A.String())
			}
		}
		if len(ips) > 0 {
			s.addLog(fmt.Sprintf("[RESPONSE] %s - %s resolved to: %s", clientAddr, q.Name, strings.Join(ips, ", ")))
		} else {
			s.addLog(fmt.Sprintf("[RESPONSE] %s - %s (no A records)", clientAddr, q.Name))
		}
	}

	w.WriteMsg(resp)
}

// Reset stats
func (s *DNSServer) resetStats() {
	s.requestCount.Store(0)
	s.passthroughCount.Store(0)
	s.redirectCount.Store(0)
	
	// Clear log buffer
	s.logMux.Lock()
	s.logBuffer = make([]string, 0, s.config.MaxLogs)
	s.logMux.Unlock()
}

// Reload config
func (s *DNSServer) reloadConfig(filename string) error {
	newConfig, err := loadConfig(filename)
	if err != nil {
		return err
	}
	
	s.pausedMux.Lock()
	s.config = newConfig
	s.cache = make(map[string][]net.IP)
	s.reverseCache = make(map[string]string)
	s.pausedMux.Unlock()
	
	return nil
}

func clearScreen() {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	case "darwin", "linux":
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	default:
		// Fallback: ANSI escape codes
		fmt.Print("\033[2J\033[H")
	}
}

func getTerminalHeight() int {
	switch runtime.GOOS {
	case "windows":
		// Windows doesn't have tput, use a default
		return 24
	default:
		cmd := exec.Command("tput", "lines")
		output, err := cmd.Output()
		if err != nil {
			return 24
		}
		var height int
		fmt.Sscanf(string(output), "%d", &height)
		return height
	}
}

func getTerminalWidth() int {
	switch runtime.GOOS {
	case "windows":
		// Windows doesn't have tput, use a default
		return 120
	default:
		cmd := exec.Command("tput", "cols")
		output, err := cmd.Output()
		if err != nil {
			return 120
		}
		var width int
		fmt.Sscanf(string(output), "%d", &width)
		return width
	}
}

func bbdnsTitle(){
	fmt.Println("╔════════════════════════════════╗")
	fmt.Println("║ BBDNS REDIRECTOR SERVER        ║")
	fmt.Println("║ 20260210                       ║")
	fmt.Println("║ Basic Bitch Domain Name System ║")
	fmt.Println("╚════════════════════════════════╝\n")
}

func hideCursor() {
	fmt.Print("\033[?25l")
}

func showCursor() {
	fmt.Print("\033[?25h")
}

func drawUI(server *DNSServer, configFile string, addrs string) {
	clearScreen()
	
	paused := server.paused.Load()
	
	// Draw title
	bbdnsTitle()

	
	// Draw logs - always draw max_logs lines
	logs := server.getLogs()
	maxLogs := server.config.MaxLogs
	
	// Calculate how many empty lines we need
	emptyLines := maxLogs - len(logs)
	
	// Draw empty lines first (if any)
	for i := 0; i < emptyLines; i++ {
		fmt.Println()
	}
	
	// Draw actual logs
	for _, logLine := range logs {
		fmt.Println(logLine)
	}
	
	// Add spacing before status bar
	fmt.Println()
	
	// Draw status bar
	termWidth := getTerminalWidth()
	
	// Separator line
	fmt.Println(strings.Repeat("─", termWidth))
	
	// Status bar content
	pausedStr := "Pause"
	if paused {
		pausedStr = "UN-PAUSE"
	}
	strConfigFile := filepath.Base(configFile)
	leftStr := fmt.Sprintf("[ Q:Quit | P:%s | R:Reload %s ]", pausedStr, strConfigFile)
	
	// Stats
	requests := server.requestCount.Load()
	passthrough := server.passthroughCount.Load()
	redirects := server.redirectCount.Load()
	rightStr := fmt.Sprintf("/ IP:%s | Requests:%d | Passthrough:%d | Redirects:%d \\ ", addrs, requests, passthrough, redirects)
	
	// Calculate padding
	padding := termWidth - len(leftStr) - len(rightStr)
	if padding < 0 { padding = 0 }
	
	// Print status bar with reverse video
	fmt.Print("\033[7m") // Reverse video
	fmt.Print(leftStr)
	fmt.Print(strings.Repeat(" ", padding))
	fmt.Print(rightStr)
	fmt.Print("\033[0m") // Reset
	fmt.Println()
}

func handleKeyboard(server *DNSServer, configFile string, quit chan bool, redraw chan bool) {
	// Put terminal in raw mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		server.addLog(fmt.Sprintf("[ERROR] Failed to set raw mode: %v", err))
		return
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)
	
	var b []byte = make([]byte, 1)
	for {
		n, err := os.Stdin.Read(b)
		if err != nil || n == 0 {
			continue
		}
		
		switch b[0] {
		case 'q', 'Q', 3: // 3 is Ctrl+C
			quit <- true
			return
		case 'p', 'P':
			if server.paused.Load() {
				server.paused.Store(false)
				server.addLog("[SYSTEM] DNS server resumed")
			} else {
				server.paused.Store(true)
				server.addLog("[SYSTEM] DNS server paused")
			}
			redraw <- true
		case 'r', 'R':
			server.addLog("[SYSTEM] Reloading config...")
			server.resetStats()
			
			err := server.reloadConfig(configFile)
			if err != nil {
				server.addLog(fmt.Sprintf("[ERROR] Failed to reload config: %v", err))
			} else {
				server.addLog("[SYSTEM] Config reloaded successfully")
				
				// Show default redirect if set
				if server.config.DefaultRedirect != "" {
					server.addLog(fmt.Sprintf("Default redirect: %s", server.config.DefaultRedirect))
				}
				
				// Re-resolve redirect targets
				server.addLog("Pre-resolving redirect targets...")
				for hostname, target := range server.config.redirectMap {
					if net.ParseIP(target) != nil {
						server.addLog(fmt.Sprintf("Redirect: %s -> %s (direct IP)", hostname, target))
					} else {
						ips, err := server.resolveHostname(target)
						if err != nil {
							server.addLog(fmt.Sprintf("Warning: Failed to resolve %s: %v", target, err))
						} else {
							server.addLog(fmt.Sprintf("Redirect: %s -> %s (%v)", hostname, target, ips))
						}
					}
				}
			}
			redraw <- true
		}
	}
}

func main() {
	var configFile string
	
	if len(os.Args) < 2 {
		// No arguments provided, check if config.yaml exists
		configFile = "config.yaml"
		if _, err := os.Stat(configFile); os.IsNotExist(err) {
			bbdnsTitle()
			// config.yaml doesn't exist, create an example
			fmt.Println("Usage: bbdns customConfig.yaml\n")
			fmt.Println("No config file specified and config.yaml not found.")
			fmt.Println("Creating example config.yaml...")
			
			exampleConfig := `# BBDNS Redirector Configuration

# Address to listen on (default: :53)
listen_address: ":53"

# Passthrough DNS server to use for resolution
passthrough_dns: "8.8.8.8:53"

# Maximum number of log lines to display (default: 20)
max_logs: 19 # Werid number cos windows is weird, you can make your terminial as large as you want though.

# Default redirect address (optional)
# If specified, any redirect without an explicit target will use this address
default: "10.0.0.44"

# Hostname redirection rules
# Format: 
#   "hostname": "target_ip_or_hostname"  - Redirect to specific target
#   "hostname":                          - Redirect to default (if default is set)
#
# When a device asks for the hostname, we return the target IP/hostname instead
redirects:
  # Examples
  # "example.com": "192.168.1.100"       # Redirect to specific IP
  # "test.example.com":                  # Use default redirect
  # "api.example.com": "my-server.local" # Redirect to another hostname
`
			if err := os.WriteFile(configFile, []byte(exampleConfig), 0644); err != nil {
				fmt.Printf("Error creating example config: %v\n", err)
				os.Exit(1)
			}
			
			fmt.Println("Example config.yaml created successfully!\n")
			fmt.Println("Edit config.yaml with your redirect rules, then run:")
			switch runtime.GOOS {
				case "windows":
					fmt.Println("  bbdns.exe\n")
				default:
					fmt.Println("  sudo ./bbdns\n")
			}
			fmt.Println("You can just run bbdns with no args to load the default config.yaml that was just created")
			fmt.Println("Press 'Enter' to exit...")
			bufio.NewReader(os.Stdin).ReadBytes('\n') 
			os.Exit(0)
		}
	} else {
		configFile = os.Args[1]
	}

	config, err := loadConfig(configFile)
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
	}

	server := NewDNSServer(config)

	// Pre-resolve all redirect targets that are hostnames
	server.addLog("Loading config from " + configFile + "...")
	
	// Show default redirect if set
	if config.DefaultRedirect != "" {
		server.addLog(fmt.Sprintf("Default redirect: %s", config.DefaultRedirect))
	}
	
	//TODO: filter to only show the last like 5 or so.
	server.addLog("Pre-resolving redirect targets...")
	for hostname, target := range config.redirectMap {
		// Check if target is an IP or hostname
		if net.ParseIP(target) != nil {
			server.addLog(fmt.Sprintf("Redirect: %s -> %s (direct IP)", hostname, target))
		} else {
			ips, err := server.resolveHostname(target)
			if err != nil {
				server.addLog(fmt.Sprintf("Warning: Failed to resolve %s: %v", target, err))
			} else {
				server.addLog(fmt.Sprintf("Redirect: %s -> %s (%v)", hostname, target, ips))
			}
		}
	}

	dns.HandleFunc(".", server.handleDNSRequest)

	dnsServer := &dns.Server{
		Addr: config.ListenAddress,
		Net:  "udp",
	}

	server.addLog(fmt.Sprintf("Starting DNS server on %s", config.ListenAddress))
	server.addLog(fmt.Sprintf("Passthrough DNS: %s", config.PassthroughDNS))
	server.addLog(fmt.Sprintf("Redirect rules: %d", len(config.redirectMap)))
	server.addLog(fmt.Sprintf("DNS Config loaded. Waiting for requests...\n"))
	
	// Hide cursor for cleaner UI
	hideCursor()
	defer showCursor()

	//Get ip
	addrs := GetLocalIP()
	// Initial draw
	drawUI(server, configFile, addrs)
	
	// Start DNS server in background
	go func() {
		if err := dnsServer.ListenAndServe(); err != nil {
			server.addLog(fmt.Sprintf("[ERROR] Failed to start server: %v", err))
		}
	}()

	// Start keyboard handler
	quit := make(chan bool)
	redraw := make(chan bool, 10)
	go handleKeyboard(server, configFile, quit, redraw)
	
	// UI redraw loop
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-quit:
			showCursor()
			clearScreen()
			fmt.Println("Shutting down BBDNS...")
			dnsServer.Shutdown()
			fmt.Println("Goodbye ^__^/")
			return
		case <-redraw:
			drawUI(server, configFile, addrs)
		case <-ticker.C:
			drawUI(server, configFile, addrs)
		}
	}
}
