package controller

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Real LAN discovery (v1.48+): the old Discover button only listed agents
// that already dialed home, so a house PC without the agent installed could
// never appear. /api/lan-scan enumerates local /24s, merges the ARP cache
// (sees silent hosts instantly) with a fast TCP sweep for Windows ports
// (445 SMB, 135 RPC, 3389 RDP), reverse-resolves names, and flags which IPs
// already have an agent so the UI can offer Clone (push install) to the rest.

type lanHostJSON struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	MAC      string `json:"mac,omitempty"`
	SMB      bool   `json:"smb"`
	RPC      bool   `json:"rpc"`
	RDP      bool   `json:"rdp"`
	Agent    bool   `json:"agent"`
	Source   string `json:"source"` // "arp", "smb", "rpc", "rdp", "arp+smb"...
}

var arpIPRe = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3})`)
var arpMACRe = regexp.MustCompile(`(?i)([0-9a-f]{2}[:-]){5}[0-9a-f]{2}`)

func localV4Nets() []string {
	var nets []string
	seen := map[string]bool{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nets
	}
	for _, fi := range ifaces {
		if fi.Flags&net.FlagUp == 0 || fi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := fi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			ip = ip.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			// Collapse to /24 for sweep speed (home LANs are /24).
			base := net.IPv4(ip[0], ip[1], ip[2], 0).String() + "/24"
			if !seen[base] {
				seen[base] = true
				nets = append(nets, base)
			}
		}
	}
	sort.Strings(nets)
	if len(nets) > 4 {
		nets = nets[:4] // safety: never sweep more than 4x254
	}
	return nets
}

func arpTable() map[string]string {
	out := map[string]string{}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("arp", "-a")
	} else {
		cmd = exec.Command("sh", "-c", "arp -a 2>/dev/null || ip neigh show 2>/dev/null")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	//nolint:gosec // arp with fixed args only
	c := exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
	raw, err := c.CombinedOutput()
	if err != nil || len(raw) == 0 {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		l := strings.ToLower(line)
		if strings.Contains(l, "incomplete") || strings.Contains(l, "no entry") {
			continue
		}
		ipm := arpIPRe.FindString(line)
		if ipm == "" || strings.HasPrefix(ipm, "224.") || strings.HasPrefix(ipm, "239.") {
			continue
		}
		ip := net.ParseIP(ipm)
		if ip == nil || ip.IsMulticast() || ip.IsLoopback() {
			continue
		}
		mac := ""
		if m := arpMACRe.FindString(line); m != "" {
			// Skip broadcast/empty MACs.
			lm := strings.ToLower(m)
			if lm != "ff-ff-ff-ff-ff-ff" && lm != "ff:ff:ff:ff:ff:ff" && lm != "00-00-00-00-00-00" {
				mac = m
			}
		}
		// Windows prints dynamic/static entries for dead hosts too; keep
		// them — the sweep below confirms liveness, ARP just seeds.
		if _, ok := out[ipm]; !ok {
			out[ipm] = mac
		}
	}
	return out
}

func tcpOpen(ip string, port int, d time.Duration) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, itoa(port)), d)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// agentIPs returns the set of remote IPs belonging to known agents
// (remote() is "IP:port").
func (s *Server) agentIPs() map[string]bool {
	set := map[string]bool{}
	for _, a := range s.Agents() {
		if rem, _ := a["remote"].(string); rem != "" {
			if h, _, err := net.SplitHostPort(rem); err == nil {
				set[h] = true
			} else if ip := net.ParseIP(strings.TrimSpace(rem)); ip != nil {
				set[ip.String()] = true
			}
		}
	}
	return set
}

func reverseName(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// lanScanNets sweeps the given /24 CIDRs + ARP seed and returns live hosts.
func (s *Server) lanScanNets(cidrs []string) []lanHostJSON {
	arp := arpTable()
	known := s.agentIPs()

	type probe struct {
		smb, rpc, rdp bool
		fromARP       bool
		mac           string
	}
	found := map[string]*probe{}
	var mu sync.Mutex
	seed := func(ip, mac string) {
		mu.Lock()
		p := found[ip]
		if p == nil {
			p = &probe{}
			found[ip] = p
		}
		p.fromARP = true
		if mac != "" && p.mac == "" {
			p.mac = mac
		}
		mu.Unlock()
	}
	for ip, mac := range arp {
		seed(ip, mac)
	}

	// Build target list from CIDRs.
	var targets []string
	seenT := map[string]bool{}
	for _, c := range cidrs {
		ip, ipnet, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			continue
		}
		ip4 := ip.To4()
		mask4 := net.IP(ipnet.Mask).To4()
		if ip4 == nil || mask4 == nil {
			continue
		}
		// Only sweep /24 or smaller views (avoid /16 storms): take the
		// /24 containing the interface address.
		base := net.IPv4(ip4[0], ip4[1], ip4[2], 0)
		for i := 1; i < 255; i++ {
			h := net.IPv4(base[0], base[1], base[2], byte(i)).String()
			if !seenT[h] {
				seenT[h] = true
				targets = append(targets, h)
			}
		}
		_ = ipnet
	}
	// Also always probe ARP hosts even if outside our /24s (multi-subnet homes).
	for ip := range arp {
		if !seenT[ip] {
			seenT[ip] = true
			targets = append(targets, ip)
		}
	}

	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup
	for _, ip := range targets {
		ip := ip
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			smb := tcpOpen(ip, 445, 400*time.Millisecond)
			var rpc, rdp bool
			if smb {
				rpc = tcpOpen(ip, 135, 300*time.Millisecond)
				rdp = tcpOpen(ip, 3389, 300*time.Millisecond)
			} else {
				// Hosts with SMB closed (firewall) still answer RPC/RDP;
				// one quick extra probe before declaring dead.
				rpc = tcpOpen(ip, 135, 350*time.Millisecond)
				if !rpc {
					rdp = tcpOpen(ip, 3389, 350*time.Millisecond)
				}
			}
			if !smb && !rpc && !rdp {
				return // silent/dead: keep only if ARP saw it AND it answers ping-ish? drop to cut noise
			}
			mu.Lock()
			p := found[ip]
			if p == nil {
				p = &probe{}
				found[ip] = p
			}
			p.smb, p.rpc, p.rdp = smb, rpc, rdp
			mu.Unlock()
		}()
	}
	wg.Wait()

	// Keep ARP-only hosts too (house PCs with firewall on vanish from TCP
	// but are exactly what users complain "doesn't pick up"). Mark them
	// alive via ARP presence; UI shows them as silent/firewalled.
	out := make([]lanHostJSON, 0, len(found))
	for ip, p := range found {
		if !p.smb && !p.rpc && !p.rdp && !p.fromARP {
			continue
		}
		src := ""
		switch {
		case p.fromARP && (p.smb || p.rpc || p.rdp):
			src = "arp+ports"
		case p.fromARP:
			src = "arp"
		default:
			src = "ports"
		}
		out = append(out, lanHostJSON{
			IP: ip, MAC: p.mac, SMB: p.smb, RPC: p.rpc, RDP: p.rdp,
			Agent: known[ip], Source: src,
		})
	}
	// Reverse-resolve names in parallel (fast, bounded).
	var wg2 sync.WaitGroup
	sem2 := make(chan struct{}, 32)
	for i := range out {
		i := i
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			sem2 <- struct{}{}
			defer func() { <-sem2 }()
			out[i].Hostname = reverseName(out[i].IP)
		}()
	}
	wg2.Wait()
	sort.Slice(out, func(a, b int) bool { return out[a].IP < out[b].IP })
	return out
}

func (s *Server) handleLanScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	cidrs := localV4Nets()
	if q := strings.TrimSpace(r.URL.Query().Get("cidr")); q != "" {
		if _, _, err := net.ParseCIDR(q); err == nil {
			cidrs = []string{q}
		} else if ip := net.ParseIP(q); ip != nil {
			ip4 := ip.To4()
			if ip4 != nil {
				cidrs = []string{net.IPv4(ip4[0], ip4[1], ip4[2], 0).String() + "/24"}
			}
		}
	}
	if len(cidrs) == 0 {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"hosts": []lanHostJSON{}, "subnets": []string{},
			"error": "no local IPv4 subnets found (VPN-only / IPv6-only?)",
		})
		return
	}
	hosts := s.lanScanNets(cidrs)
	if hosts == nil {
		hosts = []lanHostJSON{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"hosts": hosts, "subnets": cidrs,
	})
}
