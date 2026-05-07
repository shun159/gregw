package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"gopkg.in/yaml.v3"
)

const (
	configFlagFibLookup uint32 = 1 << 0
)

const (
	statPass uint32 = iota
	statDrop
	statAbort
	statEncap
	statDecap
	statMtuDrop
	statNoConfig
	statNoLanConfig
	statBypass
	statFibSuccess
	statFibNoNeigh
	statFibFail
	statFibWrongIf
	statDecapPass
	statDecapNotGRE
	statDecapBadGRE
	statDecapSlow
	statRedirectWan
	statRedirectLan
	statIcmpFragNeeded
	statMax
)

type tunnelConfig struct {
	OuterSrcIP uint32
	OuterDstIP uint32
	SrcMAC     [6]byte
	DstMAC     [6]byte
	WanIfindex uint32
	Flags      uint32
}

type lanConfig struct {
	GatewayIP uint32
	InnerMTU  uint16
	Flags     uint16
}

type lanListFlag []string

func (l *lanListFlag) String() string {
	return strings.Join(*l, ",")
}

func (l *lanListFlag) Set(s string) error {
	for _, part := range strings.Split(s, ",") {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		*l = append(*l, name)
	}
	return nil
}

type fileConfig struct {
	WAN      string             `yaml:"wan"`
	LANs     []fileLANConfig    `yaml:"lans"`
	Tunnel   fileTunnelConfig   `yaml:"tunnel"`
	XDP      fileXDPConfig      `yaml:"xdp"`
	Defaults fileDefaultsConfig `yaml:"defaults"`
}

type fileLANConfig struct {
	Name     string `yaml:"name"`
	Gateway  string `yaml:"gateway"`
	InnerMTU uint   `yaml:"inner_mtu"`
}

type fileTunnelConfig struct {
	Local           string `yaml:"local"`
	Remote          string `yaml:"remote"`
	SrcMAC          string `yaml:"src_mac"`
	DstMAC          string `yaml:"dst_mac"`
	FibLookup       *bool  `yaml:"fib_lookup"`
	ResolveInterval string `yaml:"resolve_interval"`
	ResolveTimeout  string `yaml:"resolve_timeout"`
}

type fileXDPConfig struct {
	Mode  string `yaml:"mode"`
	Decap *bool  `yaml:"decap"`
}

type fileDefaultsConfig struct {
	InnerMTU  uint   `yaml:"inner_mtu"`
	BypassDst string `yaml:"bypass_dst"`
}

func main() {
	configPath := scanStringFlag(os.Args[1:], "config")
	fileCfg, err := loadFileConfig(configPath)
	fatalf(err, "load config")

	lanNames := lanListFlag(lanNamesFromConfig(fileCfg))
	var (
		configFile   = flag.String("config", configPath, "YAML configuration file")
		lansCSV      = flag.String("lans", "", "comma-separated LAN interfaces to attach XDP to; equivalent to repeated -lan")
		wanName      = flag.String("wan", fileCfg.WAN, "WAN interface used as XDP redirect target")
		localIP      = flag.String("local", fileCfg.Tunnel.Local, "outer IPv4 source address")
		remoteIP     = flag.String("remote", fileCfg.Tunnel.Remote, "outer IPv4 destination address")
		srcMAC       = flag.String("src-mac", fileCfg.Tunnel.SrcMAC, "outer Ethernet source MAC; defaults to WAN interface MAC")
		dstMAC       = flag.String("dst-mac", fileCfg.Tunnel.DstMAC, "outer Ethernet destination MAC; if empty, resolve the remote/next-hop MAC via ARP/neighbor table")
		innerMTU     = flag.Uint("inner-mtu", fileCfg.Defaults.InnerMTU, "default maximum inner IPv4 total length before GRE encapsulation; 0 disables check; per-LAN YAML inner_mtu can override")
		bypassDst    = flag.String("bypass-dst", fileCfg.Defaults.BypassDst, "legacy override for all LAN gateway bypass IPs; normally leave empty and use each LAN interface IPv4 address or per-LAN gateway")
		fibLookup    = flag.Bool("fib-lookup", boolPtrValue(fileCfg.Tunnel.FibLookup, true), "resolve outer Ethernet src/dst MAC in XDP with bpf_fib_lookup; falls back to config MAC on lookup failure")
		decapEnabled = flag.Bool("decap", boolPtrValue(fileCfg.XDP.Decap, true), "attach WAN-side XDP GRE decap program for return traffic")
		mode         = flag.String("mode", defaultString(fileCfg.XDP.Mode, "driver"), "XDP attach mode: driver, generic, or auto")
	)
	flag.Var(&lanNames, "lan", "LAN interface to attach XDP encap to; may be repeated or comma-separated")
	flag.Parse()
	flagWasSet := visitedFlags()

	if *configFile != configPath {
		log.Printf("warning: -config was changed after defaults were loaded; using %s", configPath)
	}
	if *lansCSV != "" {
		fatalf(lanNames.Set(*lansCSV), "parse -lans")
	}
	lanNames = dedupStrings(lanNames)

	if len(lanNames) == 0 || *wanName == "" || *localIP == "" || *remoteIP == "" {
		flag.Usage()
		os.Exit(2)
	}

	lanFileCfgs, err := lanConfigsByName(fileCfg)
	fatalf(err, "parse LAN config")

	lanIfs := make([]*net.Interface, 0, len(lanNames))
	for _, name := range lanNames {
		lan, err := net.InterfaceByName(name)
		fatalf(err, "lookup LAN interface "+name)
		lanIfs = append(lanIfs, lan)
	}
	wan, err := net.InterfaceByName(*wanName)
	fatalf(err, "lookup WAN interface")

	localAddr, err := parseIPv4Addr(*localIP)
	fatalf(err, "parse local IP")
	remoteAddr, err := parseIPv4Addr(*remoteIP)
	fatalf(err, "parse remote IP")

	cfg, err := buildTunnelConfig(localAddr, remoteAddr, *srcMAC, *dstMAC, wan.HardwareAddr)
	fatalf(err, "build tunnel config")
	cfg.WanIfindex = uint32(wan.Index)
	if *fibLookup {
		cfg.Flags |= configFlagFibLookup
	}

	bypassOverride := netip.Addr{}
	if *bypassDst != "" {
		bypassOverride, err = parseIPv4Addr(*bypassDst)
		fatalf(err, "parse bypass-dst")
	}

	lanCfgs := make(map[int]lanConfig, len(lanIfs))
	for _, lan := range lanIfs {
		lanFileCfg := lanFileCfgs[lan.Name]

		gw := bypassOverride
		if lanFileCfg.Gateway != "" {
			gw, err = parseIPv4Addr(lanFileCfg.Gateway)
			fatalf(err, fmt.Sprintf("parse gateway for LAN interface %s", lan.Name))
		}
		if !gw.IsValid() {
			gw, err = firstIPv4Addr(lan)
			fatalf(err, fmt.Sprintf("discover IPv4 address for LAN interface %s", lan.Name))
		}

		mtu := *innerMTU
		if !flagWasSet["inner-mtu"] && lanFileCfg.InnerMTU != 0 {
			mtu = lanFileCfg.InnerMTU
		}
		if mtu > 65535 {
			log.Fatalf("inner-mtu for %s must be <= 65535", lan.Name)
		}

		gw4 := gw.As4()
		lanCfgs[lan.Index] = lanConfig{
			GatewayIP: binary.BigEndian.Uint32(gw4[:]),
			InnerMTU:  uint16(mtu),
		}
	}

	fatalf(rlimit.RemoveMemlock(), "remove memlock rlimit")

	objs := bpfObjects{}
	fatalf(loadBpfObjects(&objs, nil), "load BPF objects")
	defer objs.Close()

	var cfgKey uint32 = 0
	fatalf(objs.TunnelConfig.Put(cfgKey, cfg), "update config map")

	wanIfindex := uint32(wan.Index)
	fatalf(objs.TxPorts.Put(wanIfindex, wanIfindex), "update DEVMAP WAN entry")
	for _, lan := range lanIfs {
		ifindex := uint32(lan.Index)
		fatalf(objs.TxPorts.Put(ifindex, ifindex), "update DEVMAP LAN entry "+lan.Name)
		fatalf(objs.LanConfigs.Put(ifindex, lanCfgs[lan.Index]), "update LAN config "+lan.Name)
	}

	flags, err := parseXDPMode(*mode)
	fatalf(err, "parse XDP mode")

	attached := make([]link.Link, 0, len(lanIfs)+1)
	defer func() {
		for i := len(attached) - 1; i >= 0; i-- {
			_ = attached[i].Close()
		}
	}()

	for _, lan := range lanIfs {
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpGreEncap,
			Interface: lan.Index,
			Flags:     flags,
		})
		fatalf(err, "attach LAN-side XDP GRE encap program to "+lan.Name)
		attached = append(attached, l)
	}

	if *decapEnabled {
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpGreDecap,
			Interface: wan.Index,
			Flags:     flags,
		})
		fatalf(err, "attach WAN-side XDP GRE decap program")
		attached = append(attached, l)
	}

	if configPath != "" {
		log.Printf("loaded config: %s", configPath)
	}
	log.Printf("attached XDP GRE programs: encap_lans=%s decap=%s(index=%d enabled=%t) mode=%s fib_lookup=%t", formatLANs(lanIfs, lanCfgs), wan.Name, wan.Index, *decapEnabled, *mode, *fibLookup)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			printStats(&objs)
		case sig := <-stop:
			log.Printf("received %s, detaching", sig)
			return
		}
	}
}

func loadFileConfig(path string) (fileConfig, error) {
	cfg := defaultFileConfig()
	if path == "" {
		return cfg, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func defaultFileConfig() fileConfig {
	return fileConfig{
		Tunnel: fileTunnelConfig{
			FibLookup:       boolPtr(true),
			ResolveInterval: "5s",
			ResolveTimeout:  "3s",
		},
		XDP: fileXDPConfig{
			Mode:  "driver",
			Decap: boolPtr(true),
		},
		Defaults: fileDefaultsConfig{
			InnerMTU: 1476,
		},
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func boolPtrValue(v *bool, fallback bool) bool {
	if v == nil {
		return fallback
	}
	return *v
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func scanStringFlag(args []string, name string) string {
	short := "-" + name
	long := "--" + name
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == short || arg == long {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if strings.HasPrefix(arg, short+"=") {
			return strings.TrimPrefix(arg, short+"=")
		}
		if strings.HasPrefix(arg, long+"=") {
			return strings.TrimPrefix(arg, long+"=")
		}
	}
	return ""
}

func visitedFlags() map[string]bool {
	out := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		out[f.Name] = true
	})
	return out
}

func lanNamesFromConfig(cfg fileConfig) []string {
	out := make([]string, 0, len(cfg.LANs))
	for _, lan := range cfg.LANs {
		name := strings.TrimSpace(lan.Name)
		if name == "" {
			continue
		}
		out = append(out, name)
	}
	return out
}

func lanConfigsByName(cfg fileConfig) (map[string]fileLANConfig, error) {
	out := make(map[string]fileLANConfig, len(cfg.LANs))
	for _, lan := range cfg.LANs {
		lan.Name = strings.TrimSpace(lan.Name)
		if lan.Name == "" {
			return nil, fmt.Errorf("lans[].name is required")
		}
		if _, exists := out[lan.Name]; exists {
			return nil, fmt.Errorf("duplicate LAN interface in config: %s", lan.Name)
		}
		out[lan.Name] = lan
	}
	return out, nil
}

func fatalf(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}

func parseXDPMode(s string) (link.XDPAttachFlags, error) {
	switch strings.ToLower(s) {
	case "driver", "native":
		return link.XDPDriverMode, nil
	case "generic", "skb":
		return link.XDPGenericMode, nil
	case "auto", "":
		return 0, nil
	default:
		return 0, fmt.Errorf("unknown mode %q", s)
	}
}

func buildTunnelConfig(localAddr, remoteAddr netip.Addr, srcMACFlag, dstMACFlag string, defaultSrcMAC net.HardwareAddr) (tunnelConfig, error) {
	src := defaultSrcMAC
	if srcMACFlag != "" {
		parsed, err := net.ParseMAC(srcMACFlag)
		if err != nil {
			return tunnelConfig{}, fmt.Errorf("src-mac: %w", err)
		}
		src = parsed
	}
	if len(src) != 6 {
		return tunnelConfig{}, fmt.Errorf("src-mac must be 6 bytes, got %q", src)
	}

	local4 := localAddr.As4()
	remote4 := remoteAddr.As4()
	cfg := tunnelConfig{
		OuterSrcIP: binary.BigEndian.Uint32(local4[:]),
		OuterDstIP: binary.BigEndian.Uint32(remote4[:]),
	}
	return cfg, nil
}

func parseIPv4Addr(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, err
	}
	if !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("not IPv4: %s", s)
	}
	return addr, nil
}

func firstIPv4Addr(iface *net.Interface) (netip.Addr, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil {
			addr, ok := netip.AddrFromSlice(ip4)
			if ok {
				return addr, nil
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("no IPv4 address on %s", iface.Name)
}

func printStats(objs *bpfObjects) {
	names := map[uint32]string{
		statPass:           "pass",
		statDrop:           "drop",
		statAbort:          "abort",
		statEncap:          "encap",
		statDecap:          "decap",
		statMtuDrop:        "mtu_drop",
		statNoConfig:       "no_config",
		statNoLanConfig:    "no_lan_config",
		statBypass:         "bypass",
		statFibSuccess:     "fib_success",
		statFibNoNeigh:     "fib_no_neigh",
		statFibFail:        "fib_fail",
		statFibWrongIf:     "fib_wrong_if",
		statDecapPass:      "decap_pass",
		statDecapNotGRE:    "decap_not_gre",
		statDecapBadGRE:    "decap_bad_gre",
		statDecapSlow:      "decap_slow",
		statRedirectWan:    "redirect_wan",
		statRedirectLan:    "redirect_lan",
		statIcmpFragNeeded: "icmp_frag_needed",
	}

	parts := make([]string, 0, len(names))
	for k := uint32(0); k < statMax; k++ {
		var values []uint64
		if err := objs.Stats.Lookup(k, &values); err != nil {
			log.Printf("stats lookup key=%d: %v", k, err)
			continue
		}
		var sum uint64
		for _, v := range values {
			sum += v
		}
		parts = append(parts, fmt.Sprintf("%s=%d", names[k], sum))
	}
	log.Print(strings.Join(parts, " "))
}

func dedupStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func formatLANs(lans []*net.Interface, cfgs map[int]lanConfig) string {
	parts := make([]string, 0, len(lans))
	for _, lan := range lans {
		cfg := cfgs[lan.Index]
		gw := uint32ToIPv4(cfg.GatewayIP)
		parts = append(parts, fmt.Sprintf("%s(index=%d gw=%s mtu=%d)", lan.Name, lan.Index, gw, cfg.InnerMTU))
	}
	return strings.Join(parts, ",")
}

func uint32ToIPv4(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}
