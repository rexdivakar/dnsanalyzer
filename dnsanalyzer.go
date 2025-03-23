package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Version information
const (
	AppName    = "DNS Analyzer"
	AppVersion = "1.0.0"
)

// DNSAnalyzer represents the main analyzer structure
type DNSAnalyzer struct {
	Domain        string            `json:"domain"`
	Time          time.Time         `json:"timestamp"`
	Records       Records           `json:"dns_records"`
	IPInfo        IPInfo            `json:"ip_info,omitempty"`
	TLSInfo       TLSInfo           `json:"tls_info,omitempty"`
	HTTPInfo      HTTPInfo          `json:"http_info,omitempty"`
	Performance   Performance       `json:"performance,omitempty"`
	EmailSecurity EmailSecurity     `json:"email_security,omitempty"`
	DNSSEC        DNSSECInfo        `json:"dnssec,omitempty"`
	Ports         PortInfo          `json:"ports,omitempty"`
	Subdomains    []string          `json:"subdomains,omitempty"`
	Technologies  []Technology      `json:"technologies,omitempty"`
	Propagation   PropagationInfo   `json:"propagation,omitempty"`
	SecurityScore SecurityScoreInfo `json:"security_score,omitempty"`
	Typosquatting TyposquattingInfo `json:"typosquatting,omitempty"`
}

// Records holds all DNS record types
type Records struct {
	A      []string `json:"a,omitempty"`
	AAAA   []string `json:"aaaa,omitempty"`
	MX     []string `json:"mx,omitempty"`
	NS     []string `json:"ns,omitempty"`
	TXT    []string `json:"txt,omitempty"`
	SOA    []string `json:"soa,omitempty"`
	CNAME  []string `json:"cname,omitempty"`
	CAA    []string `json:"caa,omitempty"`
	DNSKEY []string `json:"dnskey,omitempty"`
	DS     []string `json:"ds,omitempty"`
}

// IPInfo contains IP-related information
type IPInfo struct {
	Address    string    `json:"address,omitempty"`
	Hostnames  []string  `json:"hostnames,omitempty"`
	IsCDN      bool      `json:"is_cdn,omitempty"`
	ASN        string    `json:"asn,omitempty"`
	HasIPv6    bool      `json:"has_ipv6,omitempty"`
	ReverseDNS string    `json:"reverse_dns,omitempty"`
	GeoIP      GeoIPInfo `json:"geo_ip,omitempty"`
}

// GeoIPInfo contains geographical information for an IP
type GeoIPInfo struct {
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	City        string  `json:"city,omitempty"`
	Region      string  `json:"region,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	Org         string  `json:"org,omitempty"`
}

// TLSInfo contains SSL/TLS certificate information
type TLSInfo struct {
	Supported   bool      `json:"supported"`
	Issuer      string    `json:"issuer,omitempty"`
	Subject     string    `json:"subject,omitempty"`
	Version     int       `json:"version,omitempty"`
	ValidFrom   time.Time `json:"valid_from,omitempty"`
	ValidUntil  time.Time `json:"valid_until,omitempty"`
	DNSNames    []string  `json:"dns_names,omitempty"`
	CipherSuite string    `json:"cipher_suite,omitempty"`
	Protocol    string    `json:"protocol,omitempty"`
	ExpiresIn   int       `json:"expires_in_days,omitempty"`
	SelfSigned  bool      `json:"self_signed,omitempty"`
}

// HTTPInfo contains HTTP response information
type HTTPInfo struct {
	StatusCode    int               `json:"status_code,omitempty"`
	Server        string            `json:"server,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	HasSecurity   bool              `json:"has_security_headers"`
	SecurityFlags []string          `json:"security_flags,omitempty"`
	Redirects     []string          `json:"redirects,omitempty"`
	CSP           CSPInfo           `json:"csp,omitempty"`
}

// CSPInfo contains Content Security Policy information
type CSPInfo struct {
	Present    bool                `json:"present"`
	Directives map[string][]string `json:"directives,omitempty"`
	Score      int                 `json:"score"` // 0-100
	Weaknesses []string            `json:"weaknesses,omitempty"`
}

// Performance contains performance metrics
type Performance struct {
	DNSResolutionTimeMs int64 `json:"dns_resolution_time_ms"`
	HTTPResponseTimeMs  int64 `json:"http_response_time_ms,omitempty"`
	TLSHandshakeTimeMs  int64 `json:"tls_handshake_time_ms,omitempty"`
}

// EmailSecurity contains email security record information
type EmailSecurity struct {
	HasSPF      bool     `json:"has_spf"`
	SPFValue    string   `json:"spf_value,omitempty"`
	HasDKIM     bool     `json:"has_dkim"`
	DKIMKeys    []string `json:"dkim_keys,omitempty"`
	HasDMARC    bool     `json:"has_dmarc"`
	DMARCPolicy string   `json:"dmarc_policy,omitempty"`
}

// DNSSECInfo contains DNSSEC validation information
type DNSSECInfo struct {
	Enabled    bool     `json:"enabled"`
	Validated  bool     `json:"validated"`
	Algorithms []string `json:"algorithms,omitempty"`
	KeyTags    []int    `json:"key_tags,omitempty"`
	Signatures []string `json:"signatures,omitempty"`
}

// PortInfo contains open port information
type PortInfo struct {
	OpenPorts map[int]string `json:"open_ports,omitempty"`
	ScanTime  time.Duration  `json:"scan_time_ms"`
}

// Technology represents a detected technology on the website
type Technology struct {
	Name       string `json:"name"`
	Category   string `json:"category"`
	Confidence int    `json:"confidence"`
}

// PropagationInfo contains DNS propagation information
type PropagationInfo struct {
	Resolvers  map[string][]string `json:"resolvers"`
	Consistent bool                `json:"consistent"`
}

// SecurityScoreInfo contains security scoring information
type SecurityScoreInfo struct {
	OverallScore    int            `json:"overall_score"` // 0-100
	CategoryScores  map[string]int `json:"category_scores"`
	Recommendations []string       `json:"recommendations,omitempty"`
}

// TyposquattingInfo contains typosquatting detection information
type TyposquattingInfo struct {
	Variants           []string `json:"variants"`
	RegisteredVariants []string `json:"registered_variants,omitempty"`
}

func main() {
	// Define command line flags
	domainPtr := flag.String("domain", "", "Domain to analyze (required)")
	outputPtr := flag.String("output", "", "Output file path (optional)")
	jsonPtr := flag.Bool("json", false, "Output in JSON format")
	verbosePtr := flag.Bool("verbose", false, "Enable verbose output")
	fullScanPtr := flag.Bool("full", false, "Perform a full scan including all checks")
	
	// Feature flags
	dnsPtr := flag.Bool("dns", true, "Perform DNS record checks")
	tlsPtr := flag.Bool("tls", false, "Check SSL/TLS certificate")
	httpPtr := flag.Bool("http", false, "Analyze HTTP response and headers")
	portsPtr := flag.Bool("ports", false, "Scan for open ports")
	geoPtr := flag.Bool("geo", false, "Get geolocation information")
	emailPtr := flag.Bool("email", false, "Check email security (SPF, DKIM, DMARC)")
	dnssecPtr := flag.Bool("dnssec", false, "Validate DNSSEC")
	techPtr := flag.Bool("tech", false, "Detect website technologies")
	propPtr := flag.Bool("prop", false, "Check DNS propagation")
	subdomainsPtr := flag.Bool("sub", false, "Discover subdomains")
	typoPtr := flag.Bool("typo", false, "Check for typosquatting domains")
	
	// Parse flags
	flag.Parse()

	// Check if domain is provided
	if *domainPtr == "" {
		fmt.Println("Error: Domain is required")
		fmt.Println("Usage: dnsanalyzer -domain example.com [options]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// If full scan is enabled, enable all checks
	if *fullScanPtr {
		*tlsPtr = true
		*httpPtr = true
		*portsPtr = true
		*geoPtr = true
		*emailPtr = true
		*dnssecPtr = true
		*techPtr = true
		*propPtr = true
		*subdomainsPtr = true
		*typoPtr = true
	}

	// Ensure domain is properly formatted
	domain := *domainPtr
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	// Initialize analyzer
	analyzer := &DNSAnalyzer{
		Domain: *domainPtr,
		Time:   time.Now(),
		SecurityScore: SecurityScoreInfo{
			CategoryScores: make(map[string]int),
		},
	}

	// Perform DNS record checks
	if *dnsPtr {
		if *verbosePtr {
			fmt.Println("Getting DNS records...")
		}
		analyzer.getDNSRecords()
	}

	// Get IP information
	if *dnsPtr {
		if *verbosePtr {
			fmt.Println("Getting IP information...")
		}
		analyzer.getIPInfo()
	}

	// Get geolocation information
	if *geoPtr && analyzer.IPInfo.Address != "" {
		if *verbosePtr {
			fmt.Println("Getting geolocation information...")
		}
		analyzer.getGeoIPInfo()
	}

	// Check SSL/TLS
	if *tlsPtr {
		if *verbosePtr {
			fmt.Println("Checking SSL/TLS certificate...")
		}
		analyzer.getTLSInfo()
	}

	// Check HTTP response and headers
	if *httpPtr {
		if *verbosePtr {
			fmt.Println("Analyzing HTTP response...")
		}
		analyzer.getHTTPInfo()
	}

	// Check email security
	if *emailPtr {
		if *verbosePtr {
			fmt.Println("Checking email security records...")
		}
		analyzer.checkEmailSecurity()
	}

	// Check DNSSEC
	if *dnssecPtr {
		if *verbosePtr {
			fmt.Println("Validating DNSSEC...")
		}
		analyzer.checkDNSSEC()
	}

	// Scan for open ports
	if *portsPtr {
		if *verbosePtr {
			fmt.Println("Scanning for open ports...")
		}
		analyzer.scanPorts()
	}

	// Discover subdomains
	if *subdomainsPtr {
		if *verbosePtr {
			fmt.Println("Discovering subdomains...")
		}
		analyzer.discoverSubdomains()
	}

	// Detect technologies
	if *techPtr {
		if *verbosePtr {
			fmt.Println("Detecting website technologies...")
		}
		analyzer.detectTechnologies()
	}

	// Check DNS propagation
	if *propPtr {
		if *verbosePtr {
			fmt.Println("Checking DNS propagation...")
		}
		analyzer.checkPropagation()
	}

	// Check for typosquatting
	if *typoPtr {
		if *verbosePtr {
			fmt.Println("Checking for typosquatting domains...")
		}
		analyzer.checkTyposquatting()
	}

	// Calculate security score
	analyzer.calculateSecurityScore()

	// Output results
	if *jsonPtr {
		// JSON output
		jsonData, err := json.MarshalIndent(analyzer, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling to JSON: %v\n", err)
			os.Exit(1)
		}
		
		if *outputPtr != "" {
			// Write to file
			err = os.WriteFile(*outputPtr, jsonData, 0644)
			if err != nil {
				fmt.Printf("Error writing to file: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Results written to %s\n", *outputPtr)
		} else {
			// Print to stdout
			fmt.Println(string(jsonData))
		}
	} else {
		// Human-readable output
		output := printHumanReadable(analyzer)
		
		if *outputPtr != "" {
			// Write to file
			err := os.WriteFile(*outputPtr, []byte(output), 0644)
			if err != nil {
				fmt.Printf("Error writing to file: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Results written to %s\n", *outputPtr)
		} else {
			// Print to stdout
			fmt.Print(output)
		}
	}
}

// getDNSRecords fetches various DNS record types
func (a *DNSAnalyzer) getDNSRecords() {
	startTime := time.Now()
	
	recordTypes := []uint16{
		dns.TypeA,
		dns.TypeAAAA,
		dns.TypeMX,
		dns.TypeNS,
		dns.TypeTXT,
		dns.TypeSOA,
		dns.TypeCNAME,
		dns.TypeCAA,
		dns.TypeDNSKEY,
		dns.TypeDS,
	}

	// Create DNS client
	client := &dns.Client{
		Timeout: time.Second * 5,
	}

	for _, recordType := range recordTypes {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(a.Domain), recordType)
		msg.RecursionDesired = true

		// Try Google's DNS server first
		resp, _, err := client.Exchange(msg, "8.8.8.8:53")
		if err != nil || resp == nil || len(resp.Answer) == 0 {
			// Try Cloudflare's DNS as fallback
			resp, _, err = client.Exchange(msg, "1.1.1.1:53")
			if err != nil || resp == nil {
				continue
			}
		}

		// Process answers based on record type
		switch recordType {
		case dns.TypeA:
			for _, ans := range resp.Answer {
				if record, ok := ans.(*dns.A); ok {
					a.Records.A = append(a.Records.A, record.A.String())
				}
			}
		case dns.TypeAAAA:
			for _, ans := range resp.Answer {
				if record, ok := ans.(*dns.AAAA); ok {
					a.Records.AAAA = append(a.Records.AAAA, record.AAAA.String())
				}
			}
		case dns.TypeMX:
			for _, ans := range resp.Answer {
				if record, ok := ans.(*dns.MX); ok {
					a.Records.MX = append(a.Records.MX, fmt.Sprintf("%d %s", record.Preference, record.Mx))
				}
			}
		case dns.TypeNS:
			for _, ans := range resp.Answer {
				if record, ok := ans.(*dns.NS); ok {
					a.Records.NS = append(a.Records.NS, record.Ns)
				}
			}
		case dns.TypeTXT:
			for _, ans := range resp.Answer {
				if record, ok := ans.(*dns.TXT); ok {
					a.Records.TXT = append(a.Records.TXT, strings.Join(record.Txt, " "))
				}
			}
		case dns.TypeSOA:
			for _, ans := range resp.Answer {
				if record, ok := ans.(*dns.SOA); ok {
					a.Records.SOA = append(a.Records.SOA, fmt.Sprintf("%s %s %d %d %d %d %d",
						record.Ns, record.Mbox, record.Serial, record.Refresh, record.Retry, record.Expire, record.Minttl))
				}
			}
		case dns.TypeCNAME:
			for _, ans := range resp.Answer {
				if record, ok := ans.(*dns.CNAME); ok {
					a.Records.CNAME = append(a.Records.CNAME, record.Target)
				}
			}
		case dns.TypeCAA:
			for _, ans := range resp.Answer {
				if record, ok := ans.(*dns.CAA); ok {
					a.Records.CAA = append(a.Records.CAA, fmt.Sprintf("%d %s \"%s\"", record.Flag, record.Tag, record.Value))
				}
			}
		case dns.TypeDNSKEY:
			for _, ans := range resp.Answer {
				if record, ok := ans.(*dns.DNSKEY); ok {
					a.Records.DNSKEY = append(a.Records.DNSKEY, fmt.Sprintf("%d %d %d %s",
						record.Flags, record.Protocol, record.Algorithm, record.PublicKey))
				}
			}
		case dns.TypeDS:
			for _, ans := range resp.Answer {
				if record, ok := ans.(*dns.DS); ok {
					a.Records.DS = append(a.Records.DS, fmt.Sprintf("%d %d %d %s",
						record.KeyTag, record.Algorithm, record.DigestType, record.Digest))
				}
			}
		}
	}
	
	// Store DNS resolution time
	a.Performance.DNSResolutionTimeMs = time.Since(startTime).Milliseconds()
}

// getIPInfo collects information about the domain's IP address
func (a *DNSAnalyzer) getIPInfo() {
	// Remove dot at the end for net package lookups
	domainName := strings.TrimSuffix(a.Domain, ".")
	
	// Get A record (IPv4)
	ips, err := net.LookupIP(domainName)
	if err != nil || len(ips) == 0 {
		return
	}

	// Set IP address
	var ipv4Address string
	var hasIPv6 bool

	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4Address = ip.String()
			break // Just use the first IPv4 found
		} else {
			hasIPv6 = true
		}
	}

	a.IPInfo.Address = ipv4Address
	a.IPInfo.HasIPv6 = hasIPv6

	// Get reverse DNS
	if ipv4Address != "" {
		names, err := net.LookupAddr(ipv4Address)
		if err == nil && len(names) > 0 {
			a.IPInfo.ReverseDNS = names[0]
		}
	}

	// Get hostnames associated with IP
	if ipv4Address != "" {
		names, err := net.LookupAddr(ipv4Address)
		if err == nil {
			a.IPInfo.Hostnames = names
		}
	}

	// Simple heuristic to guess if domain might be behind CDN
	cdnSignatures := []string{
		"cloudflare", "akamai", "fastly", "cloudfront", "cdn", "edgecast",
	}

	for _, hostname := range a.IPInfo.Hostnames {
		hostname = strings.ToLower(hostname)
		for _, sig := range cdnSignatures {
			if strings.Contains(hostname, sig) {
				a.IPInfo.IsCDN = true
				break
			}
		}
	}

	// Similar check for TXT records
	for _, txt := range a.Records.TXT {
		txt = strings.ToLower(txt)
		for _, sig := range cdnSignatures {
			if strings.Contains(txt, sig) {
				a.IPInfo.IsCDN = true
				break
			}
		}
	}
}

// getGeoIPInfo fetches geolocation information for the IP
func (a *DNSAnalyzer) getGeoIPInfo() {
	if a.IPInfo.Address == "" {
		return
	}
	
	// Use a public IP geolocation API
	resp, err := http.Get("https://ipinfo.io/" + a.IPInfo.Address + "/json")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	var ipData struct {
		IP        string `json:"ip"`
		City      string `json:"city"`
		Region    string `json:"region"`
		Country   string `json:"country"`
		Loc       string `json:"loc"`
		Org       string `json:"org"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&ipData); err != nil {
		return
	}
	
	a.IPInfo.GeoIP.City = ipData.City
	a.IPInfo.GeoIP.Region = ipData.Region
	a.IPInfo.GeoIP.Country = ipData.Country
	a.IPInfo.GeoIP.Org = ipData.Org
	
	// Parse coordinates
	if loc := strings.Split(ipData.Loc, ","); len(loc) == 2 {
		a.IPInfo.GeoIP.Latitude, _ = strconv.ParseFloat(loc[0], 64)
		a.IPInfo.GeoIP.Longitude, _ = strconv.ParseFloat(loc[1], 64)
	}
}

// getTLSInfo checks the SSL/TLS certificate
func (a *DNSAnalyzer) getTLSInfo() {
	domainName := strings.TrimSuffix(a.Domain, ".")
	
	startTime := time.Now()
	
	// Initialize as not supported
	a.TLSInfo.Supported = false
	
	// Create a connection with InsecureSkipVerify to analyze any certificate
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	
	conn, err := tls.DialWithDialer(dialer, "tcp", domainName+":443", &tls.Config{
		InsecureSkipVerify: true,
	})
	
	if err != nil {
		return
	}
	defer conn.Close()
	
	// Store handshake time
	a.Performance.TLSHandshakeTimeMs = time.Since(startTime).Milliseconds()
	
	// TLS connection succeeded
	a.TLSInfo.Supported = true
	
	// Get connection state and certificate info
	state := conn.ConnectionState()
	certs := state.PeerCertificates
	
	if len(certs) > 0 {
		cert := certs[0] // Use the leaf certificate
		
		a.TLSInfo.Issuer = cert.Issuer.CommonName
		a.TLSInfo.Subject = cert.Subject.CommonName
		a.TLSInfo.Version = cert.Version
		a.TLSInfo.ValidFrom = cert.NotBefore
		a.TLSInfo.ValidUntil = cert.NotAfter
		a.TLSInfo.DNSNames = cert.DNSNames
		
		// Check if self-signed
		a.TLSInfo.SelfSigned = (cert.Issuer.CommonName == cert.Subject.CommonName)
		
		// Calculate days until expiration
		daysUntilExpiration := int(cert.NotAfter.Sub(time.Now()).Hours() / 24)
		a.TLSInfo.ExpiresIn = daysUntilExpiration
	}
	
	// Get cipher suite and protocol
	a.TLSInfo.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	
	// Determine TLS protocol version
	switch {
	case state.Version == tls.VersionTLS13:
		a.TLSInfo.Protocol = "TLS 1.3"
	case state.Version == tls.VersionTLS12:
		a.TLSInfo.Protocol = "TLS 1.2"
	case state.Version == tls.VersionTLS11:
		a.TLSInfo.Protocol = "TLS 1.1"
	case state.Version == tls.VersionTLS10:
		a.TLSInfo.Protocol = "TLS 1.0"
	default:
		a.TLSInfo.Protocol = fmt.Sprintf("Unknown (%x)", state.Version)
	}
}

// getHTTPInfo analyzes HTTP response and headers
func (a *DNSAnalyzer) getHTTPInfo() {
	domainName := strings.TrimSuffix(a.Domain, ".")
	
	// Initialize headers map
	a.HTTPInfo.Headers = make(map[string]string)
	
	// Create client with redirect tracking
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			a.HTTPInfo.Redirects = append(a.HTTPInfo.Redirects, req.URL.String())
			// Allow up to 10 redirects
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Timeout: 10 * time.Second,
	}
	
	startTime := time.Now()
	
	// Try HTTPS first
	resp, err := client.Get("https://" + domainName)
	if err != nil {
		// Try HTTP if HTTPS fails
		resp, err = client.Get("http://" + domainName)
		if err != nil {
			return
		}
	}
	defer resp.Body.Close()
	
	// Store response time
	a.Performance.HTTPResponseTimeMs = time.Since(startTime).Milliseconds()
	
	a.HTTPInfo.StatusCode = resp.StatusCode
	a.HTTPInfo.Server = resp.Header.Get("Server")
	
	// Store headers
	for k, v := range resp.Header {
		a.HTTPInfo.Headers[k] = strings.Join(v, ", ")
	}
	
	// Check security headers
	securityHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Feature-Policy",
		"Permissions-Policy",
	}
	
	for _, header := range securityHeaders {
		if val := resp.Header.Get(header); val != "" {
			a.HTTPInfo.HasSecurity = true
			a.HTTPInfo.SecurityFlags = append(a.HTTPInfo.SecurityFlags, header)
		}
	}
	
	// Analyze CSP if present
	cspHeader := resp.Header.Get("Content-Security-Policy")
	if cspHeader != "" {
		a.HTTPInfo.CSP = analyzeCSP(cspHeader)
	}
}

// analyzeCSP analyzes the Content Security Policy
func analyzeCSP(header string) CSPInfo {
	info := CSPInfo{
		Present:    header != "",
		Directives: make(map[string][]string),
		Score:      0,
	}
	
	if !info.Present {
		info.Weaknesses = append(info.Weaknesses, "No Content-Security-Policy header")
		return info
	}
	
	// Parse directives
	parts := strings.Split(header, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		
		directive := strings.SplitN(part, " ", 2)
		directiveName := directive[0]
		
		if len(directive) > 1 {
			sources := strings.Split(directive[1], " ")
			info.Directives[directiveName] = sources
		} else {
			info.Directives[directiveName] = []string{}
		}
	}
	
	// Score and analyze the CSP
	score := 100
	
	// Check for critical directives
	criticalDirectives := []string{
		"default-src", "script-src", "object-src", "base-uri",
		"frame-ancestors",
	}
	
	for _, directive := range criticalDirectives {
		if _, ok := info.Directives[directive]; !ok {
			info.Weaknesses = append(info.Weaknesses, 
				fmt.Sprintf("Missing %s directive", directive))
			score -= 10
		}
	}
	
	// Check for unsafe values
	unsafeValues := []string{"unsafe-inline", "unsafe-eval", "*"}
	
	for directive, sources := range info.Directives {
		for _, source := range sources {
			for _, unsafe := range unsafeValues {
				if strings.Contains(source, unsafe) {
					info.Weaknesses = append(info.Weaknesses, 
						fmt.Sprintf("Unsafe value '%s' in %s", unsafe, directive))
					score -= 15
					break
				}
			}
		}
	}
	
	// Ensure the score stays in range 0-100
	if score < 0 {
		score = 0
	}
	info.Score = score
	
	return info
}

// checkEmailSecurity looks for SPF, DKIM, and DMARC records
func (a *DNSAnalyzer) checkEmailSecurity() {
	domainName := strings.TrimSuffix(a.Domain, ".")
	
	// Check SPF record (in TXT records)
	for _, txt := range a.Records.TXT {
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			a.EmailSecurity.HasSPF = true
			a.EmailSecurity.SPFValue = txt
			break
		}
	}
	
	// Check DKIM records (in TXT selectors)
	selectors := []string{"default", "dkim", "mail", "email", "selector1", "selector2", "key1", "key2"}
	for _, selector := range selectors {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(selector+"._domainkey."+domainName), dns.TypeTXT)
		msg.RecursionDesired = true
		
		client := &dns.Client{Timeout: time.Second * 5}
		resp, _, err := client.Exchange(msg, "8.8.8.8:53")
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			a.EmailSecurity.HasDKIM = true
			for _, ans := range resp.Answer {
				if txt, ok := ans.(*dns.TXT); ok {
					a.EmailSecurity.DKIMKeys = append(a.EmailSecurity.DKIMKeys, 
						selector + ": " + strings.Join(txt.Txt, " "))
				}
			}
		}
	}
	
	// Check DMARC record
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("_dmarc."+domainName), dns.TypeTXT)
	msg.RecursionDesired = true
	
	client := &dns.Client{Timeout: time.Second * 5}
	resp, _, err := client.Exchange(msg, "8.8.8.8:53")
	if err == nil && resp != nil && len(resp.Answer) > 0 {
		for _, ans := range resp.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				dmarcRecord := strings.Join(txt.Txt, " ")
				if strings.HasPrefix(strings.ToLower(dmarcRecord), "v=dmarc1") {
					a.EmailSecurity.HasDMARC = true
					a.EmailSecurity.DMARCPolicy = dmarcRecord
					
					// Extract policy
					policyRegex := regexp.MustCompile(`p=(\w+)`)
					if matches := policyRegex.FindStringSubmatch(dmarcRecord); len(matches) > 1 {
						a.EmailSecurity.DMARCPolicy = matches[1]
					}
					break
				}
			}
		}
	}
}

// checkDNSSEC validates DNSSEC implementation
func (a *DNSAnalyzer) checkDNSSEC() {
	domainName := strings.TrimSuffix(a.Domain, ".")
	
	// Create a new DNS message asking for DNSKEY records
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domainName), dns.TypeDNSKEY)
	msg.SetEdns0(4096, true) // Enable DNSSEC
	
	client := &dns.Client{Timeout: time.Second * 5}
	resp, _, err := client.Exchange(msg, "8.8.8.8:53")
	
	if err != nil || resp == nil || len(resp.Answer) == 0 {
		return
	}
	
	// Check for DNSKEY records
	for _, ans := range resp.Answer {
		if key, ok := ans.(*dns.DNSKEY); ok {
			a.DNSSEC.Enabled = true
			a.DNSSEC.Algorithms = append(a.DNSSEC.Algorithms, 
				fmt.Sprintf("%d (%s)", key.Algorithm, algorithmToString(key.Algorithm)))
			a.DNSSEC.KeyTags = append(a.DNSSEC.KeyTags, int(key.KeyTag()))
		}
	}
	
	// Check for signatures
	for _, ans := range resp.Answer {
		if sig, ok := ans.(*dns.RRSIG); ok {
			a.DNSSEC.Signatures = append(a.DNSSEC.Signatures, 
				fmt.Sprintf("Algorithm: %d, KeyTag: %d", sig.Algorithm, sig.KeyTag))
			a.DNSSEC.Validated = true
		}
	}
}

// algorithmToString converts DNSSEC algorithm numbers to names
func algorithmToString(alg uint8) string {
    algorithms := map[uint8]string{
        1:  "RSA/MD5",
        3:  "DSA/SHA1",
        5:  "RSA/SHA-1",
        6:  "DSA-NSEC3-SHA1",
        7:  "RSASHA1-NSEC3-SHA1",
        8:  "RSA/SHA-256",
        10: "RSA/SHA-512",
        12: "GOST R 34.10-2001",
        13: "ECDSA Curve P-256 with SHA-256",
        14: "ECDSA Curve P-384 with SHA-384",
        15: "Ed25519",
        16: "Ed448",
    }
    
    if name, ok := algorithms[alg]; ok {
        return name
    }
    return "Unknown"
}

// scanPorts checks for common open ports
func (a *DNSAnalyzer) scanPorts() {
	domainName := strings.TrimSuffix(a.Domain, ".")
	
	// Define common ports and services to check
	commonPorts := map[int]string{
		21:   "FTP",
		22:   "SSH",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		143:  "IMAP",
		443:  "HTTPS",
		465:  "SMTPS",
		587:  "Submission",
		993:  "IMAPS",
		995:  "POP3S",
		3306: "MySQL",
		5432: "PostgreSQL",
		8080: "HTTP-Alternate",
		8443: "HTTPS-Alternate",
	}
	
	a.Ports.OpenPorts = make(map[int]string)
	startTime := time.Now()
	
	// Set a timeout for each connection attempt
	timeout := 500 * time.Millisecond
	
	// Use wait group to limit concurrent scans
	var wg sync.WaitGroup
	// Create a semaphore to limit concurrent connections
	sem := make(chan struct{}, 10) // Allow 10 concurrent scans
	
	// Use a mutex to safely update the open ports map
	var mu sync.Mutex
	
	// Check each port
	for port, service := range commonPorts {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore
		
		go func(p int, s string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore
			
			address := fmt.Sprintf("%s:%d", domainName, p)
			conn, err := net.DialTimeout("tcp", address, timeout)
			if err == nil {
				mu.Lock()
				a.Ports.OpenPorts[p] = s
				mu.Unlock()
				conn.Close()
			}
		}(port, service)
	}
	
	wg.Wait()
	a.Ports.ScanTime = time.Since(startTime)
}


// discoverSubdomains tries to find subdomains
func (a *DNSAnalyzer) discoverSubdomains() {
	domainName := strings.TrimSuffix(a.Domain, ".")
	
	// Common subdomain prefixes to try
	commonSubdomains := []string{
		"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
		"smtp", "secure", "vpn", "api", "dev", "staging", "test", "portal",
		"admin", "cdn", "static", "cloud", "direct", "support", "forum",
		"shop", "store", "news", "app", "beta", "client", "cp", "gateway",
		"host", "id", "login", "mx", "mta", "proxy", "router", "status",
		"backup", "dashboard", "db", "demo", "docs", "files", "help", "img",
		"internal", "kb", "media", "mobile", "monitor", "my", "search", "sip",
	}
	
	// Results channel with timeout
	results := make(chan string, len(commonSubdomains))
	var wg sync.WaitGroup
	
	// Create a semaphore to limit concurrent lookups
	sem := make(chan struct{}, 10) // Allow 10 concurrent lookups
	
	// Try each subdomain in parallel
	for _, sub := range commonSubdomains {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore
		
		go func(subdomain string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore
			
			fqdn := subdomain + "." + domainName
			_, err := net.LookupHost(fqdn)
			if err == nil {
				results <- fqdn
			}
		}(sub)
	}
	
	// Close results channel when all lookups are done
	go func() {
		wg.Wait()
		close(results)
	}()
	
	// Collect found subdomains
	for subdomain := range results {
		a.Subdomains = append(a.Subdomains, subdomain)
	}
	
	// Sort for consistent output
	sort.Strings(a.Subdomains)
}


// detectTechnologies identifies technologies used by the website
func (a *DNSAnalyzer) detectTechnologies() {
    domainName := strings.TrimSuffix(a.Domain, ".")
    
    // Try HTTPS first
    resp, err := http.Get("https://" + domainName)
    if err != nil {
        // Try HTTP if HTTPS fails
        resp, err = http.Get("http://" + domainName)
        if err != nil {
            return
        }
    }
    defer resp.Body.Close()
    
    // Read body with a limit to avoid huge pages
    body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
    if err != nil {
        return
    }
    
    html := string(body)
    headers := resp.Header
    
    // Check for common technologies based on signatures
    
    // Web servers
    if server := headers.Get("Server"); server != "" {
        a.Technologies = append(a.Technologies, Technology{
            Name:       server,
            Category:   "Web Server",
            Confidence: 100,
        })
    }
    
    // JavaScript frameworks
    jsLibraries := map[string]string{
        "jQuery":      `jquery[.-](\d+\.\d+\.\d+)`,
        "React":       `react(?:.min)?.js|window\.React`,
        "Angular":     `angular(?:\.min)?\.js|ng-app|ng-controller`,
        "Vue.js":      `vue(?:\.min)?\.js|v-app|v-bind`,
        "Bootstrap":   `bootstrap(?:\.min)?\.(?:js|css)`,
        "Lodash":      `lodash(?:\.min)?\.js|\b_\b`,
        "Modernizr":   `modernizr(?:\.min)?\.js`,
    }
    
    for library, pattern := range jsLibraries {
        if regexp.MustCompile(pattern).MatchString(html) {
            a.Technologies = append(a.Technologies, Technology{
                Name:       library,
                Category:   "JavaScript Library",
                Confidence: 80,
            })
        }
    }
    
    // Content Management Systems
    cmsSignatures := map[string]string{
        "WordPress":   `wp-content|wp-includes`,
        "Drupal":      `Drupal|drupal|sites/all|sites/default/files`,
        "Joomla":      `com_content|com_contact|com_users`,
        "Magento":     `Mage\.Cookies|Magento`,
        "Shopify":     `cdn\.shopify\.com|shopify\.com`,
        "Ghost":       `ghost(?:-(?:url|script|pagination|theme-is|link))?|casper`,
        "Wix":         `wix\.com|wixsite\.com`,
    }
    
    for cms, pattern := range cmsSignatures {
        if regexp.MustCompile(pattern).MatchString(html) {
            a.Technologies = append(a.Technologies, Technology{
                Name:       cms,
                Category:   "CMS",
                Confidence: 80,
            })
        }
    }
    
    // Analytics and tracking
    analyticsSignatures := map[string]string{
        "Google Analytics":   `ga\(|Google Analytics|gtag\(`,
        "Google Tag Manager": `googletagmanager\.com|gtm\.js`,
        "Facebook Pixel":     `fbq\(|facebook-jssdk`,
        "Matomo/Piwik":       `piwik\.js|matomo\.js`,
        "HubSpot":            `hubspot\.com`,
        "Hotjar":             `hotjar\.com|hjSiteSettings`,
    }
    
    for analytics, pattern := range analyticsSignatures {
        if regexp.MustCompile(pattern).MatchString(html) {
            a.Technologies = append(a.Technologies, Technology{
                Name:       analytics,
                Category:   "Analytics",
                Confidence: 85,
            })
        }
    }
    
    // Check for common headers that indicate technologies
    headerSignatures := map[string]map[string]string{
        "X-Powered-By":       {"PHP": `PHP`, "ASP.NET": `ASP\.NET`},
        "X-AspNet-Version":   {"ASP.NET": `.`},
        "X-Generator":        {"Drupal": `Drupal`, "WordPress": `WordPress`},
        "X-Shopify-Stage":    {"Shopify": `.`},
        "X-Wix-Request-Id":   {"Wix": `.`},
        "X-Drupal-Cache":     {"Drupal": `.`},
        "X-Varnish":          {"Varnish": `.`},
        "CF-Cache-Status":    {"Cloudflare": `.`},
        "Netlify":            {"Netlify": `.`},
        "Vercel":             {"Vercel": `.`},
    }
    
    for header, sigs := range headerSignatures {
        if value := headers.Get(header); value != "" {
            for tech, pattern := range sigs {
                if regexp.MustCompile(pattern).MatchString(value) {
                    a.Technologies = append(a.Technologies, Technology{
                        Name:       tech,
                        Category:   "Platform",
                        Confidence: 90,
                    })
                }
            }
        }
    }
    
    // Add CDN detection for Akamai (since we know it's present)
    if a.IPInfo.IsCDN {
        // Check for Akamai specifically
        for _, hostname := range a.IPInfo.Hostnames {
            if strings.Contains(strings.ToLower(hostname), "akamai") {
                a.Technologies = append(a.Technologies, Technology{
                    Name:       "Akamai CDN",
                    Category:   "CDN",
                    Confidence: 100,
                })
                break
            }
        }
    }
    
    // Add basic detection for HTML/CSS/JS frameworks based on common patterns
    webTechPatterns := map[string]string{
        "HTML5":           `<!DOCTYPE html>`,
        "CSS3":            `@media|@font-face|@keyframes`,
        "Web Fonts":       `fonts\.googleapis\.com|font-family`,
        "Responsive Design": `@media \(max-width|viewport`,
        "AJAX":           `XMLHttpRequest|fetch\(`,
        "JSON":           `application/json|JSON\.parse`,
    }
    
    for tech, pattern := range webTechPatterns {
        if regexp.MustCompile(pattern).MatchString(html) {
            a.Technologies = append(a.Technologies, Technology{
                Name:       tech,
                Category:   "Web Technology",
                Confidence: 70,
            })
        }
    }
}


// checkPropagation tests DNS resolution from multiple resolvers
func (a *DNSAnalyzer) checkPropagation() {
	domainName := strings.TrimSuffix(a.Domain, ".")
	
	// Define resolvers in different locations
	resolvers := map[string]string{
		"Google":     "8.8.8.8:53",
		"Cloudflare": "1.1.1.1:53",
		"Quad9":      "9.9.9.9:53",
		"OpenDNS":    "208.67.222.222:53",
		"Level3":     "4.2.2.2:53",
	}
	
	a.Propagation.Resolvers = make(map[string][]string)
	
	// Check A records with each resolver
	client := &dns.Client{Timeout: time.Second * 5}
	
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	for name, server := range resolvers {
		wg.Add(1)
		
		go func(resolverName, resolverServer string) {
			defer wg.Done()
			
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(domainName), dns.TypeA)
			msg.RecursionDesired = true
			
			resp, _, err := client.Exchange(msg, resolverServer)
			if err != nil || resp == nil {
				return
			}
			
			var ips []string
			for _, ans := range resp.Answer {
				if record, ok := ans.(*dns.A); ok {
					ips = append(ips, record.A.String())
				}
			}
			
			if len(ips) > 0 {
				mu.Lock()
				a.Propagation.Resolvers[resolverName] = ips
				mu.Unlock()
			}
		}(name, server)
	}
	
	wg.Wait()
	
	// Check if all resolvers returned the same IPs
	var firstResolver string
	var firstIPs []string
	
	a.Propagation.Consistent = true
	
	for name, ips := range a.Propagation.Resolvers {
		sort.Strings(ips) // Sort IPs for consistent comparison
		
		if firstResolver == "" {
			firstResolver = name
			firstIPs = ips
			continue
		}
		
		// Check if IP sets match
		if !ipsEqual(firstIPs, ips) {
			a.Propagation.Consistent = false
			break
		}
	}
}

// ipsEqual compares two slices of IPs (assumed to be sorted)
func ipsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	
	return true
}

// checkTyposquatting detects potential typosquatting domains
func (a *DNSAnalyzer) checkTyposquatting() {
	domainName := strings.TrimSuffix(a.Domain, ".")
	
	// Split domain into name and TLD
	parts := strings.Split(domainName, ".")
	if len(parts) < 2 {
		return
	}
	
	name := parts[0]
	tld := "." + strings.Join(parts[1:], ".")
	
	// Generate typo variants
	variants := []string{}
	
	// 1. Character omission (up to 5 variants to avoid overwhelming)
	if len(name) > 3 {
		count := 0
		for i := 0; i < len(name) && count < 5; i++ {
			variant := name[:i] + name[i+1:]
			variants = append(variants, variant+tld)
			count++
		}
	}
	
	// 2. Character transposition (up to 5 variants)
	if len(name) > 1 {
		count := 0
		for i := 0; i < len(name)-1 && count < 5; i++ {
			variant := name[:i] + string(name[i+1]) + string(name[i]) + name[i+2:]
			variants = append(variants, variant+tld)
			count++
		}
	}
	
	// 3. Common character substitutions
	substitutions := map[rune][]rune{
		'a': {'e', '4', '@'},
		'e': {'a', '3'},
		'i': {'1', 'l', '!'},
		'o': {'0'},
		's': {'5', '$'},
	}
	
	for i, char := range name {
		if replacements, ok := substitutions[char]; ok {
			for _, replacement := range replacements {
				variant := name[:i] + string(replacement) + name[i+1:]
				variants = append(variants, variant+tld)
			}
		}
	}
	
	// 4. Common TLD variations
	commonTLDs := []string{".com", ".net", ".org", ".co", ".info", ".biz"}
	
	for _, newTLD := range commonTLDs {
		if newTLD != tld {
			variants = append(variants, name+newTLD)
		}
	}
	
	// Limit total variants to 25 to avoid overwhelming checks
	if len(variants) > 25 {
		variants = variants[:25]
	}
	
	a.Typosquatting.Variants = variants
	
	// Check which variants are registered
	client := &dns.Client{Timeout: time.Second * 2}
	
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	// Use a semaphore to limit concurrent DNS lookups
	sem := make(chan struct{}, 5) // Allow 5 concurrent lookups
	
	for _, variant := range variants {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore
		
		go func(domain string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore
			
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
			msg.RecursionDesired = true
			
			resp, _, err := client.Exchange(msg, "8.8.8.8:53")
			if err == nil && resp != nil && len(resp.Answer) > 0 {
				mu.Lock()
				a.Typosquatting.RegisteredVariants = append(a.Typosquatting.RegisteredVariants, domain)
				mu.Unlock()
			}
		}(variant)
	}
	
	wg.Wait()
	
	// Sort for consistent output
	sort.Strings(a.Typosquatting.RegisteredVariants)
}

// calculateSecurityScore analyzes the collected data and assigns a security score
func (a *DNSAnalyzer) calculateSecurityScore() {
	scores := make(map[string]int)
	recommendations := []string{}
	
	// DNS Security (20 points)
	dnsScore := 20
	
	// Check for DNSSEC
	if !a.DNSSEC.Enabled {
		dnsScore -= 10
		recommendations = append(recommendations, "Implement DNSSEC to protect against DNS spoofing")
	}
	
	// Check for CAA records
	if len(a.Records.CAA) == 0 {
		dnsScore -= 5
		recommendations = append(recommendations, "Add CAA records to restrict which CAs can issue certificates for your domain")
	}
	
	scores["DNS Security"] = dnsScore
	
	// TLS Security (25 points)
	tlsScore := 25
	
	if !a.TLSInfo.Supported {
		tlsScore = 0
		recommendations = append(recommendations, "Enable HTTPS/TLS for secure connections")
	} else {
		// Check certificate expiration
		if a.TLSInfo.ExpiresIn < 30 {
			tlsScore -= 10
			recommendations = append(recommendations, "Certificate expires in less than 30 days")
		}
		
		// Check for self-signed certificates
		if a.TLSInfo.SelfSigned {
			tlsScore -= 10
			recommendations = append(recommendations, "Replace self-signed certificate with one from trusted CA")
		}
		
		// Check protocol version
		if a.TLSInfo.Protocol != "TLS 1.3" && a.TLSInfo.Protocol != "TLS 1.2" {
			tlsScore -= 10
			recommendations = append(recommendations, "Upgrade to TLS 1.2 or 1.3")
		}
	}
	
	scores["TLS Security"] = tlsScore
	
	// HTTP Security (20 points)
	httpScore := 20
	
	if a.HTTPInfo.StatusCode != 0 {  // If HTTP check was performed
		// Check for security headers
		if !a.HTTPInfo.HasSecurity {
			httpScore -= 10
			recommendations = append(recommendations, "Implement HTTP security headers (HSTS, CSP, etc.)")
		} else {
			missingHeaders := []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"}
			for _, header := range missingHeaders {
				found := false
				for _, h := range a.HTTPInfo.SecurityFlags {
					if h == header {
						found = true
						break
					}
				}
				if !found {
					httpScore -= 2
					recommendations = append(recommendations, fmt.Sprintf("Add %s header", header))
				}
			}
		}
		
		// Check CSP
		if a.HTTPInfo.CSP.Present && a.HTTPInfo.CSP.Score < 70 {
			httpScore -= 5
			recommendations = append(recommendations, "Improve Content-Security-Policy: " + strings.Join(a.HTTPInfo.CSP.Weaknesses, ", "))
		}
	}
	
	scores["HTTP Security"] = httpScore
	
	// Email Security (15 points)
	emailScore := 15
	
	if !a.EmailSecurity.HasSPF {
		emailScore -= 5
		recommendations = append(recommendations, "Add SPF record to protect against email spoofing")
	}
	
	if !a.EmailSecurity.HasDKIM {
		emailScore -= 5
		recommendations = append(recommendations, "Implement DKIM to verify email authenticity")
	}
	
	if !a.EmailSecurity.HasDMARC {
		emailScore -= 5
		recommendations = append(recommendations, "Add DMARC record to control handling of unauthenticated emails")
	}
	
	scores["Email Security"] = emailScore
	
	// Port Security (10 points)
	portScore := 10
	
	if len(a.Ports.OpenPorts) > 0 {
		// Check for unnecessarily open ports
		unnecessaryPorts := []int{21, 23, 25, 110, 143}
		for _, port := range unnecessaryPorts {
			if _, open := a.Ports.OpenPorts[port]; open {
				portScore -= 2
				recommendations = append(recommendations, fmt.Sprintf("Close unnecessary port %d (%s) if not required", port, a.Ports.OpenPorts[port]))
			}
		}
	}
	
	scores["Port Security"] = portScore
	
	// Misc Security (10 points)
	miscScore := 10
	
	// Check for typosquatting domains
	if len(a.Typosquatting.RegisteredVariants) > 2 {
		miscScore -= 5
		recommendations = append(recommendations, "Consider registering common typo variants of your domain to protect against typosquatting")
	}
	
	scores["Miscellaneous"] = miscScore

	// Calculate overall score (weighted average)
	totalScore := 0
	totalWeight := 0
	
	weights := map[string]int{
		"DNS Security":  20,
		"TLS Security":  25,
		"HTTP Security": 20,
		"Email Security": 15,
		"Port Security": 10,
		"Miscellaneous": 10,
	}
	
	for category, score := range scores {
		weight := weights[category]
		totalScore += score * weight
		totalWeight += weight
	}
	
	overallScore := totalScore / totalWeight
	
	// Save results
	a.SecurityScore.OverallScore = overallScore
	a.SecurityScore.CategoryScores = scores
	a.SecurityScore.Recommendations = recommendations
}

// printHumanReadable formats the output for terminal display
func printHumanReadable(a *DNSAnalyzer) string {
	var sb strings.Builder
	
	// Title and domain info
	sb.WriteString(fmt.Sprintf("==== %s v%s ====\n", AppName, AppVersion))
	sb.WriteString(fmt.Sprintf("Domain: %s\n", a.Domain))
	sb.WriteString(fmt.Sprintf("Analysis Time: %s\n\n", a.Time.Format("2006-01-02 15:04:05")))

	// DNS Records
	sb.WriteString("=== DNS Records ===\n")
	if len(a.Records.A) > 0 {
		sb.WriteString("A Records:\n")
		for _, record := range a.Records.A {
			sb.WriteString(fmt.Sprintf("  %s\n", record))
		}
	} else {
		sb.WriteString("A Records: None\n")
	}
	
	if len(a.Records.AAAA) > 0 {
		sb.WriteString("AAAA Records:\n")
		for _, record := range a.Records.AAAA {
			sb.WriteString(fmt.Sprintf("  %s\n", record))
		}
	}
	
	if len(a.Records.MX) > 0 {
		sb.WriteString("MX Records:\n")
		for _, record := range a.Records.MX {
			sb.WriteString(fmt.Sprintf("  %s\n", record))
		}
	}
	
	if len(a.Records.NS) > 0 {
		sb.WriteString("NS Records:\n")
		for _, record := range a.Records.NS {
			sb.WriteString(fmt.Sprintf("  %s\n", record))
		}
	}
	
	if len(a.Records.TXT) > 0 {
		sb.WriteString("TXT Records:\n")
		for _, record := range a.Records.TXT {
			sb.WriteString(fmt.Sprintf("  %s\n", record))
		}
	}
	
	if len(a.Records.SOA) > 0 {
		sb.WriteString("SOA Records:\n")
		for _, record := range a.Records.SOA {
			sb.WriteString(fmt.Sprintf("  %s\n", record))
		}
	}
	
	if len(a.Records.CNAME) > 0 {
		sb.WriteString("CNAME Records:\n")
		for _, record := range a.Records.CNAME {
			sb.WriteString(fmt.Sprintf("  %s\n", record))
		}
	}
	
	if len(a.Records.CAA) > 0 {
		sb.WriteString("CAA Records:\n")
		for _, record := range a.Records.CAA {
			sb.WriteString(fmt.Sprintf("  %s\n", record))
		}
	}
	
	if len(a.Records.DNSKEY) > 0 {
		sb.WriteString("DNSKEY Records:\n")
		for _, record := range a.Records.DNSKEY {
			sb.WriteString(fmt.Sprintf("  %s\n", record))
		}
	}
	
	if len(a.Records.DS) > 0 {
		sb.WriteString("DS Records:\n")
		for _, record := range a.Records.DS {
			sb.WriteString(fmt.Sprintf("  %s\n", record))
		}
	}

	// IP Information
	sb.WriteString("\n=== IP Information ===\n")
	if a.IPInfo.Address != "" {
		sb.WriteString(fmt.Sprintf("IP Address: %s\n", a.IPInfo.Address))
	}
	if a.IPInfo.ReverseDNS != "" {
		sb.WriteString(fmt.Sprintf("Reverse DNS: %s\n", a.IPInfo.ReverseDNS))
	}
	if a.IPInfo.HasIPv6 {
		sb.WriteString("IPv6: Yes\n")
	} else {
		sb.WriteString("IPv6: No\n")
	}
	if a.IPInfo.IsCDN {
		sb.WriteString("CDN Detected: Yes\n")
	} else {
		sb.WriteString("CDN Detected: No\n")
	}
	if len(a.IPInfo.Hostnames) > 0 {
		sb.WriteString("IP Hostnames:\n")
		for _, hostname := range a.IPInfo.Hostnames {
			sb.WriteString(fmt.Sprintf("  %s\n", hostname))
		}
	}
	
	// Geolocation info if available
	if a.IPInfo.GeoIP.Country != "" {
		sb.WriteString("Geolocation:\n")
		sb.WriteString(fmt.Sprintf("  Country: %s\n", a.IPInfo.GeoIP.Country))
		if a.IPInfo.GeoIP.City != "" {
			sb.WriteString(fmt.Sprintf("  City: %s\n", a.IPInfo.GeoIP.City))
		}
		if a.IPInfo.GeoIP.Region != "" {
			sb.WriteString(fmt.Sprintf("  Region: %s\n", a.IPInfo.GeoIP.Region))
		}
		if a.IPInfo.GeoIP.Org != "" {
			sb.WriteString(fmt.Sprintf("  Organization: %s\n", a.IPInfo.GeoIP.Org))
		}
		if a.IPInfo.GeoIP.Latitude != 0 || a.IPInfo.GeoIP.Longitude != 0 {
			sb.WriteString(fmt.Sprintf("  Coordinates: %.4f, %.4f\n", a.IPInfo.GeoIP.Latitude, a.IPInfo.GeoIP.Longitude))
		}
	}
	
	// TLS/SSL Information if available
	if a.TLSInfo.Supported {
		sb.WriteString("\n=== SSL/TLS Information ===\n")
		sb.WriteString(fmt.Sprintf("Protocol: %s\n", a.TLSInfo.Protocol))
		sb.WriteString(fmt.Sprintf("Issuer: %s\n", a.TLSInfo.Issuer))
		sb.WriteString(fmt.Sprintf("Subject: %s\n", a.TLSInfo.Subject))
		sb.WriteString(fmt.Sprintf("Valid From: %s\n", a.TLSInfo.ValidFrom.Format("2006-01-02")))
		sb.WriteString(fmt.Sprintf("Valid Until: %s (%d days)\n", a.TLSInfo.ValidUntil.Format("2006-01-02"), a.TLSInfo.ExpiresIn))
		sb.WriteString(fmt.Sprintf("Self-Signed: %v\n", a.TLSInfo.SelfSigned))
		if len(a.TLSInfo.DNSNames) > 0 {
			sb.WriteString("Alternative Names:\n")
			for _, name := range a.TLSInfo.DNSNames {
				sb.WriteString(fmt.Sprintf("  %s\n", name))
			}
		}
	}
	
	// HTTP Information if available
	if a.HTTPInfo.StatusCode != 0 {
		sb.WriteString("\n=== HTTP Information ===\n")
		sb.WriteString(fmt.Sprintf("Status Code: %d\n", a.HTTPInfo.StatusCode))
		if a.HTTPInfo.Server != "" {
			sb.WriteString(fmt.Sprintf("Server: %s\n", a.HTTPInfo.Server))
		}
		
		if len(a.HTTPInfo.Redirects) > 0 {
			sb.WriteString("Redirects:\n")
			for _, redirect := range a.HTTPInfo.Redirects {
				sb.WriteString(fmt.Sprintf("  %s\n", redirect))
			}
		}
		
		if a.HTTPInfo.HasSecurity {
			sb.WriteString("Security Headers Present:\n")
			for _, header := range a.HTTPInfo.SecurityFlags {
				sb.WriteString(fmt.Sprintf("  %s\n", header))
			}
		} else {
			sb.WriteString("Security Headers: None\n")
		}
		
		if a.HTTPInfo.CSP.Present {
			sb.WriteString(fmt.Sprintf("Content-Security-Policy Score: %d/100\n", a.HTTPInfo.CSP.Score))
			if len(a.HTTPInfo.CSP.Weaknesses) > 0 {
				sb.WriteString("CSP Weaknesses:\n")
				for _, weakness := range a.HTTPInfo.CSP.Weaknesses {
					sb.WriteString(fmt.Sprintf("  %s\n", weakness))
				}
			}
		}
	}
	
	// Email Security
	if a.EmailSecurity.HasSPF || a.EmailSecurity.HasDKIM || a.EmailSecurity.HasDMARC {
		sb.WriteString("\n=== Email Security ===\n")
		sb.WriteString(fmt.Sprintf("SPF: %v\n", a.EmailSecurity.HasSPF))
		if a.EmailSecurity.HasSPF && a.EmailSecurity.SPFValue != "" {
			sb.WriteString(fmt.Sprintf("  Value: %s\n", a.EmailSecurity.SPFValue))
		}
		
		sb.WriteString(fmt.Sprintf("DKIM: %v\n", a.EmailSecurity.HasDKIM))
		if a.EmailSecurity.HasDKIM && len(a.EmailSecurity.DKIMKeys) > 0 {
			sb.WriteString("  Selectors Found:\n")
			for _, key := range a.EmailSecurity.DKIMKeys {
				sb.WriteString(fmt.Sprintf("    %s\n", key))
			}
		}
		
		sb.WriteString(fmt.Sprintf("DMARC: %v\n", a.EmailSecurity.HasDMARC))
		if a.EmailSecurity.HasDMARC && a.EmailSecurity.DMARCPolicy != "" {
			sb.WriteString(fmt.Sprintf("  Policy: %s\n", a.EmailSecurity.DMARCPolicy))
		}
	}
	
	// DNSSEC Information
	if a.DNSSEC.Enabled {
		sb.WriteString("\n=== DNSSEC Information ===\n")
		sb.WriteString(fmt.Sprintf("DNSSEC Enabled: Yes\n"))
		sb.WriteString(fmt.Sprintf("Validated: %v\n", a.DNSSEC.Validated))
		
		if len(a.DNSSEC.Algorithms) > 0 {
			sb.WriteString("Algorithms:\n")
			for _, algorithm := range a.DNSSEC.Algorithms {
				sb.WriteString(fmt.Sprintf("  %s\n", algorithm))
			}
		}
		
		if len(a.DNSSEC.KeyTags) > 0 {
			sb.WriteString("Key Tags:\n")
			for _, tag := range a.DNSSEC.KeyTags {
				sb.WriteString(fmt.Sprintf("  %d\n", tag))
			}
		}
	} else if a.DNSSEC.Enabled == false {
		sb.WriteString("\n=== DNSSEC Information ===\n")
		sb.WriteString("DNSSEC Enabled: No\n")
	}
	
	// Open Ports
	if len(a.Ports.OpenPorts) > 0 {
		sb.WriteString("\n=== Open Ports ===\n")
		sb.WriteString(fmt.Sprintf("Scan Time: %dms\n", a.Ports.ScanTime.Milliseconds()))
		
		// Sort ports for consistent display
		var ports []int
		for port := range a.Ports.OpenPorts {
			ports = append(ports, port)
		}
		sort.Ints(ports)
		
		for _, port := range ports {
			sb.WriteString(fmt.Sprintf("  %d: %s\n", port, a.Ports.OpenPorts[port]))
		}
	}
	
	// Subdomains
	if len(a.Subdomains) > 0 {
		sb.WriteString("\n=== Discovered Subdomains ===\n")
		for _, subdomain := range a.Subdomains {
			sb.WriteString(fmt.Sprintf("  %s\n", subdomain))
		}
	}
	
	// Website Technologies
	if len(a.Technologies) > 0 {
		sb.WriteString("\n=== Detected Technologies ===\n")
		
		// Group by category
		categories := make(map[string][]string)
		for _, tech := range a.Technologies {
			categories[tech.Category] = append(categories[tech.Category], tech.Name)
		}
		
		// Display by category
		for category, techs := range categories {
			sb.WriteString(fmt.Sprintf("%s:\n", category))
			for _, tech := range techs {
				sb.WriteString(fmt.Sprintf("  %s\n", tech))
			}
		}
	}
	
	// DNS Propagation
	if len(a.Propagation.Resolvers) > 0 {
		sb.WriteString("\n=== DNS Propagation ===\n")
		sb.WriteString(fmt.Sprintf("Consistent Across Resolvers: %v\n", a.Propagation.Consistent))
		
		for resolver, ips := range a.Propagation.Resolvers {
			sb.WriteString(fmt.Sprintf("%s:\n", resolver))
			for _, ip := range ips {
				sb.WriteString(fmt.Sprintf("  %s\n", ip))
			}
		}
	}
	
	// Typosquatting
	if len(a.Typosquatting.Variants) > 0 {
		sb.WriteString("\n=== Typosquatting Analysis ===\n")
		
		if len(a.Typosquatting.RegisteredVariants) > 0 {
			sb.WriteString("Registered Similar Domains:\n")
			for _, domain := range a.Typosquatting.RegisteredVariants {
				sb.WriteString(fmt.Sprintf("  %s\n", domain))
			}
		} else {
			sb.WriteString("No registered typosquatting domains found\n")
		}
	}
	
	// Performance Metrics
	sb.WriteString("\n=== Performance Metrics ===\n")
	if a.Performance.DNSResolutionTimeMs > 0 {
		sb.WriteString(fmt.Sprintf("DNS Resolution: %dms\n", a.Performance.DNSResolutionTimeMs))
	}
	if a.Performance.HTTPResponseTimeMs > 0 {
		sb.WriteString(fmt.Sprintf("HTTP Response: %dms\n", a.Performance.HTTPResponseTimeMs))
	}
	if a.Performance.TLSHandshakeTimeMs > 0 {
		sb.WriteString(fmt.Sprintf("TLS Handshake: %dms\n", a.Performance.TLSHandshakeTimeMs))
	}
	
	// Security Score
	sb.WriteString("\n=== Security Score ===\n")
	sb.WriteString(fmt.Sprintf("Overall Score: %d/100\n", a.SecurityScore.OverallScore))
	
	sb.WriteString("Category Scores:\n")
	// Define category order
	categories := []string{"DNS Security", "TLS Security", "HTTP Security", "Email Security", "Port Security", "Miscellaneous"}
	
	for _, category := range categories {
		if score, ok := a.SecurityScore.CategoryScores[category]; ok {
			sb.WriteString(fmt.Sprintf("  %s: %d/100\n", category, score))
		}
	}
	
	if len(a.SecurityScore.Recommendations) > 0 {
		sb.WriteString("\n=== Security Recommendations ===\n")
		for i, rec := range a.SecurityScore.Recommendations {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
		}
	}
	
	return sb.String()
}
