# DNSC - DNS Analysis Tool

DNSC is a comprehensive DNS analysis tool that provides detailed information about domains including DNS records, security posture, performance metrics, and infrastructure details.

## Installation

```bash
# Clone the repository
git clone https://github.com/rexdivakar/dnsc.git
cd dnsc

# Build the binary
go build -o dnsanalyzer
```

## Usage

### Basic Commands

```bash
# Basic analysis with just DNS records
./dnsanalyzer -domain example.com

# Full scan with all features enabled
./dnsanalyzer -domain example.com -full

# Verbose output to see progress
./dnsanalyzer -domain example.com -verbose -full

# Output to a JSON file
./dnsanalyzer -domain example.com -json -output example-results.json
```

### Feature-Specific Commands

#### Security Analysis

```bash
# SSL/TLS certificate check
./dnsanalyzer -domain example.com -tls

# HTTP headers and security
./dnsanalyzer -domain example.com -http

# Email security (SPF, DKIM, DMARC)
./dnsanalyzer -domain example.com -email

# DNSSEC validation
./dnsanalyzer -domain example.com -dnssec
```

#### Network & Infrastructure

```bash
# Port scanning
./dnsanalyzer -domain example.com -ports

# DNS propagation check
./dnsanalyzer -domain example.com -prop

# Technology detection
./dnsanalyzer -domain example.com -tech
```

#### Domain Analysis

```bash
# Subdomain discovery
./dnsanalyzer -domain example.com -sub

# Typosquatting detection
./dnsanalyzer -domain example.com -typo
```

### Combined Commands

```bash
# Security-focused scan with JSON output
./dnsanalyzer -domain example.com -tls -http -email -dnssec -json

# Domain and network analysis
./dnsanalyzer -domain example.com -ports -geo -prop
```

## Options

| Flag | Description |
|------|-------------|
| `-domain` | Target domain name to analyze |
| `-full` | Run all analysis modules |
| `-verbose` | Show detailed progress information |
| `-json` | Output results in JSON format |
| `-output` | Specify output file (default: print to console) |
| `-tls` | Check SSL/TLS certificates |
| `-http` | Analyze HTTP headers and security |
| `-ports` | Scan for open ports |
| `-email` | Check email security records |
| `-dnssec` | Validate DNSSEC implementation |
| `-tech` | Detect technologies used by the website |
| `-prop` | Check DNS propagation across multiple resolvers |
| `-sub` | Discover subdomains |
| `-typo` | Detect potential typosquatting domains |
| `-geo` | Get geographical information for the domain's IP |

## Examples

```bash
# Check security posture of a website
./dnsanalyzer -domain example.com -tls -http -dnssec

# Complete analysis with all results saved to a file
./dnsanalyzer -domain example.com -full -json -output example-full.json
```

## License

[MIT License](LICENSE)
