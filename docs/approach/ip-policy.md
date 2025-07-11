# IP Policy Implementation Approach

## Overview

The IP Policy component in Gatekeeper provides sophisticated IP-based access control with support for both individual IP addresses and CIDR ranges. It implements robust client IP resolution with proxy header support and trusted proxy validation for secure deployment in various network architectures.

## Technical Architecture

### Core Components

1. **IPPolicyConfig**: Configuration structure defining IP rules and proxy settings
2. **parsedIPPolicy**: Pre-parsed and optimized IP data structures
3. **Client IP Resolution**: Sophisticated IP extraction from HTTP requests
4. **Dual Matching Strategy**: Individual IPs and CIDR range matching

### Configuration Structure

```go
type IPPolicyConfig struct {
    Mode              PolicyMode `json:"mode"`                           // BLACKLIST or WHITELIST
    IPs               []string   `json:"ips"`                             // List of individual IPs
    CIDRs             []string   `json:"cidrs"`                           // List of CIDR ranges
    TrustProxyHeaders bool       `json:"trustProxyHeaders"`               // Trust X-Forwarded-For, X-Real-IP
    TrustedProxies    []string   `json:"trustedProxies"`                  // List of trusted proxy IPs/CIDRs
}
```

## Implementation Details

### 1. IP Parsing and Optimization

The policy pre-parses all IP addresses and CIDR ranges for performance:

```go
func newParsedIPPolicy(config *IPPolicyConfig) (*parsedIPPolicy, error) {
    parsed := &parsedIPPolicy{
        config: config,
    }
    
    // Parse individual IPs and CIDR ranges
    var err error
    parsed.parsedIPs, parsed.parsedCIDRs, err = utils.ParseIPsAndCIDRs(config.IPs, config.CIDRs)
    if err != nil {
        return nil, fmt.Errorf("failed to parse IPs/CIDRs: %w", err)
    }
    
    // Parse trusted proxies if proxy headers are trusted
    if config.TrustProxyHeaders {
        _, parsedTrustedProxiesSlice, err := utils.ParseIPsAndCIDRs(nil, config.TrustedProxies)
        if err != nil {
            return nil, fmt.Errorf("failed to parse TrustedProxies CIDRs: %w", err)
        }
        parsed.parsedTrustedProxies = parsedTrustedProxiesSlice
    }
    
    return parsed, nil
}
```

**Optimization Features:**
- Pre-parsed IP addresses stored in hash map for O(1) lookup
- Pre-parsed CIDR ranges for efficient subnet matching
- Validation during initialization prevents runtime errors
- Separate structures for individual IPs and CIDR ranges

### 2. Client IP Resolution Strategy

The implementation uses a sophisticated multi-layered approach for client IP resolution:

```go
func GetClientIPFromRequest(r *http.Request, trustProxyHeaders bool, trustedProxies []*net.IPNet) (net.IP, error) {
    // 1. Extract direct connection IP
    remoteIPStr, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        remoteIPStr = r.RemoteAddr // Handle non-host:port formats
    }
    remoteIP := net.ParseIP(remoteIPStr)
    
    // 2. If not trusting proxy headers, return direct IP
    if !trustProxyHeaders {
        return remoteIP, nil
    }
    
    // 3. Validate direct connection is from trusted proxy
    isTrustedDirectConnection := false
    if len(trustedProxies) == 0 {
        // Trust private IPs by default
        if isPrivateIP(remoteIP) {
            isTrustedDirectConnection = true
        }
    } else {
        for _, trustedCIDR := range trustedProxies {
            if trustedCIDR.Contains(remoteIP) {
                isTrustedDirectConnection = true
                break
            }
        }
    }
    
    // 4. If trusted, extract client IP from headers
    if isTrustedDirectConnection {
        // Try X-Forwarded-For first
        xff := r.Header.Get("X-Forwarded-For")
        if xff != "" {
            ips := strings.Split(xff, ",")
            for _, ipStr := range ips {
                clientIP := net.ParseIP(strings.TrimSpace(ipStr))
                if clientIP != nil {
                    return clientIP, nil
                }
            }
        }
        
        // Try X-Real-IP
        realIP := r.Header.Get("X-Real-IP")
        if realIP != "" {
            clientIP := net.ParseIP(strings.TrimSpace(realIP))
            if clientIP != nil {
                return clientIP, nil
            }
        }
    }
    
    // 5. Fallback to direct connection IP
    return remoteIP, nil
}
```

**Resolution Strategy:**
1. **Direct Connection**: Extract IP from `r.RemoteAddr`
2. **Proxy Validation**: Check if direct connection is from trusted proxy
3. **Header Extraction**: Parse `X-Forwarded-For` and `X-Real-IP` headers
4. **Fallback**: Return direct connection IP if proxy headers unavailable

### 3. Matching Algorithm

The matching process uses a two-tier approach for optimal performance:

```go
func (gk *Gatekeeper) IPPolicy(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Get client IP with proxy support
        clientIPNet, err := utils.GetClientIPFromRequest(r, p.config.TrustProxyHeaders, p.parsedTrustedProxies)
        if err != nil {
            gk.blockRequest(w, r, http.StatusInternalServerError, "Internal Server Error", "Could not determine client IP")
            return
        }
        
        clientIPStr := clientIPNet.String()
        matched := false
        
        // Check exact IP matches first (faster)
        if _, ok := p.parsedIPs[clientIPStr]; ok {
            matched = true
        }
        
        // Check CIDR matches if not already matched
        if !matched {
            for _, cidr := range p.parsedCIDRs {
                if cidr.Contains(clientIPNet) {
                    matched = true
                    break
                }
            }
        }
        
        // Decision logic based on mode
        block := false
        if p.config.Mode == ModeBlacklist {
            if matched {
                block = true
            }
        } else { // ModeWhitelist
            if !matched {
                block = true
            }
        }
        
        if block {
            gk.blockRequest(w, r, statusCode, message, reason)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}
```

**Performance Optimizations:**
1. **Fast Path**: Exact IP matching using hash map (O(1))
2. **Fallback**: CIDR range matching only if exact match fails
3. **Early Exit**: Stop CIDR matching once a match is found
4. **Pre-parsed Data**: All IPs and CIDRs parsed at startup

### 4. Policy Modes

#### Blacklist Mode
- **Behavior**: Block requests from matching IPs
- **Use Cases**: Blocking malicious IPs, known attackers, geographic restrictions
- **Logic**: `if matched { block = true }`

#### Whitelist Mode
- **Behavior**: Allow only requests from matching IPs
- **Use Cases**: Internal API access, VPN-only access, partner integrations
- **Logic**: `if !matched { block = true }`

### 5. Proxy Header Support

#### Trusted Proxy Configuration
```go
// Trust specific proxy ranges
trustedProxies := []string{
    "10.0.0.0/8",     // Internal network
    "192.168.1.0/24", // Local network
    "172.16.0.0/12",  // Private network
}
```

#### Header Processing
- **X-Forwarded-For**: Handles comma-separated IP chains
- **X-Real-IP**: Direct client IP from trusted proxies
- **Validation**: Ensures headers come from trusted sources

## Configuration Examples

### Basic IP Blacklist
```json
{
  "ipPolicy": {
    "mode": "BLACKLIST",
    "ips": [
      "192.168.1.100",
      "10.0.0.50"
    ],
    "cidrs": [
      "203.0.113.0/24",
      "198.51.100.0/24"
    ]
  }
}
```

### Whitelist with Proxy Support
```json
{
  "ipPolicy": {
    "mode": "WHITELIST",
    "ips": [
      "192.168.1.10",
      "10.0.0.5"
    ],
    "cidrs": [
      "192.168.1.0/24",
      "10.0.0.0/8"
    ],
    "trustProxyHeaders": true,
    "trustedProxies": [
      "192.168.1.0/24",
      "10.0.0.0/8"
    ]
  }
}
```

### Geographic Blocking
```json
{
  "ipPolicy": {
    "mode": "BLACKLIST",
    "cidrs": [
      "1.0.0.0/8",    // Australia
      "2.0.0.0/8",    // France
      "3.0.0.0/8"     // Germany
    ]
  }
}
```

## Security Considerations

### 1. IP Spoofing Protection
- **Risk**: Malicious clients can spoof IP addresses
- **Mitigation**: Use in combination with other policies
- **Best Practice**: Don't rely solely on IP for security

### 2. Proxy Header Security
- **Risk**: Untrusted proxy headers can be spoofed
- **Mitigation**: Validate proxy headers against trusted sources
- **Strategy**: Only trust headers from known proxy IPs

### 3. CIDR Range Security
- **Risk**: Overly broad CIDR ranges may block legitimate traffic
- **Mitigation**: Use specific ranges when possible
- **Monitoring**: Track false positive rates

## Performance Characteristics

### Time Complexity
- **Exact IP Matching**: O(1) hash map lookup
- **CIDR Matching**: O(n) where n = number of CIDR ranges
- **Overall**: O(1) for exact matches, O(n) worst case

### Memory Usage
- **IP Set**: O(m) where m = number of individual IPs
- **CIDR Ranges**: O(p) where p = number of CIDR ranges
- **Per Request**: Minimal additional memory

### Optimization Strategies
1. **Exact First**: Check exact IPs before CIDR ranges
2. **Early Exit**: Stop CIDR matching on first match
3. **Pre-parsing**: Parse all IPs and CIDRs at startup
4. **Efficient Storage**: Use hash maps for O(1) lookups

## Network Architecture Support

### 1. Direct Connection
- **Use Case**: Single server deployments
- **Configuration**: `trustProxyHeaders: false`
- **IP Source**: `r.RemoteAddr`

### 2. Load Balancer
- **Use Case**: Cloud deployments with load balancers
- **Configuration**: `trustProxyHeaders: true`
- **IP Source**: X-Forwarded-For header

### 3. Reverse Proxy
- **Use Case**: Nginx, Apache, or custom proxies
- **Configuration**: `trustProxyHeaders: true`
- **IP Source**: X-Real-IP or X-Forwarded-For

### 4. CDN Integration
- **Use Case**: CloudFlare, AWS CloudFront
- **Configuration**: `trustProxyHeaders: true`
- **IP Source**: CDN-specific headers

## Monitoring and Debugging

### 1. Logging
```go
// Log blocked requests with client IP
gk.logger.Printf("IP blocked: %s (reason: %s)", clientIPStr, reason)

// Log proxy header processing
gk.logger.Printf("Using proxy header IP: %s (direct: %s)", proxyIP, directIP)
```

### 2. Metrics
- Blocked requests per IP/CIDR
- Proxy header usage patterns
- False positive rates

### 3. Testing
```go
// Test cases for IP matching
testCases := []struct {
    clientIP string
    expected bool
}{
    {"192.168.1.100", true},
    {"10.0.0.5", false},
}
```

## Best Practices

### 1. IP Range Design
- Use specific IPs over broad ranges when possible
- Document the purpose of each IP/CIDR entry
- Regular review and cleanup of IP lists

### 2. Proxy Configuration
- Only trust headers from known proxy IPs
- Use private IP ranges for internal proxies
- Monitor for unexpected proxy header usage

### 3. Security Monitoring
- Alert on high block rates
- Monitor for IP spoofing attempts
- Track geographic access patterns

## Future Enhancements

### 1. Advanced Features
- Geographic IP databases
- Threat intelligence integration
- Dynamic IP reputation scoring

### 2. Performance Improvements
- IP range optimization algorithms
- Caching of IP resolution results
- Parallel IP matching

### 3. Integration
- SIEM system integration
- Threat intelligence feeds
- Automated IP list updates 