# User-Agent Policy Implementation Approach

## Overview

The User-Agent policy component in Gatekeeper provides sophisticated filtering capabilities based on HTTP User-Agent headers. It supports both blacklist and whitelist modes with exact string matching and regex pattern matching for comprehensive control over client access.

## Technical Architecture

### Core Components

1. **UserAgentPolicyConfig**: Configuration structure defining policy rules
2. **parsedUserAgentPolicy**: Pre-compiled and optimized policy data
3. **Middleware Integration**: HTTP middleware for request filtering
4. **Dual Matching Strategy**: Exact strings and regex patterns

### Configuration Structure

```go
type UserAgentPolicyConfig struct {
    Mode     PolicyMode `json:"mode"`         // BLACKLIST or WHITELIST
    Exact    []string   `json:"exact"`        // List of exact User-Agent strings
    Patterns []string   `json:"patterns"`     // List of regex patterns for User-Agents
}
```

## Implementation Details

### 1. Policy Parsing and Optimization

The policy is pre-compiled for performance during initialization:

```go
func newParsedUserAgentPolicy(config *UserAgentPolicyConfig) (*parsedUserAgentPolicy, error) {
    parsed := &parsedUserAgentPolicy{
        config:           config,
        exactSet:         make(map[string]struct{}),
        compiledPatterns: make([]*regexp.Regexp, 0, len(config.Patterns)),
    }
    
    // Process exact matches (case-insensitive)
    for _, ua := range config.Exact {
        if ua == "" {
            continue
        }
        parsed.exactSet[strings.ToLower(ua)] = struct{}{}
    }
    
    // Compile regex patterns
    for _, pattern := range config.Patterns {
        if pattern == "" {
            continue
        }
        re, err := regexp.Compile(pattern)
        if err != nil {
            return nil, fmt.Errorf("invalid User-Agent pattern '%s': %w", pattern, err)
        }
        parsed.compiledPatterns = append(parsed.compiledPatterns, re)
    }
    
    return parsed, nil
}
```

**Optimization Features:**
- Case-insensitive exact matching using `strings.ToLower()`
- Pre-compiled regex patterns for performance
- Hash map lookup for exact matches (O(1) complexity)
- Validation during initialization

### 2. Matching Algorithm

The matching process uses a two-tier approach for optimal performance:

```go
func (gk *Gatekeeper) UserAgentPolicy(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        userAgent := r.Header.Get("User-Agent")
        lowerUserAgent := strings.ToLower(userAgent)
        
        matched := false
        
        // Check exact matches first (faster)
        if _, ok := p.exactSet[lowerUserAgent]; ok {
            matched = true
        }
        
        // Check patterns if not already matched
        if !matched {
            for _, re := range p.compiledPatterns {
                if re.MatchString(userAgent) {
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
1. **Fast Path**: Exact string matching using hash map (O(1))
2. **Fallback**: Regex pattern matching only if exact match fails
3. **Early Exit**: Stop pattern matching once a match is found
4. **Case Normalization**: Single `ToLower()` call per request

### 3. Policy Modes

#### Blacklist Mode
- **Behavior**: Block requests with matching User-Agents
- **Use Cases**: Blocking malicious bots, scrapers, outdated clients
- **Logic**: `if matched { block = true }`

#### Whitelist Mode
- **Behavior**: Allow only requests with matching User-Agents
- **Use Cases**: Restricting access to specific clients, API clients only
- **Logic**: `if !matched { block = true }`

### 4. Matching Strategies

#### Exact String Matching
```go
// Case-insensitive exact match
exactSet := map[string]struct{}{
    "mozilla/5.0 (windows nt 10.0; win64; x64)": {},
    "python-requests/2.28.1": {},
}
```

**Advantages:**
- O(1) lookup time
- Precise control
- No false positives

#### Regex Pattern Matching
```go
// Compiled patterns for flexible matching
patterns := []*regexp.Regexp{
    regexp.MustCompile(`(?i)bot|crawler|spider`),
    regexp.MustCompile(`(?i)python-requests`),
    regexp.MustCompile(`(?i)curl`),
}
```

**Advantages:**
- Flexible pattern matching
- Wildcard support
- Complex matching rules

## Configuration Examples

### Bot Blocking (Blacklist)
```json
{
  "userAgentPolicy": {
    "mode": "BLACKLIST",
    "exact": [
      "python-requests/2.28.1",
      "curl/7.68.0"
    ],
    "patterns": [
      "(?i)bot|crawler|spider",
      "(?i)scraper",
      "(?i)python-requests"
    ]
  }
}
```

### API Client Whitelist
```json
{
  "userAgentPolicy": {
    "mode": "WHITELIST",
    "exact": [
      "MyApp/1.0",
      "API-Client/2.1"
    ],
    "patterns": [
      "^MyApp/",
      "^API-Client/"
    ]
  }
}
```

### Malicious User-Agent Blocking
```json
{
  "userAgentPolicy": {
    "mode": "BLACKLIST",
    "patterns": [
      "(?i)sqlmap",
      "(?i)nikto",
      "(?i)dirbuster",
      "(?i)wget",
      "(?i)masscan"
    ]
  }
}
```

## Security Considerations

### 1. User-Agent Spoofing
- **Risk**: Malicious clients can easily spoof User-Agent headers
- **Mitigation**: Use in combination with other policies (IP, rate limiting)
- **Best Practice**: Don't rely solely on User-Agent for security

### 2. False Positives
- **Risk**: Legitimate clients blocked due to pattern matches
- **Mitigation**: Test patterns thoroughly in staging
- **Strategy**: Start with blacklist mode, add patterns incrementally

### 3. Performance Impact
- **Risk**: Complex regex patterns can impact performance
- **Mitigation**: Use exact matches when possible
- **Monitoring**: Profile regex performance in production

## Performance Characteristics

### Time Complexity
- **Exact Matching**: O(1) hash map lookup
- **Pattern Matching**: O(n) where n = number of patterns
- **Overall**: O(1) for exact matches, O(n) worst case

### Memory Usage
- **Exact Set**: O(m) where m = number of exact strings
- **Patterns**: O(p) where p = number of regex patterns
- **Per Request**: Minimal additional memory

### Optimization Strategies
1. **Exact First**: Check exact matches before patterns
2. **Early Exit**: Stop on first pattern match
3. **Pre-compilation**: Compile regex patterns at startup
4. **Case Normalization**: Single ToLower() call per request

## Monitoring and Debugging

### 1. Logging
```go
// Log blocked requests with reason
gk.logger.Printf("User-Agent blocked: %s (reason: %s)", userAgent, reason)
```

### 2. Metrics
- Blocked requests per User-Agent pattern
- Performance impact of regex patterns
- False positive rates

### 3. Testing
```go
// Test cases for pattern matching
testCases := []struct {
    userAgent string
    expected  bool
}{
    {"Mozilla/5.0 (compatible; Googlebot/2.1)", true},
    {"MyApp/1.0", false},
}
```

## Best Practices

### 1. Pattern Design
- Use specific patterns over broad ones
- Test patterns against legitimate traffic
- Document pattern purpose and expected matches

### 2. Configuration Management
- Version control configuration changes
- Gradual rollout of new patterns
- Rollback capability for problematic patterns

### 3. Monitoring
- Alert on high block rates
- Monitor for false positives
- Track pattern effectiveness

## Future Enhancements

### 1. Advanced Features
- User-Agent fingerprinting
- Machine learning-based detection
- Behavioral analysis integration

### 2. Performance Improvements
- Pattern optimization algorithms
- Caching of match results
- Parallel pattern matching

### 3. Integration
- SIEM system integration
- Threat intelligence feeds
- Automated pattern updates 