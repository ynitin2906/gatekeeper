# Referer Policy Implementation Approach

## Overview

The Referer Policy component in Gatekeeper provides sophisticated filtering capabilities based on HTTP Referer headers. It supports both blacklist and whitelist modes with exact string matching and regex pattern matching for comprehensive control over cross-origin requests and referrer-based access control.

## Technical Architecture

### Core Components

1. **RefererPolicyConfig**: Configuration structure defining policy rules
2. **parsedRefererPolicy**: Pre-compiled and optimized policy data
3. **Middleware Integration**: HTTP middleware for request filtering
4. **Dual Matching Strategy**: Exact strings and regex patterns

### Configuration Structure

```go
type RefererPolicyConfig struct {
    Mode     PolicyMode `json:"mode"`         // BLACKLIST or WHITELIST
    Exact    []string   `json:"exact"`        // List of exact Referer strings
    Patterns []string   `json:"patterns"`     // List of regex patterns for Referers
}
```

## Implementation Details

### 1. Policy Parsing and Optimization

The policy is pre-compiled for performance during initialization:

```go
func newParsedRefererPolicy(config *RefererPolicyConfig) (*parsedRefererPolicy, error) {
    if config == nil {
        return nil, fmt.Errorf("referer policy config is nil")
    }
    
    parsed := &parsedRefererPolicy{
        config:   config,
        exactSet: make(map[string]struct{}),
    }
    
    // Process exact referers (case-insensitive)
    for _, referer := range config.Exact {
        parsed.exactSet[strings.ToLower(referer)] = struct{}{}
    }
    
    // Compile regex patterns
    for _, pattern := range config.Patterns {
        compiled, err := regexp.Compile(pattern)
        if err != nil {
            return nil, fmt.Errorf("invalid referer regex pattern '%s': %w", pattern, err)
        }
        parsed.compiledPatterns = append(parsed.compiledPatterns, compiled)
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
func (gk *Gatekeeper) isRefererMatched(referer string) bool {
    if gk.parsedRefererPolicy == nil {
        return false
    }
    
    // Normalize referer for case-insensitive comparison
    refererLower := strings.ToLower(referer)
    
    // Check exact matches first (faster)
    if _, exists := gk.parsedRefererPolicy.exactSet[refererLower]; exists {
        return true
    }
    
    // Check regex patterns if not already matched
    for _, pattern := range gk.parsedRefererPolicy.compiledPatterns {
        if pattern.MatchString(referer) {
            return true
        }
    }
    
    return false
}
```

**Performance Optimizations:**
1. **Fast Path**: Exact string matching using hash map (O(1))
2. **Fallback**: Regex pattern matching only if exact match fails
3. **Early Exit**: Stop pattern matching once a match is found
4. **Case Normalization**: Single `ToLower()` call per request

### 3. Policy Modes

#### Blacklist Mode
- **Behavior**: Block requests with matching Referers
- **Use Cases**: Blocking malicious sites, preventing CSRF attacks, blocking specific domains
- **Logic**: `if matched { block = true }`

#### Whitelist Mode
- **Behavior**: Allow only requests with matching Referers
- **Use Cases**: Restricting access to specific domains, API access control, partner integrations
- **Logic**: `if !matched { block = true }`

### 4. Middleware Implementation

```go
func (gk *Gatekeeper) RefererPolicy(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        referer := r.Header.Get("Referer")
        
        // If no referer policy is configured, allow the request
        if gk.parsedRefererPolicy == nil {
            next.ServeHTTP(w, r)
            return
        }
        
        config := gk.parsedRefererPolicy.config
        isMatched := gk.isRefererMatched(referer)
        
        var shouldBlock bool
        var reason string
        
        switch config.Mode {
        case ModeBlacklist:
            if isMatched {
                shouldBlock = true
                reason = fmt.Sprintf("referer '%s' is blacklisted", referer)
            }
        case ModeWhitelist:
            if !isMatched {
                shouldBlock = true
                if referer == "" {
                    reason = "no referer provided and whitelist mode is active"
                } else {
                    reason = fmt.Sprintf("referer '%s' is not whitelisted", referer)
                }
            }
        default:
            gk.logger.Printf("Invalid referer policy mode: %s", config.Mode)
            next.ServeHTTP(w, r)
            return
        }
        
        if shouldBlock {
            gk.blockRequest(w, r, gk.config.DefaultBlockStatusCode, gk.config.DefaultBlockMessage, reason)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}
```

### 5. Matching Strategies

#### Exact String Matching
```go
// Case-insensitive exact match
exactSet := map[string]struct{}{
    "https://trusted-site.com": {},
    "https://api.partner.com": {},
    "https://internal.company.com": {},
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
    regexp.MustCompile(`^https://.*\.trusted-domain\.com`),
    regexp.MustCompile(`^https://api\..*\.com`),
    regexp.MustCompile(`^https://.*\.internal\.company\.com`),
}
```

**Advantages:**
- Flexible pattern matching
- Wildcard support
- Complex matching rules

## Configuration Examples

### CSRF Protection (Blacklist)
```json
{
  "refererPolicy": {
    "mode": "BLACKLIST",
    "exact": [
      "https://malicious-site.com",
      "https://phishing-site.net"
    ],
    "patterns": [
      "(?i)https://.*\\.malicious\\.com",
      "(?i)https://.*\\.phishing\\.net"
    ]
  }
}
```

### API Access Control (Whitelist)
```json
{
  "refererPolicy": {
    "mode": "WHITELIST",
    "exact": [
      "https://trusted-partner.com",
      "https://api.client.com"
    ],
    "patterns": [
      "^https://.*\\.trusted-domain\\.com",
      "^https://api\\..*\\.com"
    ]
  }
}
```

### Internal Access Control
```json
{
  "refererPolicy": {
    "mode": "WHITELIST",
    "patterns": [
      "^https://.*\\.internal\\.company\\.com",
      "^https://intranet\\.company\\.com",
      "^https://admin\\.company\\.com"
    ]
  }
}
```

### Malicious Site Blocking
```json
{
  "refererPolicy": {
    "mode": "BLACKLIST",
    "patterns": [
      "(?i)https://.*\\.malware\\.com",
      "(?i)https://.*\\.spam\\.net",
      "(?i)https://.*\\.phishing\\.org"
    ]
  }
}
```

## Security Considerations

### 1. Referer Header Spoofing
- **Risk**: Malicious clients can easily spoof Referer headers
- **Mitigation**: Use in combination with other policies (IP, rate limiting)
- **Best Practice**: Don't rely solely on Referer for security

### 2. False Positives
- **Risk**: Legitimate requests blocked due to pattern matches
- **Mitigation**: Test patterns thoroughly in staging
- **Strategy**: Start with blacklist mode, add patterns incrementally

### 3. Empty Referer Handling
- **Risk**: Some legitimate requests may not include Referer headers
- **Mitigation**: Configure appropriate handling for empty referers
- **Strategy**: Consider allowing empty referers in whitelist mode

### 4. Performance Impact
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

## Use Cases and Scenarios

### 1. CSRF Protection
- **Goal**: Prevent cross-site request forgery attacks
- **Strategy**: Blacklist known malicious domains
- **Configuration**: Use blacklist mode with specific domains

### 2. API Access Control
- **Goal**: Restrict API access to trusted partners
- **Strategy**: Whitelist partner domains
- **Configuration**: Use whitelist mode with partner domains

### 3. Internal Resource Protection
- **Goal**: Protect internal resources from external access
- **Strategy**: Whitelist internal domains only
- **Configuration**: Use whitelist mode with internal patterns

### 4. Partner Integration
- **Goal**: Allow specific partner integrations
- **Strategy**: Whitelist partner domains
- **Configuration**: Use whitelist mode with partner patterns

## Monitoring and Debugging

### 1. Logging
```go
// Log blocked requests with referer
gk.logger.Printf("Referer blocked: %s (reason: %s)", referer, reason)

// Log invalid policy modes
gk.logger.Printf("Invalid referer policy mode: %s", config.Mode)
```

### 2. Metrics
- Blocked requests per referer pattern
- Performance impact of regex patterns
- False positive rates

### 3. Testing
```go
// Test cases for referer matching
testCases := []struct {
    referer  string
    expected bool
}{
    {"https://trusted-site.com", true},
    {"https://malicious-site.com", false},
    {"", false}, // Empty referer
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

### 4. Security Considerations
- Don't rely solely on Referer for security
- Use in combination with other policies
- Consider browser behavior with Referer headers

## Browser and Referer Behavior

### 1. Referer Header Availability
- **HTTPS to HTTPS**: Full referer included
- **HTTPS to HTTP**: Referer may be stripped
- **HTTP to HTTP**: Full referer included
- **Direct Navigation**: No referer header

### 2. Browser Privacy Settings
- **Private/Incognito**: May strip or modify referer
- **Privacy Extensions**: May block referer headers
- **User Settings**: May disable referer sending

### 3. Mobile and App Behavior
- **Mobile Apps**: May not send referer headers
- **WebViews**: May have different referer behavior
- **Progressive Web Apps**: May have limited referer support

## Future Enhancements

### 1. Advanced Features
- Referer fingerprinting
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

### 4. Enhanced Security
- Referer validation algorithms
- Cross-origin request analysis
- Advanced CSRF protection 