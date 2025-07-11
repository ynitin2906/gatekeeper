# Rate Limiting Implementation Approach

## Overview

The rate limiting component in Gatekeeper implements a sliding window rate limiter that tracks requests per client IP address within a configurable time window. It provides protection against abuse, DDoS attacks, and ensures fair resource distribution.

## Technical Architecture

### Core Components

1. **RateLimiterConfig**: Configuration structure defining limits and behavior
2. **RateLimiterStore**: Interface for storage backends (memory, Redis, etc.)
3. **MemoryStore**: In-memory implementation for single-server deployments
4. **Middleware Chain**: HTTP middleware integration

### Configuration Structure

```go
type RateLimiterConfig struct {
    Requests   int64                  // Max requests per period
    Period     time.Duration          // Time window
    Store      store.RateLimiterStore // Storage backend
    Exceptions *RateLimiterExceptions // Whitelist exemptions
    LimitExceededMessage string       // Custom error message
    LimitExceededStatusCode int       // Custom HTTP status code
}
```

## Implementation Details

### 1. Client IP Resolution

The rate limiter uses a sophisticated IP resolution strategy:

```go
// Primary: Use proxy headers if trusted
clientIP, err := utils.GetClientIPFromRequest(r, trustProxyHeaders, trustedProxies)

// Fallback: Use RemoteAddr if proxy resolution fails
if err != nil {
    ipStr, _, _ := net.SplitHostPort(r.RemoteAddr)
    clientKeyForStore = ipStr
}
```

**Proxy Header Support:**
- `X-Forwarded-For`: Handles comma-separated IP chains
- `X-Real-IP`: Direct client IP from trusted proxies
- Trusted proxy validation using CIDR ranges

### 2. Sliding Window Algorithm

The implementation uses a **sliding window** approach rather than fixed windows:

```go
// Remove timestamps older than the window
validTimestamps := []time.Time{}
windowStart := now.Add(-window)
for _, ts := range record.timestamps {
    if ts.After(windowStart) {
        validTimestamps = append(validTimestamps, ts)
    }
}
```

**Advantages:**
- Prevents request bursts at window boundaries
- More accurate rate limiting
- Smooth traffic distribution

### 3. Storage Backend Interface

```go
type RateLimiterStore interface {
    Allow(key string, limit int64, window time.Duration) (allowed bool, retryAfter time.Duration, err error)
    Cleanup()
}
```

**Memory Store Implementation:**
- Thread-safe using `sync.Mutex`
- Automatic cleanup of stale records
- Configurable TTL for record retention

### 4. Exception Handling

Rate limiter supports two types of exemptions:

```go
type RateLimiterExceptions struct {
    IPWhitelist            []string // IP addresses or CIDR ranges
    RouteWhitelistPatterns []string // Regex patterns for URL routes
}
```

**Exemption Logic:**
1. Check if client IP is in whitelist
2. Check if request path matches whitelist patterns
3. Skip rate limiting if either condition is met

### 5. HTTP Response Handling

When rate limit is exceeded:

```go
if !allowed {
    w.Header().Set("Retry-After", strconv.FormatInt(int64(retryAfter.Seconds()), 10))
    gk.blockRequest(w, r, rlc.LimitExceededStatusCode, rlc.LimitExceededMessage, reason)
    return
}
```

**Standard Compliance:**
- Sets `Retry-After` header with seconds until reset
- Configurable HTTP status code (default: 429)
- Custom error messages

## Performance Considerations

### 1. Memory Usage
- Records stored per unique client IP
- Automatic cleanup prevents memory leaks
- Configurable cleanup intervals

### 2. Concurrency
- Thread-safe operations using mutex
- Minimal lock contention
- Efficient timestamp management

### 3. Scalability
- Interface-based design allows Redis/DB backends
- Stateless middleware design
- Horizontal scaling support

## Configuration Examples

### Basic Rate Limiting
```json
{
  "rateLimiter": {
    "requests": 100,
    "period": "1m",
    "limitExceededMessage": "Too Many Requests",
    "limitExceededStatusCode": 429
  }
}
```

### With Exceptions
```json
{
  "rateLimiter": {
    "requests": 100,
    "period": "1m",
    "exceptions": {
      "ipWhitelist": ["192.168.1.0/24", "10.0.0.1"],
      "routeWhitelistPatterns": ["^/health$", "^/metrics$"]
    }
  }
}
```

## Security Considerations

### 1. IP Spoofing Protection
- Validates proxy headers against trusted sources
- Falls back to direct connection IP if untrusted
- Configurable trusted proxy ranges

### 2. Fail-Safe Behavior
- Fails open on storage errors
- Logs errors for monitoring
- Continues processing if rate limiter unavailable

### 3. Resource Protection
- Prevents memory exhaustion through cleanup
- Configurable limits prevent abuse
- Exception handling for critical endpoints

## Monitoring and Observability

### 1. Logging
- Rate limit violations logged with client IP
- Storage errors logged for debugging
- Exemption matches logged for audit

### 2. Metrics (Potential)
- Requests per second per IP
- Rate limit violations
- Storage backend performance
- Exception usage patterns

## Future Enhancements

### 1. Advanced Algorithms
- Token bucket implementation
- Leaky bucket algorithm
- Burst handling improvements

### 2. Distributed Support
- Redis backend implementation
- Database storage options
- Cluster coordination

### 3. Dynamic Configuration
- Runtime limit adjustments
- A/B testing support
- Machine learning integration 