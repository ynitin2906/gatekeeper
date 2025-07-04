package gatekeeper

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ynitin2906/gatekeeper/internal/utils"
	"github.com/ynitin2906/gatekeeper/store"
)

// PolicyMode defines whether a list is a blacklist or a whitelist.
type PolicyMode string

const (
	ModeBlacklist PolicyMode = "BLACKLIST" // Block if matched
	ModeWhitelist PolicyMode = "WHITELIST" // Allow only if matched, block others
)

// --- User-Agent Policy ---
type UserAgentPolicyConfig struct {
	Mode     PolicyMode `json:"mode" yaml:"mode"`         // BLACKLIST or WHITELIST
	Exact    []string   `json:"exact" yaml:"exact"`       // List of exact User-Agent strings
	Patterns []string   `json:"patterns" yaml:"patterns"` // List of regex patterns for User-Agents
}

// --- Referer Policy ---
type RefererPolicyConfig struct {
	Mode     PolicyMode `json:"mode" yaml:"mode"`         // BLACKLIST or WHITELIST
	Exact    []string   `json:"exact" yaml:"exact"`       // List of exact Referer strings
	Patterns []string   `json:"patterns" yaml:"patterns"` // List of regex patterns for Referers
}

// --- IP Policy ---
type IPPolicyConfig struct {
	Mode              PolicyMode `json:"mode" yaml:"mode"`                           // BLACKLIST or WHITELIST
	IPs               []string   `json:"ips" yaml:"ips"`                             // List of individual IPs
	CIDRs             []string   `json:"cidrs" yaml:"cidrs"`                         // List of CIDR ranges
	TrustProxyHeaders bool       `json:"trustProxyHeaders" yaml:"trustProxyHeaders"` // Trust X-Forwarded-For, X-Real-IP
	TrustedProxies    []string   `json:"trustedProxies" yaml:"trustedProxies"`       // List of trusted proxy IPs/CIDRs (if TrustProxyHeaders is true)

	// Internal: these will be populated after parsing IPs/CIDRs
	// parsedIPs (map for fast lookup)
	// parsedCIDRs
	// parsedTrustedProxies
}

// --- Rate Limiter ---
type RateLimiterExceptions struct {
	IPWhitelist            []string `json:"ipWhitelist" yaml:"ipWhitelist"`                       // List of IP addresses or CIDR ranges
	RouteWhitelistPatterns []string `json:"routeWhitelistPatterns" yaml:"routeWhitelistPatterns"` // List of regex patterns for URL routes

	// Internal (parsed versions)
	parsedIPs             map[string]struct{} // Stores individual IPs for quick lookup
	parsedCIDRs           []*net.IPNet        // Stores parsed CIDR blocks
	compiledRoutePatterns []*regexp.Regexp    // Stores compiled regex for route patterns
}

type RateLimiterConfig struct {
	Requests   int64                  `json:"requests" yaml:"requests"` // Max requests per period
	Period     time.Duration          `json:"period" yaml:"period"`     // Time window
	Store      store.RateLimiterStore `json:"-" yaml:"-"`               // Storage backend (e.g., in-memory, Redis)
	Exceptions *RateLimiterExceptions `json:"exceptions,omitempty" yaml:"exceptions,omitempty"`
	// Message to return when rate limited, defaults to "Too Many Requests"
	LimitExceededMessage string `json:"limitExceededMessage,omitempty" yaml:"limitExceededMessage,omitempty"`
	// HTTP status code to return when rate limited, defaults to http.StatusTooManyRequests
	LimitExceededStatusCode int `json:"limitExceededStatusCode,omitempty" yaml:"limitExceededStatusCode,omitempty"`
}

// UnmarshalJSON implements custom JSON unmarshaling for RateLimiterConfig
func (rlc *RateLimiterConfig) UnmarshalJSON(data []byte) error {
	// Define a temporary struct with Period as string
	type tempRateLimiterConfig struct {
		Requests                int64                  `json:"requests"`
		Period                  string                 `json:"period"`
		Exceptions              *RateLimiterExceptions `json:"exceptions,omitempty"`
		LimitExceededMessage    string                 `json:"limitExceededMessage,omitempty"`
		LimitExceededStatusCode int                    `json:"limitExceededStatusCode,omitempty"`
	}

	var temp tempRateLimiterConfig
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	// Parse the period string
	period, err := time.ParseDuration(temp.Period)
	if err != nil {
		return fmt.Errorf("invalid period format '%s': %w", temp.Period, err)
	}

	// Set the values
	rlc.Requests = temp.Requests
	rlc.Period = period
	rlc.Exceptions = temp.Exceptions
	rlc.LimitExceededMessage = temp.LimitExceededMessage
	rlc.LimitExceededStatusCode = temp.LimitExceededStatusCode

	return nil
}

// MarshalJSON implements custom JSON marshaling for RateLimiterConfig
func (rlc RateLimiterConfig) MarshalJSON() ([]byte, error) {
	// Define a temporary struct with Period as string
	type tempRateLimiterConfig struct {
		Requests                int64                  `json:"requests"`
		Period                  string                 `json:"period"`
		Exceptions              *RateLimiterExceptions `json:"exceptions,omitempty"`
		LimitExceededMessage    string                 `json:"limitExceededMessage,omitempty"`
		LimitExceededStatusCode int                    `json:"limitExceededStatusCode,omitempty"`
	}

	temp := tempRateLimiterConfig{
		Requests:                rlc.Requests,
		Period:                  rlc.Period.String(),
		Exceptions:              rlc.Exceptions,
		LimitExceededMessage:    rlc.LimitExceededMessage,
		LimitExceededStatusCode: rlc.LimitExceededStatusCode,
	}

	return json.Marshal(temp)
}

// --- Profanity Filter ---
type ProfanityFilterConfig struct {
	BlockWords []string `json:"blockWords" yaml:"blockWords"` // Words to block (case-insensitive)
	AllowWords []string `json:"allowWords" yaml:"allowWords"` // Words to explicitly allow (case-insensitive, e.g., Scunthorpe)

	CheckQueryParams bool `json:"checkQueryParams" yaml:"checkQueryParams"` // Check query parameters
	CheckFormFields  bool `json:"checkFormFields" yaml:"checkFormFields"`   // Check x-www-form-urlencoded and multipart/form-data fields
	CheckJSONBody    bool `json:"checkJsonBody" yaml:"checkJsonBody"`       // Check JSON request bodies
	// TODO: Option to specify which fields to check, or check all by default.

	// Message to return when profanity is detected, defaults to "Bad Request"
	BlockedMessage string `json:"blockedMessage,omitempty" yaml:"blockedMessage,omitempty"`
	// HTTP status code to return when profanity is detected, defaults to http.StatusBadRequest
	BlockedStatusCode int `json:"blockedStatusCode,omitempty" yaml:"blockedStatusCode,omitempty"`
}

// --- Main Config ---
type Config struct {
	UserAgentPolicy *UserAgentPolicyConfig `json:"userAgentPolicy,omitempty" yaml:"userAgentPolicy,omitempty"`
	IPPolicy        *IPPolicyConfig        `json:"ipPolicy,omitempty" yaml:"ipPolicy,omitempty"`
	RefererPolicy   *RefererPolicyConfig   `json:"refererPolicy,omitempty" yaml:"refererPolicy,omitempty"`
	RateLimiter     *RateLimiterConfig     `json:"rateLimiter,omitempty" yaml:"rateLimiter,omitempty"`
	ProfanityFilter *ProfanityFilterConfig `json:"profanityFilter,omitempty" yaml:"profanityFilter,omitempty"`

	// Logger for Gatekeeper actions, defaults to standard log package
	Logger *log.Logger `json:"-" yaml:"-"`
	// Default HTTP status code for blocked requests if not specified by a specific policy
	DefaultBlockStatusCode int `json:"defaultBlockStatusCode,omitempty" yaml:"defaultBlockStatusCode,omitempty"`
	// Default message for blocked requests
	DefaultBlockMessage string `json:"defaultBlockMessage,omitempty" yaml:"defaultBlockMessage,omitempty"`
}

// Gatekeeper holds the compiled configuration and provides middleware methods.
type Gatekeeper struct {
	config Config
	// Pre-compiled/parsed versions of config options for performance
	parsedUserAgentPolicy *parsedUserAgentPolicy
	parsedIPPolicy        *parsedIPPolicy
	parsedRefererPolicy   *parsedRefererPolicy
	// Rate limiter store is already part of RateLimiterConfig
	parsedProfanityFilter *parsedProfanityFilter
	logger                *log.Logger
}

// Internal structs to hold processed configuration
type parsedUserAgentPolicy struct {
	config           *UserAgentPolicyConfig
	compiledPatterns []*regexp.Regexp
	exactSet         map[string]struct{}
}

type parsedIPPolicy struct {
	config               *IPPolicyConfig
	parsedIPs            map[string]struct{} // Storing string representation of net.IP for map key
	parsedCIDRs          []*net.IPNet
	parsedTrustedProxies []*net.IPNet
}

type parsedRefererPolicy struct {
	config           *RefererPolicyConfig
	compiledPatterns []*regexp.Regexp
	exactSet         map[string]struct{}
}

type parsedProfanityFilter struct {
	config        *ProfanityFilterConfig
	blockWordsSet map[string]struct{}
	allowWordsSet map[string]struct{}
}

// New creates a new Gatekeeper instance with the given configuration.
// It validates the configuration and pre-compiles/parses necessary parts.
func New(config Config) (*Gatekeeper, error) {
	gk := &Gatekeeper{
		config: config,
	}

	// Set defaults
	if config.Logger == nil {
		gk.logger = log.New(log.Writer(), "[Gatekeeper] ", log.LstdFlags)
	} else {
		gk.logger = config.Logger
	}
	if config.DefaultBlockStatusCode == 0 {
		config.DefaultBlockStatusCode = http.StatusForbidden
	}
	if config.DefaultBlockMessage == "" {
		config.DefaultBlockMessage = "Forbidden"
	}
	// Ensure DefaultBlockMessage is applied to policies if their specific messages are empty
	if config.RateLimiter != nil {
		if config.RateLimiter.LimitExceededMessage == "" {
			config.RateLimiter.LimitExceededMessage = config.DefaultBlockMessage
		}
		if config.RateLimiter.LimitExceededStatusCode == 0 {
			config.RateLimiter.LimitExceededStatusCode = http.StatusTooManyRequests // Use proper default for rate limiter
		}
	}
	if config.ProfanityFilter != nil {
		if config.ProfanityFilter.BlockedMessage == "" {
			config.ProfanityFilter.BlockedMessage = config.DefaultBlockMessage
		}
		if config.ProfanityFilter.BlockedStatusCode == 0 {
			config.ProfanityFilter.BlockedStatusCode = http.StatusBadRequest // Use proper default for profanity filter
		}
	}

	var err error
	if config.UserAgentPolicy != nil {
		gk.parsedUserAgentPolicy, err = newParsedUserAgentPolicy(config.UserAgentPolicy)
		if err != nil {
			return nil, fmt.Errorf("failed to parse user agent policy: %w", err)
		}
	}

	if config.IPPolicy != nil {
		gk.parsedIPPolicy, err = newParsedIPPolicy(config.IPPolicy)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IP policy: %w", err)
		}
	}

	if config.RefererPolicy != nil {
		gk.parsedRefererPolicy, err = newParsedRefererPolicy(config.RefererPolicy)
		if err != nil {
			return nil, fmt.Errorf("failed to parse referer policy: %w", err)
		}
	}

	if config.RateLimiter != nil {
		if config.RateLimiter.Requests <= 0 || config.RateLimiter.Period <= 0 {
			return nil, fmt.Errorf("rate limiter requests and period must be positive")
		}
		if config.RateLimiter.Store == nil {
			gk.logger.Println("RateLimiter store not provided, defaulting to in-memory store.")
			config.RateLimiter.Store = store.NewMemoryStore(config.RateLimiter.Period + 5*time.Minute) // Cleanup a bit after period
		}

		if config.RateLimiter.Exceptions != nil {
			exc := config.RateLimiter.Exceptions
			exc.parsedIPs = make(map[string]struct{})
			exc.parsedCIDRs = make([]*net.IPNet, 0)
			exc.compiledRoutePatterns = make([]*regexp.Regexp, 0)

			for _, ipStr := range exc.IPWhitelist {
				if strings.Contains(ipStr, "/") {
					_, cidr, err := net.ParseCIDR(ipStr)
					if err != nil {
						gk.logger.Printf("Warning: Invalid CIDR in rate limiter IP whitelist '%s': %v", ipStr, err)
						continue
					}
					exc.parsedCIDRs = append(exc.parsedCIDRs, cidr)
				} else {
					parsedIP := net.ParseIP(ipStr)
					if parsedIP == nil {
						gk.logger.Printf("Warning: Invalid IP address in rate limiter IP whitelist '%s'", ipStr)
						continue
					}
					exc.parsedIPs[parsedIP.String()] = struct{}{}
				}
			}

			for _, patternStr := range exc.RouteWhitelistPatterns {
				re, err := regexp.Compile(patternStr)
				if err != nil {
					gk.logger.Printf("Warning: Invalid regex pattern in rate limiter route whitelist '%s': %v", patternStr, err)
					continue
				}
				exc.compiledRoutePatterns = append(exc.compiledRoutePatterns, re)
			}
		}
	}

	if config.ProfanityFilter != nil {
		gk.parsedProfanityFilter, err = newParsedProfanityFilter(config.ProfanityFilter)
		if err != nil {
			return nil, fmt.Errorf("failed to parse profanity filter: %w", err)
		}
	}

	return gk, nil
}

// Helper to respond with a block
func (gk *Gatekeeper) blockRequest(w http.ResponseWriter, r *http.Request, statusCode int, message string, reason string) {
	clientIPStr := "unknown"
	parsedClientIP, err := utils.GetClientIPFromRequest(r,
		gk.config.IPPolicy != nil && gk.config.IPPolicy.TrustProxyHeaders,
		gk.parsedTrustedProxiesIfAvailable()) // Use helper for safety
	if err == nil && parsedClientIP != nil {
		clientIPStr = parsedClientIP.String()
	} else {
		ip, _, splitErr := net.SplitHostPort(r.RemoteAddr)
		if splitErr == nil {
			clientIPStr = ip
		} else {
			clientIPStr = r.RemoteAddr
		}
		if err != nil {
			gk.logger.Printf("blockRequest: Error getting client IP: %v. Using: %s", err, clientIPStr)
		} else if parsedClientIP == nil {
			gk.logger.Printf("blockRequest: GetClientIPFromRequest returned nil IP. Using: %s", clientIPStr)
		}
	}
	gk.logger.Printf("Request blocked: %s %s from %s. Reason: %s", r.Method, r.URL.Path, clientIPStr, reason)
	http.Error(w, message, statusCode)
}

// --- Middleware Chaining ---

// Protect wraps a http.Handler with all configured Gatekeeper policies in a sensible order.
// Order: IP Policy -> User-Agent Policy -> Referer Policy -> Rate Limiter -> Profanity Filter
func (gk *Gatekeeper) Protect(next http.Handler) http.Handler {
	handler := next
	if gk.config.ProfanityFilter != nil && gk.parsedProfanityFilter != nil {
		handler = gk.ProfanityPolicy(handler)
	}
	if gk.config.RateLimiter != nil {
		handler = gk.RateLimit(handler) // RateLimit middleware is in rate_limiter.go
	}
	if gk.config.RefererPolicy != nil && gk.parsedRefererPolicy != nil {
		handler = gk.RefererPolicy(handler)
	}
	if gk.config.UserAgentPolicy != nil && gk.parsedUserAgentPolicy != nil {
		handler = gk.UserAgentPolicy(handler)
	}
	if gk.config.IPPolicy != nil && gk.parsedIPPolicy != nil {
		handler = gk.IPPolicy(handler)
	}
	return handler
}

func (gk *Gatekeeper) isRateLimitExempt(r *http.Request, clientIP net.IP) bool {
	cfg := gk.config.RateLimiter
	if cfg == nil || cfg.Exceptions == nil || clientIP == nil {
		return false
	}
	exc := cfg.Exceptions

	// Check IP Whitelist
	clientIPStr := clientIP.String()
	if _, ok := exc.parsedIPs[clientIPStr]; ok {
		gk.logger.Printf("Rate limit exempt: IP %s in whitelist", clientIPStr)
		return true
	}
	for _, cidr := range exc.parsedCIDRs {
		if cidr.Contains(clientIP) {
			gk.logger.Printf("Rate limit exempt: IP %s in whitelisted CIDR %s", clientIPStr, cidr.String())
			return true
		}
	}

	// Check Route Whitelist
	for _, re := range exc.compiledRoutePatterns {
		if re.MatchString(r.URL.Path) {
			gk.logger.Printf("Rate limit exempt: Route %s matches pattern %s", r.URL.Path, re.String())
			return true
		}
	}
	return false
}

// Helper to get parsedTrustedProxies safely if IPPolicy is nil
func (gk *Gatekeeper) parsedTrustedProxiesIfAvailable() []*net.IPNet {
	if gk.parsedIPPolicy == nil {
		return nil
	}
	return gk.parsedIPPolicy.parsedTrustedProxies
}

// Helper methods to check if policies are configured

// ConfiguredIPPolicy returns true if IP policy is configured and active
func (gk *Gatekeeper) ConfiguredIPPolicy() bool {
	return gk.config.IPPolicy != nil && gk.parsedIPPolicy != nil
}

// ConfiguredUserAgentPolicy returns true if User-Agent policy is configured and active
func (gk *Gatekeeper) ConfiguredUserAgentPolicy() bool {
	return gk.config.UserAgentPolicy != nil && gk.parsedUserAgentPolicy != nil
}

// ConfiguredRateLimiter returns true if rate limiter is configured and active
func (gk *Gatekeeper) ConfiguredRateLimiter() bool {
	return gk.config.RateLimiter != nil
}

// ConfiguredProfanityFilter returns true if profanity filter is configured and active
func (gk *Gatekeeper) ConfiguredProfanityFilter() bool {
	return gk.config.ProfanityFilter != nil && gk.parsedProfanityFilter != nil
}

// ConfiguredRefererPolicy returns true if Referer policy is configured and active
func (gk *Gatekeeper) ConfiguredRefererPolicy() bool {
	return gk.config.RefererPolicy != nil && gk.parsedRefererPolicy != nil
}

// TODO: Implement individual middleware methods:
// UserAgentPolicy(next http.Handler) http.Handler
// IPPolicy(next http.Handler) http.Handler
// RateLimit(next http.Handler) http.Handler // This one is already in rate_limiter.go
// ProfanityPolicy(next http.Handler) http.Handler
