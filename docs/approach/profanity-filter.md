# Profanity Filter Implementation Approach

## Overview

The Profanity Filter component in Gatekeeper provides sophisticated content filtering capabilities across multiple request components including query parameters, form fields, and JSON request bodies. It implements intelligent word matching with support for allowlists to prevent false positives and handles various content types efficiently.

## Technical Architecture

### Core Components

1. **ProfanityFilterConfig**: Configuration structure defining filter rules and content types
2. **parsedProfanityFilter**: Pre-processed word sets for efficient matching
3. **Multi-Content Scanning**: Support for query params, form fields, and JSON bodies
4. **Allowlist System**: Sophisticated false positive prevention

### Configuration Structure

```go
type ProfanityFilterConfig struct {
    BlockWords []string `json:"blockWords"` // Words to block (case-insensitive)
    AllowWords []string `json:"allowWords"` // Words to explicitly allow (case-insensitive)
    
    CheckQueryParams bool `json:"checkQueryParams"` // Check query parameters
    CheckFormFields  bool `json:"checkFormFields"`  // Check form data
    CheckJSONBody    bool `json:"checkJsonBody"`    // Check JSON request bodies
    
    BlockedMessage    string `json:"blockedMessage,omitempty"`    // Custom error message
    BlockedStatusCode int    `json:"blockedStatusCode,omitempty"` // Custom HTTP status code
}
```

## Implementation Details

### 1. Word Set Processing and Optimization

The filter pre-processes word lists for efficient matching:

```go
func newParsedProfanityFilter(config *ProfanityFilterConfig) (*parsedProfanityFilter, error) {
    parsed := &parsedProfanityFilter{
        config:        config,
        blockWordsSet: make(map[string]struct{}),
        allowWordsSet: make(map[string]struct{}),
    }
    
    if len(config.BlockWords) == 0 {
        return nil, fmt.Errorf("ProfanityFilter defined but no blockWords provided")
    }
    
    // Process block words (case-insensitive)
    for _, word := range config.BlockWords {
        parsed.blockWordsSet[strings.ToLower(word)] = struct{}{}
    }
    
    // Process allow words (case-insensitive)
    for _, word := range config.AllowWords {
        parsed.allowWordsSet[strings.ToLower(word)] = struct{}{}
    }
    
    return parsed, nil
}
```

**Optimization Features:**
- Case-insensitive word matching using `strings.ToLower()`
- Hash map lookups for O(1) word checking
- Separate sets for blocked and allowed words
- Validation during initialization

### 2. Multi-Content Type Scanning

The filter implements sophisticated scanning across different content types:

#### Query Parameter Scanning
```go
func (gk *Gatekeeper) scanValuesForProfanity(values url.Values) bool {
    p := gk.parsedProfanityFilter
    
    for _, vals := range values {
        for _, val := range vals {
            lowerVal := strings.ToLower(val)
            
            // Check if entire value is allowed
            if _, isAllowed := p.allowWordsSet[lowerVal]; isAllowed {
                continue
            }
            
            // Check for blocked words within the value
            for profaneWord := range p.blockWordsSet {
                if strings.Contains(lowerVal, profaneWord) {
                    // Check if this specific word is allowed
                    if _, isDirectlyAllowed := p.allowWordsSet[profaneWord]; isDirectlyAllowed {
                        continue
                    }
                    
                    // Check if any allowed word containing this profane word is present
                    isWordAllowed := false
                    for allowedWord := range p.allowWordsSet {
                        if strings.Contains(allowedWord, profaneWord) && strings.Contains(lowerVal, allowedWord) {
                            isWordAllowed = true
                            break
                        }
                    }
                    
                    if !isWordAllowed {
                        gk.logger.Printf("Profanity found in value: '%s' (matched: '%s')", val, profaneWord)
                        return true
                    }
                }
            }
        }
    }
    return false
}
```

#### Form Field Scanning
```go
// Check application/x-www-form-urlencoded
if mediaType == "application/x-www-form-urlencoded" {
    if err := r.ParseForm(); err == nil {
        if gk.scanValuesForProfanity(r.Form) {
            gk.blockRequest(w, r, p.BlockedStatusCode, p.BlockedMessage, "Profanity in form data (urlencoded)")
            return
        }
    }
}

// Check multipart/form-data
if mediaType == "multipart/form-data" {
    if err := r.ParseMultipartForm(10 << 20); err == nil && r.MultipartForm != nil {
        if gk.scanValuesForProfanity(r.MultipartForm.Value) {
            gk.blockRequest(w, r, p.BlockedStatusCode, p.BlockedMessage, "Profanity in form data (multipart)")
            return
        }
    }
}
```

#### JSON Body Scanning
```go
func (gk *Gatekeeper) scanJSONForProfanity(data interface{}) bool {
    p := gk.parsedProfanityFilter
    
    switch v := data.(type) {
    case string:
        lowerVal := strings.ToLower(v)
        
        // Check if entire string is allowed
        if _, isAllowed := p.allowWordsSet[lowerVal]; isAllowed {
            return false
        }
        
        // Check for blocked words within the string
        for profaneWord := range p.blockWordsSet {
            if strings.Contains(lowerVal, profaneWord) {
                // Check if this specific word is allowed
                if _, isDirectlyAllowed := p.allowWordsSet[profaneWord]; isDirectlyAllowed {
                    continue
                }
                
                // Check if any allowed word containing this profane word is present
                isWordAllowed := false
                for allowedWord := range p.allowWordsSet {
                    if strings.Contains(allowedWord, profaneWord) && strings.Contains(lowerVal, allowedWord) {
                        isWordAllowed = true
                        break
                    }
                }
                
                if !isWordAllowed {
                    gk.logger.Printf("Profanity found in JSON string: '%s' (matched: '%s')", v, profaneWord)
                    return true
                }
            }
        }
        
    case map[string]interface{}:
        for _, val := range v {
            if gk.scanJSONForProfanity(val) {
                return true
            }
        }
        
    case []interface{}:
        for _, item := range v {
            if gk.scanJSONForProfanity(item) {
                return true
            }
        }
    }
    
    return false
}
```

### 3. Allowlist System

The filter implements a sophisticated allowlist system to prevent false positives:

#### Allowlist Logic
1. **Exact Match**: If the entire value is in the allowlist, skip checking
2. **Direct Word Allow**: If the specific profane word is in the allowlist, skip it
3. **Containing Word Allow**: If an allowed word contains the profane word and is present, allow it

#### Scunthorpe Problem Solution
```go
// Example: Allow "Scunthorpe" while blocking "cunt"
allowWords := []string{"scunthorpe", "assassin", "classic"}
blockWords := []string{"cunt", "ass", "class"}

// "Scunthorpe" contains "cunt" but is explicitly allowed
// "assassin" contains "ass" but is explicitly allowed
// "classic" contains "class" but is explicitly allowed
```

### 4. Request Body Handling

The filter carefully manages request body reading to avoid conflicts:

```go
// Read body once for JSON checking
if p.CheckJSONBody && strings.HasPrefix(contentType, "application/json") {
    if len(requestBodyCopy) == 0 && r.Body != nil && r.Body != http.NoBody {
        var errRead error
        requestBodyCopy, errRead = io.ReadAll(r.Body)
        r.Body.Close()
        
        if errRead != nil {
            gk.logger.Printf("ProfanityFilter: Error reading request body: %v", errRead)
            next.ServeHTTP(w, r)
            return
        }
        
        // Restore the body for downstream handlers
        r.Body = io.NopCloser(bytes.NewBuffer(requestBodyCopy))
    }
    
    if len(requestBodyCopy) > 0 {
        var jsonData interface{}
        if err := json.Unmarshal(requestBodyCopy, &jsonData); err == nil {
            if gk.scanJSONForProfanity(jsonData) {
                gk.blockRequest(w, r, p.BlockedStatusCode, p.BlockedMessage, "Profanity in JSON body")
                return
            }
        }
    }
}
```

## Configuration Examples

### Basic Profanity Filtering
```json
{
  "profanityFilter": {
    "blockWords": ["badword1", "badword2", "profanity"],
    "checkQueryParams": true,
    "checkFormFields": true,
    "checkJsonBody": true,
    "blockedMessage": "Inappropriate content detected",
    "blockedStatusCode": 400
  }
}
```

### With Allowlist Protection
```json
{
  "profanityFilter": {
    "blockWords": ["cunt", "ass", "class"],
    "allowWords": ["scunthorpe", "assassin", "classic"],
    "checkQueryParams": true,
    "checkFormFields": true,
    "checkJsonBody": true
  }
}
```

### Selective Content Checking
```json
{
  "profanityFilter": {
    "blockWords": ["spam", "malware", "hack"],
    "checkQueryParams": true,
    "checkFormFields": false,
    "checkJsonBody": true
  }
}
```

## Performance Characteristics

### Time Complexity
- **Word Lookup**: O(1) hash map lookup for exact matches
- **String Contains**: O(n*m) where n = string length, m = word length
- **JSON Traversal**: O(d) where d = depth of JSON structure
- **Overall**: Linear with content size and word count

### Memory Usage
- **Word Sets**: O(b + a) where b = blocked words, a = allowed words
- **Request Body**: Temporary copy for JSON processing
- **Per Request**: Minimal additional memory beyond body copy

### Optimization Strategies
1. **Hash Map Lookups**: O(1) word existence checking
2. **Early Exit**: Stop scanning on first match
3. **Case Normalization**: Single ToLower() call per value
4. **Body Management**: Read body once, restore for downstream

## Security Considerations

### 1. Content Injection
- **Risk**: Malicious content in request bodies
- **Mitigation**: Proper body size limits and validation
- **Strategy**: Use with other security measures

### 2. False Positives
- **Risk**: Legitimate content blocked due to word matches
- **Mitigation**: Comprehensive allowlist system
- **Best Practice**: Test thoroughly with real content

### 3. Performance Impact
- **Risk**: Large request bodies can impact performance
- **Mitigation**: Configurable body size limits
- **Monitoring**: Track processing times

## Content Type Support

### 1. Query Parameters
- **Format**: `?param=value&param2=value2`
- **Processing**: URL-decoded and scanned
- **Performance**: Fast, no body reading required

### 2. Form Data
- **application/x-www-form-urlencoded**: Key-value pairs
- **multipart/form-data**: File uploads and form fields
- **Processing**: Parsed and scanned for text values

### 3. JSON Bodies
- **Support**: Any valid JSON structure
- **Traversal**: Recursive scanning of all string values
- **Types**: Objects, arrays, and primitive values

## Monitoring and Debugging

### 1. Logging
```go
// Log detected profanity with context
gk.logger.Printf("Profanity found in value: '%s' (matched: '%s')", val, profaneWord)
gk.logger.Printf("Profanity found in JSON string: '%s' (matched: '%s')", v, profaneWord)
```

### 2. Metrics
- Profanity detection rates by content type
- False positive rates
- Processing time per request

### 3. Testing
```go
// Test cases for word matching
testCases := []struct {
    content string
    expected bool
}{
    {"hello world", false},
    {"hello badword world", true},
    {"hello scunthorpe world", false}, // Allowlist protection
}
```

## Best Practices

### 1. Word List Management
- Use specific words over broad patterns
- Maintain comprehensive allowlists
- Regular review and updates

### 2. Content Type Selection
- Enable only necessary content types
- Consider performance impact
- Test with real traffic patterns

### 3. Allowlist Design
- Include common false positive cases
- Document allowlist reasoning
- Regular review of allowlist effectiveness

## Future Enhancements

### 1. Advanced Features
- Machine learning-based detection
- Context-aware filtering
- Multi-language support

### 2. Performance Improvements
- Parallel content scanning
- Caching of scan results
- Optimized word matching algorithms

### 3. Integration
- External profanity databases
- Real-time word list updates
- Content analysis APIs 