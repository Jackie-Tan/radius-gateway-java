# RADIUS Gateway - Security Configuration Guide

## Overview

The Java RADIUS Gateway implements comprehensive security validation based on RADIUS RFCs (2865, 2869, 5080). This guide covers all security features, configuration options, and best practices for production deployment.

**Security Status: ✅ PRODUCTION-READY with RFC Compliance**

---

## Security Architecture

### Defense in Depth Strategy

The RADIUS Gateway employs multiple layers of security validation:

1. **Packet-Level Validation** - Header structure and bounds checking
2. **Attribute-Level Validation** - Individual attribute validation and occurrence rules  
3. **Cryptographic Validation** - Request/Response Authenticator verification
4. **Replay Protection** - Duplicate packet detection and replay attack mitigation
5. **Protocol Compliance** - RFC-mandated attribute requirements and formats

### Security Validation Flow

```
Incoming RADIUS Packet
          ↓
┌─────────────────────────┐
│ 1. Packet Bounds Check  │ ← Header structure, length validation
└─────────────────────────┘
          ↓
┌─────────────────────────┐
│ 2. Attribute Validation │ ← Individual attributes, occurrence rules
└─────────────────────────┘
          ↓
┌─────────────────────────┐
│ 3. Replay Protection    │ ← Duplicate detection, identifier tracking
└─────────────────────────┘
          ↓
┌─────────────────────────┐
│ 4. Authenticator Check  │ ← Request Authenticator MD5 validation
└─────────────────────────┘
          ↓
┌─────────────────────────┐
│ 5. Message-Authenticator│ ← HMAC-MD5 validation (if present)
└─────────────────────────┘
          ↓
    Authentication Processing
```

---

## Security Features Configuration

### RadiusSecurityValidator Configuration

All security features are controlled through the `RadiusSecurityValidator` interface with the following configurable options:

#### Security Feature Enumeration

```java
public enum SecurityFeature {
    PACKET_BOUNDS_VALIDATION,           // RFC 2865 §3 packet structure
    ATTRIBUTE_BOUNDS_VALIDATION,        // RFC 2865 §3 attribute validation
    REQUEST_AUTHENTICATOR_VALIDATION,   // RFC 2865 §3 MD5 validation
    MESSAGE_AUTHENTICATOR_VALIDATION,   // RFC 2869 §5.14 HMAC-MD5
    REPLAY_PROTECTION,                  // RFC 5080 §2.2 duplicate detection
    STRICT_RFC_COMPLIANCE              // Enhanced RFC compliance mode
}
```

#### Default Security Configuration

```java
// Production-ready defaults (all critical features enabled)
PACKET_BOUNDS_VALIDATION = true          // Always enabled for basic security
ATTRIBUTE_BOUNDS_VALIDATION = true       // Always enabled for basic security  
REQUEST_AUTHENTICATOR_VALIDATION = true  // Critical for preventing packet forgery
MESSAGE_AUTHENTICATOR_VALIDATION = true  // Advanced security (HMAC-MD5)
REPLAY_PROTECTION = true                 // Enhanced protection against replay attacks
STRICT_RFC_COMPLIANCE = false            // Optional strict mode
```

### Programmatic Configuration

```java
// Create security validator with custom settings
RadiusSecurityValidator securityValidator = new RadiusSecurityValidatorImpl();

// Enable/disable specific features
securityValidator.configureSecurityFeature(
    SecurityFeature.MESSAGE_AUTHENTICATOR_VALIDATION, true);
securityValidator.configureSecurityFeature(
    SecurityFeature.STRICT_RFC_COMPLIANCE, true);

// Create server with custom security validator
RadiusServer server = new RadiusServer(port, nasRegistry, handler, securityValidator);
```

---

## Detailed Security Features

### 1. Packet Bounds Validation

**Purpose**: Validates RADIUS packet structure according to RFC 2865 §3

**Implementation**: `RadiusSecurityValidatorImpl.validatePacketBounds()`

**Validations Performed**:
- Minimum packet length (20 bytes for header)
- Maximum packet length (4096 bytes per RFC)
- Header structure integrity
- Length field consistency
- Code field validity (1-255)

**Configuration**:
```properties
# Always enabled - critical for basic security
security.packet.bounds.validation=true
```

**Error Responses**:
- Invalid packets are silently dropped (no response sent)
- Malformed packets trigger security logging

### 2. Attribute Bounds Validation

**Purpose**: Validates individual RADIUS attributes according to RFC 2865 §3

**Implementation**: `RadiusSecurityValidatorImpl.validateAttributeBounds()`

**Validations Performed**:
- Attribute length bounds (2-255 bytes)
- Value length consistency with attribute length field
- Total packet size validation
- Attribute occurrence rules (some must be unique)
- Required attribute presence for Access-Request packets

**Specific Attribute Rules**:
```java
// Must appear at most once per packet
USER_NAME (1)
USER_PASSWORD (2) 
CHAP_PASSWORD (3)
NAS_IP_ADDRESS (4)
NAS_PORT (5)
MESSAGE_AUTHENTICATOR (80)

// Can appear multiple times
REPLY_MESSAGE (18)
VENDOR_SPECIFIC (26)
```

**Required Attributes for Access-Request**:
- `User-Name` (1) - MUST be present
- `User-Password` (2) OR `CHAP-Password` (3) - One MUST be present
- `User-Password` and `CHAP-Password` are mutually exclusive

**Configuration**:
```properties
# Always enabled - critical for basic security
security.attribute.bounds.validation=true
```

### 3. Request Authenticator Validation

**Purpose**: Prevents packet forgery through cryptographic validation (RFC 2865 §3)

**Implementation**: `RadiusCodec.validateRequestAuthenticator()`

**Validation Process**:
1. **Access-Request packets**: Request Authenticator must be non-zero random value
2. **Response packets**: Response Authenticator = MD5(Code + ID + Length + Request Authenticator + Attributes + Shared Secret)
3. **Cryptographic verification** using shared secret

**Security Benefits**:
- Prevents packet forgery attacks
- Ensures packet integrity
- Validates shared secret without transmission

**Configuration**:
```properties
# Enabled by default - critical security feature
security.request.authenticator.validation=true
```

**Error Handling**:
- Invalid Request Authenticator → Silent packet drop
- Logs security violation for monitoring

### 4. Message-Authenticator Validation

**Purpose**: Advanced packet integrity protection using HMAC-MD5 (RFC 2869 §5.14)

**Implementation**: `RadiusSecurityValidatorImpl.validateMessageAuthenticator()`

**Validation Process**:
1. Check if Message-Authenticator attribute (80) is present
2. Validate attribute length (must be exactly 16 bytes)
3. Create packet copy with Message-Authenticator set to zeros
4. Compute HMAC-MD5 over modified packet using shared secret
5. Compare using constant-time comparison to prevent timing attacks

**HMAC-MD5 Computation**:
```
Message-Authenticator = HMAC-MD5(Type + Identifier + Length + 
                                Request Authenticator + 
                                Attributes (with Message-Authenticator = 0) + 
                                Shared Secret)
```

**Security Benefits**:
- Stronger integrity protection than Request Authenticator
- Prevents sophisticated forgery attacks
- Protects against packet modification

**Configuration**:
```properties
# Enabled by default - advanced security feature
security.message.authenticator.validation=true
```

### 5. Replay Protection

**Purpose**: Prevents replay attacks and duplicate packet processing (RFC 5080 §2.2)

**Implementation**: `RadiusSecurityValidatorImpl.checkReplayProtection()`

**Protection Mechanisms**:

#### Unique Packet Identification
```java
String packetKey = clientAddress + ":" + packetIdentifier + ":" + 
                   hexEncode(requestAuthenticator);
```

#### Replay Window Management
- **Default window**: 5 minutes (300,000 ms)
- **Configurable**: Adjust based on network conditions
- **Memory management**: Automatic cleanup of expired entries

#### Enhanced Protection Features
- **Identifier reuse detection**: Warns about suspicious patterns
- **Thread-safe tracking**: Uses `ConcurrentHashMap` for concurrent access
- **Memory limits**: Maximum 1,000 recent packets tracked

**Configuration**:
```properties
# Enabled by default - enhanced security
security.replay.protection=true
security.replay.window.ms=300000      # 5 minutes default
security.replay.max.packets=1000      # Memory limit
```

**Replay Attack Response**:
- Duplicate packets within window → Silent drop + security log
- Suspicious identifier reuse → Warning log (configurable to block)

### 6. Strict RFC Compliance Mode

**Purpose**: Enhanced validation for environments requiring strict RFC adherence

**Implementation**: Available across all validation components

**Additional Validations**:
- Stricter attribute format validation
- Enhanced protocol compliance checks
- More aggressive error handling
- Detailed compliance logging

**Configuration**:
```properties
# Optional - for strict compliance environments
security.strict.rfc.compliance=false   # Disabled by default
```

---

## Configuration Examples

### Production Environment (Recommended)

```properties
# Production-ready security configuration
server.port=1812
server.thread.pool.size=20

# Authentication configuration
auth.mode=otp-only
auth.otp.length=6

# Security features (production defaults)
security.packet.bounds.validation=true
security.attribute.bounds.validation=true
security.request.authenticator.validation=true
security.message.authenticator.validation=true
security.replay.protection=true
security.replay.window.ms=300000
security.strict.rfc.compliance=false

# NAS registry
nas.vpn-gateway.ip=192.168.1.100
nas.vpn-gateway.secret=your-secure-shared-secret
nas.vpn-gateway.name=Production VPN Gateway
```

### High-Security Environment

```properties
# Maximum security configuration
server.port=1812
server.thread.pool.size=10

# Authentication configuration  
auth.mode=two-stage
auth.otp.length=8

# Security features (maximum security)
security.packet.bounds.validation=true
security.attribute.bounds.validation=true
security.request.authenticator.validation=true
security.message.authenticator.validation=true
security.replay.protection=true
security.replay.window.ms=120000          # Stricter 2-minute window
security.strict.rfc.compliance=true       # Enable strict mode

# NAS registry with strong secrets
nas.vpn-gateway.ip=10.0.1.100
nas.vpn-gateway.secret=very-long-secure-shared-secret-with-high-entropy
nas.vpn-gateway.name=High-Security VPN Gateway
```

### Development/Testing Environment

```properties
# Development configuration (some features disabled for debugging)
server.port=1812
server.thread.pool.size=5

# Authentication configuration
auth.mode=combined
auth.otp.length=6

# Security features (basic protection for development)
security.packet.bounds.validation=true
security.attribute.bounds.validation=true
security.request.authenticator.validation=true
security.message.authenticator.validation=false  # Disabled for testing
security.replay.protection=false                 # Disabled for testing
security.strict.rfc.compliance=false

# NAS registry
nas.localhost.ip=127.0.0.1
nas.localhost.secret=test-secret
nas.localhost.name=Development Test Client
```

---

## Security Monitoring

### Security Event Logging

The RADIUS Gateway provides comprehensive security event logging for monitoring and compliance:

#### Log Levels and Categories

```
DEBUG - Normal security validation success
INFO  - Security feature status changes  
WARN  - Security violations and suspicious activity
ERROR - Security validation failures and attacks
```

#### Key Security Log Messages

```
# Successful validation
DEBUG RadiusSecurityValidatorImpl - Comprehensive security validation passed for packet from 192.168.1.100
DEBUG RadiusSecurityValidatorImpl - Request Authenticator validation passed for packet type 1
DEBUG RadiusSecurityValidatorImpl - Message-Authenticator validation passed for packet type 1

# Security violations
WARN  RadiusSecurityValidatorImpl - Replay attack detected from 192.168.1.100: packet ID 123 within 500ms window
WARN  RadiusSecurityValidatorImpl - Suspicious identifier reuse detected from 192.168.1.100: ID 42 used with different authenticator
ERROR RadiusSecurityValidatorImpl - Request Authenticator validation failed for packet from 192.168.1.100

# Feature status
INFO  RadiusSecurityValidatorImpl - Security feature MESSAGE_AUTHENTICATOR_VALIDATION enabled
INFO  RadiusSecurityValidatorImpl - Security validator shutdown completed
```

### Recommended Monitoring Alerts

#### Critical Alerts (Immediate Response Required)
- Request Authenticator validation failures
- High volume of replay attacks from single source
- Security validator initialization failures

#### Warning Alerts (Investigation Required)  
- Suspicious identifier reuse patterns
- Malformed packet attempts
- Message-Authenticator validation failures

#### Info Alerts (Trend Monitoring)
- Security feature configuration changes
- Normal authentication success/failure rates
- Replay protection cache cleanup events

---

## Security Best Practices

### 1. Shared Secret Management

**Requirements**:
- **Minimum length**: 32 characters
- **Character set**: Mixed case letters, numbers, special characters
- **Entropy**: High randomness (use cryptographic random generators)
- **Rotation**: Regular secret rotation (quarterly recommended)

**Example Strong Shared Secret**:
```
Kp9$mN8@vQ2#xR7!wE5&zL4^tY3*uI6%oP1+sF0-aG8~bH9=cJ2<dK7>eM4?fN5{gO6}
```

### 2. Network Security

**Firewall Configuration**:
```bash
# Allow RADIUS traffic only from known NAS devices
iptables -A INPUT -p udp --dport 1812 -s 192.168.1.100 -j ACCEPT
iptables -A INPUT -p udp --dport 1812 -j DROP
```

**Network Isolation**:
- Deploy RADIUS server in dedicated network segment
- Use VPN or private networks for NAS communication
- Implement network-level monitoring and intrusion detection

### 3. Authentication Backend Security

**Secure Integration**:
```java
// Example secure authentication backend
public class SecureAuthBackend implements AuthBackend {
    
    @Override
    public AuthResult authenticate(String username, String password, String otp) {
        // 1. Input sanitization
        username = sanitizeInput(username);
        
        // 2. Rate limiting
        if (isRateLimited(username)) {
            return AuthResult.failure("Rate limited", "Too many attempts");
        }
        
        // 3. Secure credential validation
        boolean passwordValid = securePasswordCheck(username, password);
        boolean otpValid = secureOtpValidation(username, otp);
        
        // 4. Audit logging
        auditLog.record(username, passwordValid && otpValid, getClientIP());
        
        if (passwordValid && otpValid) {
            return AuthResult.success("Authentication successful");
        } else {
            return AuthResult.failure("Invalid credentials", "Authentication failed");
        }
    }
}
```

### 4. Monitoring and Alerting

**Security Metrics to Track**:
- Authentication success/failure rates
- Replay attack frequency
- Security validation failure patterns
- Response time anomalies
- Resource consumption trends

**SIEM Integration**:
```json
{
  "timestamp": "2025-08-03T13:45:00Z",
  "event_type": "radius_security_violation",
  "source_ip": "192.168.1.100",
  "violation_type": "replay_attack",
  "packet_id": 123,
  "severity": "high"
}
```

### 5. Incident Response

**Security Incident Procedures**:

1. **Immediate Response**:
   - Block attacking IP addresses
   - Increase logging verbosity
   - Alert security team

2. **Investigation**:
   - Analyze attack patterns
   - Check for credential compromise
   - Review NAS device security

3. **Recovery**:
   - Rotate shared secrets if compromised
   - Update security configurations
   - Implement additional protections

---

## Troubleshooting Security Issues

### Common Security Validation Failures

#### 1. Request Authenticator Validation Failed

**Symptoms**:
```
ERROR RadiusSecurityValidatorImpl - Request Authenticator validation failed for packet from 192.168.1.100
```

**Possible Causes**:
- Incorrect shared secret configuration
- Clock synchronization issues
- Network packet corruption
- Man-in-the-middle attack

**Resolution Steps**:
1. Verify shared secret matches between RADIUS server and NAS
2. Check network connectivity and packet integrity
3. Synchronize clocks between systems
4. Investigate potential security threats

#### 2. Replay Attack Detection

**Symptoms**:
```
WARN RadiusSecurityValidatorImpl - Replay attack detected from 192.168.1.100: packet ID 123 within 500ms window
```

**Possible Causes**:
- Network packet duplication
- Malicious replay attack
- NAS device malfunction
- Network equipment issues

**Resolution Steps**:
1. Check network infrastructure for packet duplication
2. Investigate potential security threats
3. Review NAS device configuration
4. Consider adjusting replay window if legitimate

#### 3. Message-Authenticator Validation Failed

**Symptoms**:
```
ERROR RadiusSecurityValidatorImpl - Message-Authenticator validation failed for packet from 192.168.1.100
```

**Possible Causes**:
- HMAC-MD5 implementation differences
- Packet modification in transit
- Shared secret mismatch
- Software version incompatibility

**Resolution Steps**:
1. Verify HMAC-MD5 implementation compatibility
2. Check for packet modification or corruption
3. Validate shared secret configuration
4. Review software versions and compatibility

---

## Conclusion

The Java RADIUS Gateway provides enterprise-grade security validation with comprehensive RFC compliance. All critical security features are enabled by default, ensuring production-ready security out of the box.

**Security Recommendation**: Deploy with default security settings for production environments. Customize only based on specific security requirements and thorough testing.

**Compliance Status**: ✅ **PRODUCTION-READY** with full RFC compliance

*Last Updated: August 4, 2025*
*Security Review: Production Security Standards Met*