# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **Java RADIUS Gateway Module** - a lightweight, embeddable RADIUS protocol handler designed for integration into authentication servers. The project enables Java-based auth servers to handle VPN clients (Cisco, OpenVPN, Fortinet, etc.) that send `Access-Request` packets over UDP/1812, supporting password + OTP authentication flows.

## Architecture

The project follows a modular design with these core components:

### Core RADIUS Protocol
- **RadiusServer.java** - Multi-threaded UDP listener on port 1812, main entry point
- **RadiusPacket.java** - RADIUS packet parsing and encoding with full AVP support
- **RadiusCodec.java** - Protocol-level encoding/decoding, password encryption/decryption
- **RadiusResponseBuilder.java** - Builds Access-Accept/Access-Reject/Access-Challenge responses
- **RadiusUtils.java** - Common RADIUS protocol utilities

### Security & Validation
- **RadiusSecurityValidator.java** - Security validation interface
- **RadiusSecurityValidatorImpl.java** - RFC-compliant security validation implementation
- **RadiusSecurityException.java** - Security violation exceptions
- **RadiusValidationException.java** - Packet validation exceptions

### Authentication Handlers (Pluggable)
- **RadiusHandler.java** - Base pluggable interface for authentication logic
- **CombinedPasswordOtpHandler.java** - Fixed-length password+OTP splitting logic
- **SeparatePasswordOtpHandler.java** - Separate password and OTP attribute handling
- **TwoStagePasswordOtpHandler.java** - Two-stage challenge/response authentication
- **OtpOnlyHandler.java** - OTP-only authentication (no password required)
- **AuthBackend.java** - Backend authentication interface

### Configuration & Management
- **NasRegistry.java** - NAS (Network Access Server) registry with shared secret validation
- **ConfigurationManager.java** - Configuration loading and management
- **HandlerFactory.java** - Factory for creating authentication handlers
- **HandlerUtils.java** - Common utilities for authentication handlers
- **RadiusServerLifecycle.java** - Server lifecycle management and command-line interface

### Session Management
- **ChallengeState.java** - Session state management for two-stage authentication

The system uses a pluggable handler pattern where authentication logic is completely decoupled from RADIUS protocol handling, enabling support for four distinct authentication modes with comprehensive RFC-compliant security validation.

## Authentication Modes

The RADIUS Gateway supports **four different authentication modes** to accommodate various VPN client configurations:

### 1. **Combined Password+OTP Mode** (`CombinedPasswordOtpHandler`)
- **Input**: User enters `password123456` (password + 6-digit OTP)
- **Processing**: Gateway splits into password and OTP components using fixed-length OTP
- **Use Case**: Simple VPN clients that send combined credentials in User-Password attribute
- **Configuration**: Configurable OTP length (default: 6 digits)

### 2. **Separate Password/OTP Mode** (`SeparatePasswordOtpHandler`)
- **Input**: User enters password and OTP in separate fields
- **Processing**: Gateway processes password from User-Password and OTP from Vendor-Specific attributes
- **Use Case**: VPN clients with dedicated OTP fields or custom attribute support
- **Configuration**: Supports vendor-specific OTP attribute formats

### 3. **Two-Stage Authentication Mode** (`TwoStagePasswordOtpHandler`)
- **Stage 1**: User enters username/password → Gateway validates and sends Access-Challenge
- **Stage 2**: VPN client prompts for OTP → Gateway validates OTP and responds
- **Processing**: Uses State attribute for session management between stages
- **Use Case**: Advanced VPN clients supporting RADIUS challenge/response flow
- **Configuration**: Configurable challenge timeouts and session management

### 4. **OTP-Only Mode** (`OtpOnlyHandler`)
- **Input**: User enters only OTP code (no password required)
- **Processing**: Gateway validates OTP directly from User-Password attribute
- **Use Case**: Hardware tokens, SMS OTP, or passwordless authentication scenarios
- **Configuration**: Direct OTP validation without password splitting

## Security Framework

The comprehensive security validation framework (`RadiusSecurityValidator`) implements:

- **Request Authenticator Validation**: Prevents packet forgery (RFC 2865 §3)
- **Replay Attack Protection**: Timestamp-based duplicate detection (RFC 5080 §2.2)
- **Message-Authenticator Validation**: HMAC-MD5 integrity checking (RFC 2869 §5.14)
- **Packet Bounds Validation**: Prevents buffer overflow and parsing attacks
- **Attribute Validation**: Comprehensive AVP length and format checking
- **Configurable Security Features**: Individual security features can be enabled/disabled
- **Production-Ready Defaults**: All security features enabled by default

## Current Implementation Status

**✅ PRODUCTION-READY FEATURES (Implemented):**
- UDP listener on port 1812 with multi-threaded processing
- Complete Access-Request packet parsing and validation
- User-Name, User-Password, State, Reply-Message AVP support
- PAP password encryption/decryption (RFC 2865 §5.2)
- Four authentication modes: Combined, Separate, Two-stage, OTP-only
- NAS registry with shared secret validation and access tracking
- Response Authenticator computation and validation
- Access-Challenge support for two-stage authentication
- Comprehensive security validation framework

**✅ RFC SECURITY COMPLIANCE (Implemented):**
- Request Authenticator validation (RFC 2865 §3)
- Duplicate Identifier protection (RFC 5080 §2.2)
- Replay attack mitigation with timestamp tracking (RFC 5080 §2.2)
- AVP bounds/length validation (RFC 2865 §3)
- Message-Authenticator (AVP 80) HMAC-MD5 validation (RFC 2869 §5.14)
- Comprehensive packet security validation
- Configurable security feature toggles

## Development Commands

**Note:** Ensure Maven and Java 11+ are installed on your system.

```bash
# Build project
mvn clean compile

# Run tests
mvn test

# Run specific test
mvn test -Dtest=RadiusPacketTest

# Package JAR
mvn package

# Run the server (demo mode)
java -cp target/classes com.radiusgateway.RadiusServer

# Run test driver to simulate client requests
java -cp target/test-classes:target/classes com.radiusgateway.RadiusTestDriver --help
```

## Security Considerations

This is a **production-ready defensive security project** implementing full RADIUS protocol compliance for authentication. Key security aspects:

- **Full RFC Compliance**: All critical security features implemented (RFC 2865, 2869, 5080)
- **Request Authenticator Validation**: Prevents packet forgery and ensures message integrity
- **Replay Protection**: Timestamp-based protection against duplicate and replay attacks
- **Comprehensive Validation**: AVP bounds checking prevents buffer overflow and parsing attacks
- **Shared Secret Management**: Secure NAS registry with access tracking and validation
- **Production Hardened**: All security features enabled by default with proper error handling
- **Configurable Security**: Security features can be individually configured for gradual deployment

## Development Status & Priorities

**✅ Phase 1: Core Implementation (COMPLETED)**
- Basic packet decoder/encoder with full AVP support
- PAP password encryption/decryption (RFC 2865)
- NAS registry with shared secret validation and access tracking
- Pluggable RadiusHandler interface with 4 authentication modes
- Access-Request/Accept/Reject/Challenge handling
- Production-ready server lifecycle management

**✅ Phase 2: RFC Security Hardening (COMPLETED)**
- Request Authenticator validation (RFC 2865 §3)
- AVP bounds + length validation (RFC 2865 §3)
- Identifier replay protection with timestamps (RFC 5080 §2.2)
- Message-Authenticator HMAC-MD5 validation (RFC 2869 §5.14)
- Comprehensive security validation framework
- All security features enabled by default

**🚀 Phase 3: Production Readiness & Documentation (IN PROGRESS)**
- RFC compliance test suites
- Security validation test scenarios
- Complete configuration documentation
- Production deployment checklist
- Performance and scaling guidelines
- Integration tests for all authentication modes
- Monitoring and observability features

## Project Structure

Actual source structure (production-ready implementation):
```
src/main/java/com/radiusgateway/
├── Core Protocol
│   ├── RadiusServer.java
│   ├── RadiusPacket.java
│   ├── RadiusCodec.java
│   ├── RadiusResponseBuilder.java
│   ├── RadiusUtils.java
│   └── RadiusServerLifecycle.java
├── Security & Validation
│   ├── RadiusSecurityValidator.java
│   ├── RadiusSecurityValidatorImpl.java
│   ├── RadiusSecurityException.java
│   └── RadiusValidationException.java
├── Authentication Handlers
│   ├── RadiusHandler.java
│   ├── AuthBackend.java
│   ├── CombinedPasswordOtpHandler.java
│   ├── SeparatePasswordOtpHandler.java
│   ├── TwoStagePasswordOtpHandler.java
│   └── OtpOnlyHandler.java
├── Configuration & Management
│   ├── NasRegistry.java
│   ├── ConfigurationManager.java
│   ├── HandlerFactory.java
│   └── HandlerUtils.java
└── Session Management
    └── ChallengeState.java
```