# RADIUS Gateway Configuration Guide

This document provides comprehensive configuration instructions for all authentication modes supported by the Java RADIUS Gateway.

## 📋 Configuration File: `deploy-config.properties`

### Basic Server Configuration
```properties
# Server Settings
radius.port=1812
radius.thread.pool.size=20

# NAS Client Configuration
nas.vpngateway.ip=192.168.203.1
nas.vpngateway.secret=YourStrongSecret123!
nas.vpngateway.description=VPN Gateway

# Demo Users (replace with your actual authentication backend)
demo.user.alice=password123
demo.user.bob=secretpass  
demo.user.admin=adminpass
```

## 🔐 Authentication Modes

### Mode 1: Combined Password+OTP (Traditional)

**Configuration:**
```properties
auth.otp.mode=combined
auth.otp.length=6
```

**User Experience:**
- User enters: `password123456789` in a single password field
- Gateway splits it: password=`password123`, OTP=`456789`

**When to Use:**
- Legacy VPN clients with single password field
- Simple setup requirements
- Backwards compatibility needed

**Testing:**
```bash
java -cp target/test-classes:target/classes com.radiusgateway.RadiusTestDriver \
  --username alice --password password123456789 --secret YourStrongSecret123!
```

---

### Mode 2: Separate Password and OTP (Modern)

**Configuration:**
```properties
auth.otp.mode=separate
auth.otp.attribute.type=26
```

**User Experience:**
- User enters password in password field: `password123`  
- User enters OTP in separate OTP field: `456789`
- Gateway receives them in different RADIUS attributes

**When to Use:**
- Modern VPN clients with dedicated OTP field
- Better user experience (clear separation)
- Enhanced security (separate validation)

**Testing:**
```bash
java -cp target/test-classes:target/classes com.radiusgateway.RadiusTestDriver \
  --username alice --password password123 --otp 456789 --secret YourStrongSecret123!
```

---

### Mode 3: Two-Stage Authentication (VPN-Style)

**Configuration:**
```properties
auth.otp.mode=two-stage
auth.challenge.timeout=300
auth.challenge.message=Enter your OTP code
```

**User Experience:**
1. **Stage 1**: User enters username and password
2. **Stage 2**: VPN client prompts: "Enter your OTP code"
3. User enters OTP in the prompted field

**When to Use:**
- Modern VPN clients supporting RADIUS challenge/response
- Best security (password verified before OTP prompt)
- Matches enterprise VPN user expectations

**Testing:**
```bash
java -cp target/test-classes:target/classes com.radiusgateway.TwoStageTestDriver \
  --username alice --password password123 --secret YourStrongSecret123!
```

---

### Mode 4: OTP-Only Authentication **[RECOMMENDED]**

**Configuration:**
```properties
auth.otp.mode=otp-only
auth.otp.length=6
```

**User Experience:**
- User enters only: `456789` (just the OTP) in the password field
- No traditional password required
- Direct authentication via OTP/token

**When to Use:**
- Hardware token authentication (RSA SecurID, YubiKey)
- SMS/Email OTP systems
- Time-based OTP (TOTP) applications
- Passwordless authentication flows
- **Recommended for token-based systems**

**Testing:**
```bash
java -cp target/test-classes:target/classes com.radiusgateway.RadiusTestDriver \
  --username alice --password 123456 --secret YourStrongSecret123!
```

## 🎛️ Advanced Configuration Options

### Two-Stage Authentication Settings
```properties
# Challenge session timeout (seconds)
auth.challenge.timeout=300

# Message displayed to user for OTP prompt
auth.challenge.message=Enter your OTP code

# Alternative challenge messages
auth.challenge.message=Please enter your 6-digit authentication code
auth.challenge.message=Enter token from your authenticator app
```

### Separate Mode Attribute Configuration
```properties
# RADIUS attribute type for OTP (default: Vendor-Specific)
auth.otp.attribute.type=26

# Alternative attribute types
auth.otp.attribute.type=24  # State attribute
auth.otp.attribute.type=18  # Reply-Message
```

### Combined Mode and OTP-Only Length Settings
```properties
# OTP length for splitting combined password or validating OTP-only
auth.otp.length=6   # 6-digit OTP (default)
auth.otp.length=4   # 4-digit PIN
auth.otp.length=8   # 8-digit token
```

### OTP-Only Mode Settings
```properties
# Accept OTPs within reasonable range of expected length
# Actual validation accepts ±2 digits from configured length
auth.otp.length=6   # Accepts 4-8 digit OTPs
auth.otp.length=4   # Accepts 2-6 digit PINs
```

## 🚀 Deployment Commands

### Start Server
```bash
# Production mode with configuration
java -jar radius-gateway-1.0.0-SNAPSHOT.jar deploy-config.properties

# Background with logging
nohup java -jar radius-gateway-1.0.0-SNAPSHOT.jar deploy-config.properties > radius.log 2>&1 &

# Demo mode (testing only)
java -jar radius-gateway-1.0.0-SNAPSHOT.jar
```

### Monitor Server
```bash
# Watch logs
tail -f radius.log

# Check if running
ps aux | grep radius-gateway

# Check port binding
netstat -ulnp | grep 1812
```

## 🧪 Testing All Modes

### Quick Test Script
```bash
#!/bin/bash
HOST="localhost"
SECRET="YourStrongSecret123!"

echo "Testing Combined Mode..."
java -cp target/test-classes:target/classes com.radiusgateway.RadiusTestDriver \
  --username alice --password password123456789 --secret $SECRET

echo "Testing Separate Mode..."  
java -cp target/test-classes:target/classes com.radiusgateway.RadiusTestDriver \
  --username alice --password password123 --otp 456789 --secret $SECRET

echo "Testing Two-Stage Mode..."
java -cp target/test-classes:target/classes com.radiusgateway.TwoStageTestDriver \
  --username alice --password password123 --secret $SECRET

echo "Testing OTP-Only Mode..."
java -cp target/test-classes:target/classes com.radiusgateway.RadiusTestDriver \
  --username alice --password 123456 --secret $SECRET
```

## 🔧 VPN Client Configuration

### For Two-Stage Mode
1. Configure RADIUS server: `IP:1812`
2. Set shared secret: `YourStrongSecret123!`
3. Enable challenge/response support
4. Authentication method: PAP
5. **Important**: Ensure VPN client supports RADIUS challenges

### For OTP-Only Mode (Recommended)
1. Configure RADIUS server: `IP:1812`
2. Set shared secret: `YourStrongSecret123!`
3. Authentication method: PAP
4. **User instruction**: Enter only the OTP/token in password field
5. **Important**: No traditional password required

### VPN Client Compatibility
- ✅ **Modern VPN Clients**: FortiClient, Cisco AnyConnect, Palo Alto GlobalProtect
- ✅ **Network Equipment**: Most enterprise firewalls and VPN gateways
- ⚠️ **Legacy Clients**: May only support combined mode

## 📊 Monitoring & Logs

### Log Messages by Mode

**Combined Mode:**
```
INFO  - Creating combined password+OTP handler with OTP length: 6
DEBUG - Authenticating user 'alice' with combined credentials
```

**Separate Mode:**
```  
INFO  - Creating separate OTP handler with attribute type: 26
DEBUG - Authenticating user 'alice' with separate password and OTP
```

**Two-Stage Mode:**
```
INFO  - Creating two-stage OTP handler with timeout: 300s
DEBUG - Stage 1: Authenticating password for user 'alice'
INFO  - Stage 1: Password authentication successful. Sending OTP challenge.
DEBUG - Stage 2: Validating OTP for user 'alice'  
INFO  - Stage 2: OTP authentication successful. Access granted.
```

**OTP-Only Mode:**
```
INFO  - Creating OTP-only handler with expected OTP length: 6
DEBUG - Authenticating user 'alice' with OTP-only
INFO  - OTP authentication successful for user 'alice'
```

## 🔐 Security Considerations

### Production Checklist
- [ ] Use strong shared secrets (32+ characters)
- [ ] Configure firewall rules (allow only NAS clients)
- [ ] Replace demo authentication with real backend
- [ ] Set appropriate challenge timeout (300s recommended)
- [ ] Enable RADIUS server logging
- [ ] Monitor authentication success/failure rates
- [ ] Implement OTP system integration

### Security by Mode
- **Combined**: Moderate (single transmission)
- **Separate**: Good (separate validation)  
- **Two-Stage**: Excellent (password verified before OTP exposure)
- **OTP-Only**: Best (no password storage or transmission required)

This configuration guide covers all aspects of deploying the RADIUS Gateway in any authentication mode to match your VPN infrastructure requirements.