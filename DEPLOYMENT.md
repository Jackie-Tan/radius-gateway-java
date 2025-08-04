# VPN Gateway RADIUS Authentication Deployment Guide

## 🚀 Quick Deployment

### 1. Build the Production JAR

```bash
mvn clean package
```

This creates `radius-gateway-1.0.0-SNAPSHOT.jar` - a standalone executable with all dependencies.

### 2. Deploy to Your Server

```bash
# Copy files to your server
scp target/radius-gateway-1.0.0-SNAPSHOT.jar user@your-server:/opt/radius/
scp deploy-config.properties user@your-server:/opt/radius/

# SSH to your server
ssh user@your-server
cd /opt/radius
```

### 3. Configure for Your Environment

Edit `deploy-config.properties`:

```properties
# Replace with your VPN Gateway's actual IP
nas.vpngateway.ip=192.168.1.100
nas.vpngateway.secret=YourStrongSecret123!

# Authentication Mode Configuration
# Choose one of: combined, separate, two-stage
auth.otp.mode=two-stage
auth.challenge.timeout=300
auth.challenge.message=Enter your OTP code

# Add your users (temporary - replace with real auth backend)
demo.user.alice=password123
demo.user.bob=secretpass
```

### 4. Run the Server

```bash
# Standard run
java -jar radius-gateway-1.0.0-SNAPSHOT.jar deploy-config.properties

# Production run with logging
nohup java -jar radius-gateway-1.0.0-SNAPSHOT.jar deploy-config.properties > radius.log 2>&1 &
```

## 🔐 Authentication Mode Configuration

The RADIUS Gateway supports four different authentication modes to match your VPN client capabilities:

### Mode 1: Combined Password+OTP (Traditional)
```properties
auth.otp.mode=combined
auth.otp.length=6
```
- User enters: `password123456789` (password + OTP combined)
- Gateway splits: password=`password123`, OTP=`456789`
- **Use when**: VPN client has single password field

### Mode 2: Separate Password and OTP (Modern)
```properties
auth.otp.mode=separate
auth.otp.attribute.type=26
```
- User enters password and OTP in different fields
- Gateway receives them in separate RADIUS attributes
- **Use when**: VPN client supports dedicated OTP field

### Mode 3: Two-Stage Authentication (VPN-Style)
```properties
auth.otp.mode=two-stage
auth.challenge.timeout=300
auth.challenge.message=Enter your OTP code
```
- **Stage 1**: User enters username + password → Server validates → Sends challenge
- **Stage 2**: VPN client prompts for OTP → User enters OTP → Server validates
- **Use when**: VPN client supports RADIUS challenge/response (most modern VPNs)

### Mode 4: OTP-Only Authentication (Token-Based)
```properties
auth.otp.mode=otp-only
auth.otp.length=6
```
- User enters: `456789` (just the OTP) in password field
- No traditional password required
- **Use when**: Hardware tokens, SMS OTP, TOTP apps, passwordless authentication

**Recommended**: Use `otp-only` mode for token-based systems and `two-stage` mode for password+OTP systems.

## 🔧 VPN Gateway Configuration

### Step 1: Configure RADIUS Server on VPN Gateway

1. **Login to VPN Gateway Web Interface**
2. **Navigate to User & Authentication > RADIUS Servers** (location varies by vendor)
3. **Click "Create New" or "Add RADIUS Server"**

**Configuration:**
```
Name: RADIUS-Gateway
Primary Server IP: [Your RADIUS server IP]
Primary Server Port: 1812
Primary Server Secret: YourStrongSecret123!
Secondary Server: [Optional - leave blank]
Authentication Method: PAP
```

### Step 2: Create User Group

1. **Navigate to User & Authentication > User Groups**
2. **Click "Create New"**

**Configuration:**
```
Name: VPN-RADIUS-Users
Type: Remote User
Remote Groups: [Leave empty for all users]
```

### Step 3: Configure SSL VPN with RADIUS

1. **Navigate to VPN > SSL VPN Settings** (path varies by vendor)
2. **Configure Authentication:**

```
Source IP Pools: [VPN tunnel address pool]
Authentication/Portal Mapping:
  - Groups: VPN-RADIUS-Users
  - Portal: [appropriate access level]
```

### Step 4: Create VPN Access Policy

1. **Navigate to Firewall/Security Policies**
2. **Create VPN Access Policy:**

```
Incoming Interface: [VPN interface]
Outgoing Interface: [internal network]
Source: [VPN user pool]
Destination: [allowed resources]
Service: [required services]
Action: ACCEPT
```

## 🧪 Testing the Integration

### Test 1: Direct RADIUS Test

**For Combined Mode:**
```bash
java -cp target/test-classes:target/classes com.radiusgateway.RadiusTestDriver \
  --host [RADIUS-SERVER-IP] \
  --username alice \
  --password password123456789 \
  --secret YourStrongSecret123!
```

**For Separate Mode:**
```bash
java -cp target/test-classes:target/classes com.radiusgateway.RadiusTestDriver \
  --host [RADIUS-SERVER-IP] \
  --username alice \
  --password password123 \
  --otp 456789 \
  --secret YourStrongSecret123!
```

**For Two-Stage Mode:**
```bash
java -cp target/test-classes:target/classes com.radiusgateway.TwoStageTestDriver \
  --host [RADIUS-SERVER-IP] \
  --username alice \
  --password password123 \
  --secret YourStrongSecret123!
```

Expected two-stage output:
```
Stage 1: Sending username and password...
Stage 1 Response:
  Code: Access-Challenge
  Message: Enter your OTP code

Stage 2: Using default OTP: 123456
Stage 2: Sending OTP with challenge state...
Stage 2 Response:
  Code: Access-Accept
  Message: Welcome alice!
  Result: SUCCESS
```

**For OTP-Only Mode:**
```bash
java -cp target/test-classes:target/classes com.radiusgateway.RadiusTestDriver \
  --host [RADIUS-SERVER-IP] \
  --username alice \
  --password 123456 \
  --secret YourStrongSecret123!
```

Expected OTP-only output:
```
Response received:
  Code: Access-Accept
  Reply-Message: Welcome alice!
  Success: true
```

### Test 2: VPN Gateway Test

1. **Install VPN Client** on a test machine (varies by vendor)
2. **Configure SSL VPN connection:**
   ```
   Server: [VPN Gateway IP]:443
   Username: alice
   ```

3. **Authentication Flow (depends on mode):**

   **Combined Mode:**
   - Password field: `password123456789` (password + OTP combined)

   **Separate Mode:**
   - Password field: `password123`
   - OTP field: `456789` (if VPN client supports separate OTP field)

   **Two-Stage Mode:**
   - Enter username: `alice`
   - Enter password: `password123`
   - VPN client will prompt: "Enter your OTP code"
   - Enter OTP: `123456`

   **OTP-Only Mode (Recommended for tokens):**
   - Enter username: `alice`
   - Password field: `123456` (just the OTP/token value)
   - No traditional password required

4. **Connect and verify** in VPN Gateway logs (commands vary by vendor)

### Test 3: Monitor RADIUS Server

Watch the server logs:
```bash
tail -f radius.log
```

Expected log entries:
```
INFO  - Authentication successful for user 'alice' from [VPN-Gateway-IP]
INFO  - Sent Access-Accept response to [VPN-Gateway-IP]
```

## 🔍 Troubleshooting

### Common Issues

**1. Connection Refused**
- Check firewall: `sudo ufw allow 1812/udp`
- Verify server is listening: `netstat -ulnp | grep 1812`

**2. Authentication Failures**
- Verify shared secret matches between VPN Gateway and config
- Check username/password in configuration
- Ensure OTP is exactly 6 digits

**3. VPN Gateway Cannot Reach RADIUS**
- Test connectivity: `ping [RADIUS-SERVER-IP]` from VPN Gateway
- Check VPN Gateway routing to RADIUS server
- Verify network policies allow RADIUS traffic

**4. Wrong OTP Length**
- Default is 6 digits - adjust `auth.otp.length` in config if needed
- Restart server after config changes

### Debug Commands

**Check server status:**
```bash
ps aux | grep radius-gateway
netstat -ulnp | grep 1812
```

**Test network connectivity:**
```bash
# From VPN Gateway to RADIUS server (commands vary by vendor)
ping [RADIUS-SERVER-IP]

# Test UDP port
nmap -sU -p 1812 [RADIUS-SERVER-IP]
```

**VPN Gateway debug commands:**
```bash
# Debug commands vary by vendor
# Common examples:

# Generic RADIUS debug
show radius statistics
debug radius

# View authentication logs
show log auth
show log radius
```

## 🔐 Production Security Notes

✅ **PRODUCTION-READY:** All critical security features implemented and enabled:

1. **Request Authenticator Validation** - ✅ Fully implemented (RFC 2865 §3)
2. **AVP Bounds Validation** - ✅ Comprehensive validation (RFC 2865 §3)
3. **Message-Authenticator Support** - ✅ HMAC-MD5 validation (RFC 2869 §5.14)
4. **Replay Attack Protection** - ✅ Enhanced protection (RFC 5080 §2.2)
5. **Replace demo authentication** with your actual backend
6. **Use strong shared secrets** (32+ characters)
7. **Enable firewall rules** to restrict RADIUS access
8. **Consider network-level security** for additional protection

## 📊 Monitoring

**Key metrics to monitor:**
- Authentication success/failure rates
- Connection counts per NAS client
- Response times
- Error logs

**Log locations:**
- Application logs: `radius.log`
- VPN Gateway logs: Check vendor documentation for log locations

This setup provides a solid foundation for VPN Gateway RADIUS authentication with your custom backend!