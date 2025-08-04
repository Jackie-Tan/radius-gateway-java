# Java RADIUS Gateway - High-Level Architecture

## 🔄 **Complete Authentication Flow**

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   VPN Client    │────▶│  VPN Gateway    │────▶│ RADIUS Gateway  │────▶│ Auth Backend    │
│   (Various)     │     │ (FortiGate/     │     │ (Java Server)   │     │ (Your System)   │
│                 │     │  Cisco/etc)     │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘     └─────────────────┘
        │                        │                        │                        │
        │                        │                        │                        │
        ▼                        ▼                        ▼                        ▼
    SSL VPN              RADIUS Protocol           Password + OTP            User Database
   Connection             UDP Port 1812             Validation              + OTP System
```

## 📋 **Detailed Step-by-Step Flow**

### **Phase 1: VPN Connection Request**
```
1. User opens VPN Client (FortiClient/Cisco AnyConnect/etc)
2. Enters credentials: username + password+OTP
   Example: alice / password123456
   (Where "password123" = password, "456" = OTP)
3. VPN Client connects to VPN Gateway (SSL VPN)
```

### **Phase 2: VPN Gateway → RADIUS Gateway**
```
4. VPN Gateway receives VPN login attempt
5. VPN Gateway creates RADIUS Access-Request packet:
   ┌─────────────────────────────────────┐
   │ RADIUS Access-Request Packet        │
   ├─────────────────────────────────────┤
   │ Code: Access-Request (1)            │
   │ Identifier: 42                      │
   │ Authenticator: [16-byte random]     │
   │ Attributes:                         │
   │   User-Name: "alice"                │
   │   User-Password: [encrypted]        │
   │   NAS-IP-Address: 192.168.1.100     │
   └─────────────────────────────────────┘
6. Sends packet to RADIUS Gateway (UDP:1812)
```

### **Phase 3: RADIUS Gateway Processing**
```
7. RadiusServer receives UDP packet
8. Validates VPN Gateway is registered NAS client
9. RadiusPacket.decode() parses the packet
10. Decrypts User-Password using shared secret
11. CombinedPasswordOtpHandler splits:
    - Password: "password123" 
    - OTP: "456"
12. Calls AuthBackend.authenticate(alice, password123, 456)
```

### **Phase 4: Authentication Backend**
```
13. Your AuthBackend implementation:
    - Validates "alice" + "password123" against user DB
    - Validates "456" against OTP system (TOTP/HOTP)
    - Returns AuthResult.success() or failure()
```

### **Phase 5: RADIUS Response**
```
14. RadiusResponseBuilder creates response:
    ┌─────────────────────────────────────┐
    │ RADIUS Access-Accept Packet         │
    ├─────────────────────────────────────┤
    │ Code: Access-Accept (2)             │
    │ Identifier: 42 (matches request)    │
    │ Response-Authenticator: [computed]  │
    │ Attributes:                         │
    │   Reply-Message: "Welcome alice!"   │
    └─────────────────────────────────────┘
15. Sends response back to VPN Gateway
```

### **Phase 6: VPN Access Granted**
```
16. VPN Gateway receives Access-Accept
17. Grants VPN access to user
18. User gets connected to internal network
19. Traffic flows through VPN tunnel
```

## 🏗 **Component Architecture**

### **RADIUS Gateway Internal Structure**
```
┌─────────────────────────────────────────────────────────────────┐
│                    RADIUS Gateway (Java)                        │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │RadiusServer │  │NasRegistry  │  │RadiusHandler│              │
│  │UDP :1812    │  │Shared Secrets│  │(Pluggable) │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
│         │                │                │                     │
│         ▼                ▼                ▼                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │RadiusPacket │  │RadiusCodec  │  │CombinedPass │              │
│  │Parse/Encode │  │Encrypt/     │  │wordOtpHandler│              │
│  │             │  │Decrypt PAP  │  │              │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
│                           │                │                    │
│                           ▼                ▼                    │
│                    ┌─────────────┐  ┌─────────────┐             │
│                    │ResponseBuilder│  │AuthBackend  │             │
│                    │Build Accept/ │  │(Your Impl)  │             │
│                    │Reject        │  │             │             │
│                    └─────────────┘  └─────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

## 🌐 **Network Topology Example**

### **Typical Enterprise Setup**
```
Internet
    │
    ▼
┌─────────────────┐
│  VPN Gateway    │ 192.168.1.1 (WAN: Public IP)
│ (FortiGate/     │ 192.168.1.100 (LAN)
│  Cisco/etc)     │
└─────────────────┘
    │ LAN
    ▼
┌─────────────────┐
│  Network Switch │
└─────────────────┘
    │
    ├── 192.168.1.10 ─── RADIUS Gateway Server
    ├── 192.168.1.20 ─── Domain Controller / LDAP
    ├── 192.168.1.30 ─── Database Server
    └── 192.168.1.x  ─── Internal Resources

Remote Users:
┌─────────────────┐     Internet     ┌─────────────────┐
│  VPN Client     │ ◄──────────────► │  VPN Gateway    │
│ (Various Apps)  │    SSL VPN       │  (Public IP)    │
└─────────────────┘                  └─────────────────┘
```

## 🔐 **Authentication Flow Details**

### **Password + OTP Handling**
```
User Input: "password123456"
           ┌─────────────┐
           │Split by OTP │
           │Length (6)   │
           └─────────────┘
                 │
         ┌───────┴───────┐
         ▼               ▼
   "password123"     "456"
   (Base Password)   (OTP)
         │               │
         ▼               ▼
   Check against     Validate
   User Database     OTP System
         │               │
         └───────┬───────┘
                 ▼
           Success/Failure
```

### **RADIUS Protocol Security**
```
┌─────────────────────────────────────────┐
│ ✅ IMPLEMENTED SECURITY FEATURES:       │
├─────────────────────────────────────────┤
│ ✅ Shared Secret Validation            │
│ ✅ PAP Password Encryption/Decryption  │
│ ✅ Request Authenticator Validation    │
│ ✅ Response Authenticator Validation   │
│ ✅ Message-Authenticator HMAC-MD5      │
│ ✅ AVP Bounds/Length Validation        │
│ ✅ Replay Attack Protection            │
│ ✅ Duplicate Packet Detection          │
│ ✅ NAS Client Registration             │
│ ✅ Comprehensive Security Validation   │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│ 🔒 PRODUCTION-READY SECURITY STATUS:   │
├─────────────────────────────────────────┤
│ ✅ RFC 2865 Compliance (Complete)      │
│ ✅ RFC 2869 Compliance (Complete)      │
│ ✅ RFC 5080 Compliance (Complete)      │
│ ✅ All Security Features Enabled       │
└─────────────────────────────────────────┘
```

## 🔄 **Integration Points**

### **1. AuthBackend Interface** 
Replace with your authentication system:
```java
public interface AuthBackend {
    AuthResult authenticate(String username, String password, String otp);
}

// Examples:
// - LDAP/Active Directory integration
// - Database authentication
// - REST API calls to external systems
// - Multi-factor authentication providers
```

### **2. OTP Systems Integration**
```
Supported OTP Types:
├── TOTP (Time-based) - Google Authenticator, Authy
├── HOTP (Counter-based) - Hardware tokens
├── SMS-based OTP
└── Custom OTP validation systems
```

### **3. User Database Integration**
```
Compatible Systems:
├── Active Directory / LDAP
├── MySQL / PostgreSQL databases  
├── REST APIs
├── Identity Providers (Okta, Auth0)
└── Custom user management systems
```

## 📊 **Monitoring & Logging Points**

### **Key Metrics to Track**
```
1. Authentication Events:
   ├── Success/Failure rates per user
   ├── Failed login attempts
   └── OTP validation failures

2. Network Events:
   ├── RADIUS request/response times
   ├── VPN Gateway connection stats
   └── NAS client activity

3. System Health:
   ├── Server uptime
   ├── Memory/CPU usage
   └── Error rates
```

This architecture provides a clear foundation for enterprise VPN authentication using the RADIUS protocol with multi-vendor VPN Gateway integration!