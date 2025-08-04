package com.radiusgateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Implementation of RADIUS security validation.
 * Provides comprehensive security checks for RADIUS packets according to RFC standards.
 */
public class RadiusSecurityValidatorImpl implements RadiusSecurityValidator {
    
    private static final Logger logger = LoggerFactory.getLogger(RadiusSecurityValidatorImpl.class);
    
    // RFC 2865 constants
    private static final int MIN_PACKET_LENGTH = 20;
    private static final int MAX_PACKET_LENGTH = 4096;
    private static final int MIN_ATTRIBUTE_LENGTH = 2;
    private static final int MAX_ATTRIBUTE_LENGTH = 255;
    private static final int AUTHENTICATOR_LENGTH = 16;
    
    // Replay protection settings
    private static final long DEFAULT_REPLAY_WINDOW_MS = 300000; // 5 minutes
    private static final int MAX_RECENT_PACKETS = 1000;
    
    // Security feature configuration
    private final Map<SecurityFeature, Boolean> securityFeatures;
    
    // Replay protection state
    private final ConcurrentHashMap<String, Long> recentPackets;
    private final ScheduledExecutorService cleanupExecutor;
    private final long replayWindowMs;
    
    /**
     * Creates a new security validator with default settings.
     */
    public RadiusSecurityValidatorImpl() {
        this(DEFAULT_REPLAY_WINDOW_MS);
    }
    
    /**
     * Creates a new security validator with specified replay window.
     * 
     * @param replayWindowMs replay protection window in milliseconds
     */
    public RadiusSecurityValidatorImpl(long replayWindowMs) {
        this.replayWindowMs = replayWindowMs;
        this.securityFeatures = new EnumMap<>(SecurityFeature.class);
        this.recentPackets = new ConcurrentHashMap<>();
        
        // Initialize default security feature settings
        initializeDefaultSecurityFeatures();
        
        // Setup cleanup executor for replay protection
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "SecurityValidator-Cleanup");
            t.setDaemon(true);
            return t;
        });
        
        // Schedule cleanup every minute
        cleanupExecutor.scheduleAtFixedRate(this::cleanupExpiredPackets, 
                                          60, 60, TimeUnit.SECONDS);
    }
    
    @Override
    public void validateRequestAuthenticator(RadiusPacket packet, String sharedSecret) 
            throws RadiusSecurityException {
        if (!isFeatureEnabled(SecurityFeature.REQUEST_AUTHENTICATOR_VALIDATION)) {
            logger.debug("Request Authenticator validation is disabled");
            return;
        }
        
        try {
            // Use RadiusCodec for proper RFC 2865 validation
            boolean isValid = RadiusCodec.validateRequestAuthenticator(packet, sharedSecret);
            
            if (!isValid) {
                throw RadiusSecurityException.invalidRequestAuthenticator(null);
            }
            
            logger.debug("Request Authenticator validation passed for packet type {}", packet.getCode());
            
        } catch (RadiusPacket.RadiusException e) {
            throw RadiusSecurityException.cryptographicError("Request Authenticator validation", e);
        } catch (Exception e) {
            if (e instanceof RadiusSecurityException) {
                throw e;
            }
            throw RadiusSecurityException.cryptographicError("Request Authenticator validation", e);
        }
    }
    
    @Override
    public void validateMessageAuthenticator(RadiusPacket packet, String sharedSecret) 
            throws RadiusSecurityException {
        if (!isFeatureEnabled(SecurityFeature.MESSAGE_AUTHENTICATOR_VALIDATION)) {
            logger.debug("Message-Authenticator validation is disabled");
            return;
        }
        
        RadiusPacket.RadiusAttribute msgAuth = packet.getAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR);
        if (msgAuth == null) {
            // No Message-Authenticator present - this is allowed
            logger.debug("No Message-Authenticator attribute present");
            return;
        }
        
        try {
            // Validate Message-Authenticator according to RFC 2869 §5.14
            byte[] receivedAuthenticator = msgAuth.getValue();
            
            // Message-Authenticator must be exactly 16 bytes
            if (receivedAuthenticator.length != 16) {
                throw RadiusSecurityException.invalidMessageAuthenticator(
                    "Invalid length: " + receivedAuthenticator.length + " bytes");
            }
            
            // Compute expected Message-Authenticator
            byte[] expectedAuthenticator = computeMessageAuthenticator(packet, sharedSecret);
            
            // Compare using constant-time comparison to prevent timing attacks
            if (!constantTimeEquals(receivedAuthenticator, expectedAuthenticator)) {
                throw RadiusSecurityException.invalidMessageAuthenticator(
                    "HMAC-MD5 verification failed");
            }
            
            logger.debug("Message-Authenticator validation passed for packet type {}", packet.getCode());
            
        } catch (Exception e) {
            if (e instanceof RadiusSecurityException) {
                throw (RadiusSecurityException) e;
            }
            throw RadiusSecurityException.cryptographicError("Message-Authenticator validation", e);
        }
    }
    
    @Override
    public void validatePacketBounds(RadiusPacket packet) throws RadiusValidationException {
        if (!isFeatureEnabled(SecurityFeature.PACKET_BOUNDS_VALIDATION)) {
            logger.debug("Packet bounds validation is disabled");
            return;
        }
        
        // Validate packet structure through encoding/decoding
        try {
            byte[] encoded = packet.encode();
            
            // Check overall packet length
            if (encoded.length < MIN_PACKET_LENGTH) {
                throw RadiusValidationException.packetLengthError(
                    encoded.length, MIN_PACKET_LENGTH, MAX_PACKET_LENGTH);
            }
            
            if (encoded.length > MAX_PACKET_LENGTH) {
                throw RadiusValidationException.packetLengthError(
                    encoded.length, MIN_PACKET_LENGTH, MAX_PACKET_LENGTH);
            }
            
            // Validate header structure
            validatePacketHeader(encoded);
            
            logger.debug("Packet bounds validation passed for {} byte packet", encoded.length);
            
        } catch (Exception e) {
            if (e instanceof RadiusValidationException) {
                throw e;
            }
            throw new RadiusValidationException("Packet bounds validation failed", e);
        }
    }
    
    @Override
    public void validateAttributeBounds(RadiusPacket packet) throws RadiusValidationException {
        if (!isFeatureEnabled(SecurityFeature.ATTRIBUTE_BOUNDS_VALIDATION)) {
            logger.debug("Attribute bounds validation is disabled");
            return;
        }
        
        int totalAttributeLength = 0;
        Map<Integer, Integer> attributeCounts = new HashMap<>();
        
        for (RadiusPacket.RadiusAttribute attr : packet.getAttributes()) {
            // Validate individual attribute length
            int attrLength = attr.getLength();
            if (attrLength < MIN_ATTRIBUTE_LENGTH) {
                throw RadiusValidationException.attributeLengthError(
                    attr.getType(), attrLength, MIN_ATTRIBUTE_LENGTH);
            }
            
            if (attrLength > MAX_ATTRIBUTE_LENGTH) {
                throw RadiusValidationException.attributeLengthError(
                    attr.getType(), attrLength, MAX_ATTRIBUTE_LENGTH);
            }
            
            // Track total attribute length for packet size validation
            totalAttributeLength += attrLength;
            
            // Track attribute occurrence counts for RFC compliance
            attributeCounts.merge(attr.getType(), 1, Integer::sum);
            
            // Validate attribute value length is within bounds
            byte[] value = attr.getValue();
            if (value.length != attrLength - 2) {
                throw RadiusValidationException.invalidFormat(
                    "Attribute-" + attr.getType(), 
                    "length=" + value.length,
                    "Value length must match attribute length field minus 2"
                );
            }
            
            // Validate specific attribute types and RFC constraints
            validateSpecificAttributeType(attr);
            validateAttributeOccurrenceRules(attr.getType(), attributeCounts.get(attr.getType()));
        }
        
        // Validate total packet size constraints (RFC 2865 §3)
        int expectedPacketSize = 20 + totalAttributeLength; // Header + attributes
        if (expectedPacketSize > MAX_PACKET_LENGTH) {
            throw RadiusValidationException.packetLengthError(
                expectedPacketSize, MIN_PACKET_LENGTH, MAX_PACKET_LENGTH);
        }
        
        // Validate required attributes are present for Access-Request packets
        if (packet.getCode() == RadiusPacket.ACCESS_REQUEST) {
            validateRequiredAttributes(packet, attributeCounts);
        }
        
        logger.debug("Enhanced attribute bounds validation passed for {} attributes, total size {} bytes", 
                    packet.getAttributes().size(), totalAttributeLength);
    }
    
    @Override
    public void checkReplayProtection(RadiusPacket packet, String clientAddress) 
            throws RadiusSecurityException {
        if (!isFeatureEnabled(SecurityFeature.REPLAY_PROTECTION)) {
            logger.debug("Replay protection is disabled");
            return;
        }
        
        // Enhanced replay protection per RFC 5080 §2.2
        
        // 1. Create unique packet identifier including Request Authenticator
        String packetKey = createPacketKey(packet, clientAddress);
        long currentTime = System.currentTimeMillis();
        
        // 2. Check for exact duplicate packets (RFC 5080 §2.2.1)
        Long lastSeen = recentPackets.get(packetKey);
        if (lastSeen != null) {
            long timeSinceLastSeen = currentTime - lastSeen;
            
            if (timeSinceLastSeen < replayWindowMs) {
                // Log security event for monitoring
                logger.warn("Replay attack detected from {}: packet ID {} within {}ms window", 
                           clientAddress, packet.getIdentifier(), timeSinceLastSeen);
                
                throw RadiusSecurityException.replayAttackDetected(clientAddress, packet.getIdentifier());
            }
        }
        
        // 3. Additional validation: Check for identifier reuse with different authenticator
        validateIdentifierReuse(packet, clientAddress, currentTime);
        
        // 4. Record this packet with timestamp
        recentPackets.put(packetKey, currentTime);
        
        // 5. Proactive memory management
        if (recentPackets.size() > MAX_RECENT_PACKETS) {
            cleanupExpiredPackets();
        }
        
        logger.debug("Enhanced replay protection check passed for packet ID {} from {}", 
                    packet.getIdentifier(), clientAddress);
    }
    
    @Override
    public void validatePacketSecurity(RadiusPacket packet, String sharedSecret, String clientAddress) 
            throws RadiusSecurityException, RadiusValidationException {
        
        logger.debug("Performing comprehensive security validation for packet from {}", clientAddress);
        
        // Perform all enabled security validations
        validatePacketBounds(packet);
        validateAttributeBounds(packet);
        checkReplayProtection(packet, clientAddress);
        validateRequestAuthenticator(packet, sharedSecret);
        validateMessageAuthenticator(packet, sharedSecret);
        
        logger.debug("Comprehensive security validation passed for packet from {}", clientAddress);
    }
    
    @Override
    public void configureSecurityFeature(SecurityFeature feature, boolean enabled) {
        securityFeatures.put(feature, enabled);
        logger.info("Security feature {} {}", feature, enabled ? "enabled" : "disabled");
    }
    
    /**
     * Checks if a security feature is enabled.
     */
    private boolean isFeatureEnabled(SecurityFeature feature) {
        return securityFeatures.getOrDefault(feature, false);
    }
    
    /**
     * Initializes default security feature settings.
     */
    private void initializeDefaultSecurityFeatures() {
        // Start with basic validations enabled, advanced features disabled
        securityFeatures.put(SecurityFeature.PACKET_BOUNDS_VALIDATION, true);
        securityFeatures.put(SecurityFeature.ATTRIBUTE_BOUNDS_VALIDATION, true);
        securityFeatures.put(SecurityFeature.REQUEST_AUTHENTICATOR_VALIDATION, true); // Enabled by default for security
        securityFeatures.put(SecurityFeature.MESSAGE_AUTHENTICATOR_VALIDATION, true); // Now implemented per RFC 2869 §5.14
        securityFeatures.put(SecurityFeature.REPLAY_PROTECTION, true); // Enabled for production security
        securityFeatures.put(SecurityFeature.STRICT_RFC_COMPLIANCE, false);
    }
    
    
    /**
     * Validates RADIUS packet header structure.
     */
    private void validatePacketHeader(byte[] packetData) throws RadiusValidationException {
        if (packetData.length < 4) {
            throw new RadiusValidationException("Packet too short for header");
        }
        
        // Validate code field
        int code = packetData[0] & 0xFF;
        if (code < 1 || code > 255) {
            throw new RadiusValidationException("packet-code", String.valueOf(code), 
                "Invalid packet code");
        }
        
        // Validate length field
        int length = ((packetData[2] & 0xFF) << 8) | (packetData[3] & 0xFF);
        if (length != packetData.length) {
            throw new RadiusValidationException("packet-length", String.valueOf(length), 
                "Length field mismatch with actual packet length");
        }
    }
    
    /**
     * Validates specific RADIUS attribute types according to RFC specifications.
     */
    private void validateSpecificAttributeType(RadiusPacket.RadiusAttribute attr) 
            throws RadiusValidationException {
        
        switch (attr.getType()) {
            case RadiusPacket.USER_NAME:
                validateUserNameAttribute(attr);
                break;
            case RadiusPacket.USER_PASSWORD:
                validateUserPasswordAttribute(attr);
                break;
            case RadiusPacket.MESSAGE_AUTHENTICATOR:
                validateMessageAuthenticatorAttribute(attr);
                break;
            // Add more specific validations as needed
        }
    }
    
    /**
     * Validates User-Name attribute format.
     */
    private void validateUserNameAttribute(RadiusPacket.RadiusAttribute attr) 
            throws RadiusValidationException {
        String username = attr.getStringValue();
        if (username == null || username.isEmpty()) {
            throw RadiusValidationException.invalidFormat("User-Name", username, "non-empty string");
        }
        
        if (username.length() > 253) {
            throw RadiusValidationException.attributeLengthError(
                RadiusPacket.USER_NAME, username.length(), 253);
        }
    }
    
    /**
     * Validates User-Password attribute format.
     */
    private void validateUserPasswordAttribute(RadiusPacket.RadiusAttribute attr) 
            throws RadiusValidationException {
        byte[] password = attr.getValue();
        if (password == null || password.length == 0) {
            throw RadiusValidationException.invalidFormat("User-Password", "[empty]", "non-empty encrypted value");
        }
        
        if (password.length % 16 != 0) {
            throw RadiusValidationException.invalidFormat("User-Password", "[encrypted]", 
                "length must be multiple of 16 bytes");
        }
    }
    
    /**
     * Validates Message-Authenticator attribute format.
     */
    private void validateMessageAuthenticatorAttribute(RadiusPacket.RadiusAttribute attr) 
            throws RadiusValidationException {
        byte[] value = attr.getValue();
        if (value == null || value.length != 16) {
            throw RadiusValidationException.attributeLengthError(
                RadiusPacket.MESSAGE_AUTHENTICATOR, value != null ? value.length : 0, 16);
        }
    }
    
    /**
     * Validates attribute occurrence rules according to RFC 2865.
     * Some attributes can appear multiple times, others must be unique.
     */
    private void validateAttributeOccurrenceRules(int attributeType, int count) 
            throws RadiusValidationException {
        
        switch (attributeType) {
            case RadiusPacket.USER_NAME:
            case RadiusPacket.USER_PASSWORD:
            case RadiusPacket.CHAP_PASSWORD:
            case RadiusPacket.NAS_IP_ADDRESS:
            case RadiusPacket.NAS_PORT:
            case RadiusPacket.MESSAGE_AUTHENTICATOR:
                // These attributes MUST appear at most once per packet
                if (count > 1) {
                    throw RadiusValidationException.invalidFormat(
                        "Attribute-" + attributeType,
                        "count=" + count,
                        "Attribute can appear at most once per packet (RFC 2865)"
                    );
                }
                break;
                
            case RadiusPacket.REPLY_MESSAGE:
            case RadiusPacket.VENDOR_SPECIFIC:
                // These attributes can appear multiple times
                // No restriction needed
                break;
                
            default:
                // For unknown attributes, be conservative and allow multiples
                // Real implementation should consult RFC attribute registry
                logger.debug("Unknown attribute type {} appeared {} times", attributeType, count);
                break;
        }
    }
    
    /**
     * Validates that required attributes are present for Access-Request packets.
     */
    private void validateRequiredAttributes(RadiusPacket packet, Map<Integer, Integer> attributeCounts) 
            throws RadiusValidationException {
        
        // RFC 2865 §4.1: Access-Request MUST contain User-Name
        if (!attributeCounts.containsKey(RadiusPacket.USER_NAME)) {
            throw RadiusValidationException.missingRequiredAttribute("User-Name", "Access-Request");
        }
        
        // RFC 2865 §4.1: Access-Request MUST contain either User-Password or CHAP-Password
        boolean hasPassword = attributeCounts.containsKey(RadiusPacket.USER_PASSWORD);
        boolean hasChapPassword = attributeCounts.containsKey(RadiusPacket.CHAP_PASSWORD);
        
        if (!hasPassword && !hasChapPassword) {
            throw RadiusValidationException.missingRequiredAttribute(
                "User-Password or CHAP-Password", "Access-Request");
        }
        
        // RFC 2865: User-Password and CHAP-Password are mutually exclusive
        if (hasPassword && hasChapPassword) {
            throw RadiusValidationException.conflictingAttributes(
                "User-Password", "CHAP-Password", "Cannot both be present in same packet");
        }
        
        logger.debug("Required attribute validation passed for Access-Request");
    }
    
    /**
     * Validates identifier reuse patterns to detect sophisticated replay attacks.
     * 
     * @param packet the RADIUS packet
     * @param clientAddress client IP address
     * @param currentTime current timestamp
     * @throws RadiusSecurityException if suspicious identifier reuse is detected
     */
    private void validateIdentifierReuse(RadiusPacket packet, String clientAddress, long currentTime) 
            throws RadiusSecurityException {
        
        // Check for identifier reuse with different Request Authenticator
        // This could indicate an attempt to replay with modified authenticator
        String identifierKey = clientAddress + ":" + packet.getIdentifier();
        
        for (Map.Entry<String, Long> entry : recentPackets.entrySet()) {
            String existingKey = entry.getKey();
            long timestamp = entry.getValue();
            
            // Skip expired entries
            if (currentTime - timestamp >= replayWindowMs) {
                continue;
            }
            
            // Check if this identifier was used recently with different authenticator
            if (existingKey.startsWith(identifierKey + ":") && !existingKey.equals(createPacketKey(packet, clientAddress))) {
                logger.warn("Suspicious identifier reuse detected from {}: ID {} used with different authenticator", 
                           clientAddress, packet.getIdentifier());
                
                // This is suspicious but not necessarily an attack, so log but don't block
                // In strict mode, this could be blocked
                if (isFeatureEnabled(SecurityFeature.STRICT_RFC_COMPLIANCE)) {
                    throw RadiusSecurityException.replayAttackDetected(clientAddress, packet.getIdentifier());
                }
            }
        }
    }
    
    /**
     * Computes Message-Authenticator according to RFC 2869 §5.14.
     * 
     * @param packet the RADIUS packet
     * @param sharedSecret the shared secret
     * @return computed Message-Authenticator (16 bytes)
     * @throws Exception if cryptographic operation fails
     */
    private byte[] computeMessageAuthenticator(RadiusPacket packet, String sharedSecret) throws Exception {
        // RFC 2869 §5.14: Message-Authenticator = HMAC-MD5(Type + Identifier + Length + 
        //                 Request Authenticator + Attributes (with Message-Authenticator = 0))
        
        // Create a copy of the packet with Message-Authenticator set to zeros
        RadiusPacket tempPacket = createPacketWithZeroMessageAuth(packet);
        
        // Encode the packet
        byte[] packetData = tempPacket.encode();
        
        // Compute HMAC-MD5
        Mac hmacMd5 = Mac.getInstance("HmacMD5");
        SecretKeySpec secretKey = new SecretKeySpec(sharedSecret.getBytes(), "HmacMD5");
        hmacMd5.init(secretKey);
        
        return hmacMd5.doFinal(packetData);
    }
    
    /**
     * Creates a copy of the packet with Message-Authenticator attribute set to zeros.
     * This is required for Message-Authenticator computation per RFC 2869 §5.14.
     */
    private RadiusPacket createPacketWithZeroMessageAuth(RadiusPacket original) {
        List<RadiusPacket.RadiusAttribute> modifiedAttributes = new ArrayList<>();
        
        for (RadiusPacket.RadiusAttribute attr : original.getAttributes()) {
            if (attr.getType() == RadiusPacket.MESSAGE_AUTHENTICATOR) {
                // Replace Message-Authenticator with zeros
                modifiedAttributes.add(new RadiusPacket.RadiusAttribute(
                    RadiusPacket.MESSAGE_AUTHENTICATOR, new byte[16]));
            } else {
                modifiedAttributes.add(attr);
            }
        }
        
        return new RadiusPacket(original.getCode(), original.getIdentifier(), 
                               original.getAuthenticator(), modifiedAttributes);
    }
    
    /**
     * Performs constant-time comparison of byte arrays to prevent timing attacks.
     * 
     * @param a first byte array
     * @param b second byte array
     * @return true if arrays are equal, false otherwise
     */
    private boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        
        return result == 0;
    }
    
    /**
     * Creates a unique key for replay protection.
     */
    private String createPacketKey(RadiusPacket packet, String clientAddress) {
        // Create key from client address, packet identifier, and authenticator
        return String.format("%s:%d:%s", 
            clientAddress, 
            packet.getIdentifier(),
            RadiusUtils.bytesToHex(packet.getAuthenticator()));
    }
    
    /**
     * Cleans up expired packets from replay protection cache.
     */
    private void cleanupExpiredPackets() {
        long currentTime = System.currentTimeMillis();
        long expiredThreshold = currentTime - replayWindowMs;
        
        int removedCount = 0;
        var iterator = recentPackets.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            if (entry.getValue() < expiredThreshold) {
                iterator.remove();
                removedCount++;
            }
        }
        
        if (removedCount > 0) {
            logger.debug("Cleaned up {} expired packets from replay protection cache", removedCount);
        }
    }
    
    /**
     * Shuts down the security validator and cleanup resources.
     */
    public void shutdown() {
        cleanupExecutor.shutdown();
        try {
            if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            cleanupExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        recentPackets.clear();
        logger.info("Security validator shutdown completed");
    }
}