package com.radiusgateway;

/**
 * Interface for RADIUS security validation operations.
 * Provides methods for validating packet integrity, authenticators, and bounds checking.
 */
public interface RadiusSecurityValidator {
    
    /**
     * Validates the Request Authenticator according to RFC 2865 §3.
     * 
     * @param packet the RADIUS packet to validate
     * @param sharedSecret the shared secret for this client
     * @throws RadiusSecurityException if validation fails
     */
    void validateRequestAuthenticator(RadiusPacket packet, String sharedSecret) 
            throws RadiusSecurityException;
    
    /**
     * Validates the Message-Authenticator attribute according to RFC 2869 §5.14.
     * 
     * @param packet the RADIUS packet to validate
     * @param sharedSecret the shared secret for this client
     * @throws RadiusSecurityException if validation fails
     */
    void validateMessageAuthenticator(RadiusPacket packet, String sharedSecret) 
            throws RadiusSecurityException;
    
    /**
     * Validates packet structure and attribute bounds according to RFC 2865.
     * 
     * @param packet the RADIUS packet to validate
     * @throws RadiusValidationException if validation fails
     */
    void validatePacketBounds(RadiusPacket packet) 
            throws RadiusValidationException;
    
    /**
     * Validates individual attribute lengths and formats.
     * 
     * @param packet the RADIUS packet to validate
     * @throws RadiusValidationException if validation fails
     */
    void validateAttributeBounds(RadiusPacket packet) 
            throws RadiusValidationException;
    
    /**
     * Checks for replay attacks using packet identifier and timestamp.
     * 
     * @param packet the RADIUS packet to check
     * @param clientAddress the client address
     * @throws RadiusSecurityException if replay attack is detected
     */
    void checkReplayProtection(RadiusPacket packet, String clientAddress) 
            throws RadiusSecurityException;
    
    /**
     * Performs comprehensive security validation on a RADIUS packet.
     * This method combines all security checks.
     * 
     * @param packet the RADIUS packet to validate
     * @param sharedSecret the shared secret for this client
     * @param clientAddress the client address
     * @throws RadiusSecurityException if security validation fails
     * @throws RadiusValidationException if format validation fails
     */
    void validatePacketSecurity(RadiusPacket packet, String sharedSecret, String clientAddress) 
            throws RadiusSecurityException, RadiusValidationException;
    
    /**
     * Enables or disables specific security validations.
     * This allows gradual deployment of security features.
     * 
     * @param feature the security feature to configure
     * @param enabled whether the feature should be enabled
     */
    void configureSecurityFeature(SecurityFeature feature, boolean enabled);
    
    /**
     * Enumeration of configurable security features.
     */
    enum SecurityFeature {
        REQUEST_AUTHENTICATOR_VALIDATION,
        MESSAGE_AUTHENTICATOR_VALIDATION,
        PACKET_BOUNDS_VALIDATION,
        ATTRIBUTE_BOUNDS_VALIDATION,
        REPLAY_PROTECTION,
        STRICT_RFC_COMPLIANCE
    }
}