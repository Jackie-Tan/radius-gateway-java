package com.radiusgateway;

/**
 * Exception thrown when RADIUS security validation fails.
 * This includes authenticator validation, replay detection, and other security-related errors.
 */
public class RadiusSecurityException extends Exception {
    
    private final SecurityFailureType failureType;
    private final String clientAddress;
    
    /**
     * Enumeration of security failure types.
     */
    public enum SecurityFailureType {
        INVALID_REQUEST_AUTHENTICATOR("Invalid Request Authenticator"),
        INVALID_RESPONSE_AUTHENTICATOR("Invalid Response Authenticator"),
        INVALID_MESSAGE_AUTHENTICATOR("Invalid Message-Authenticator"),
        REPLAY_ATTACK_DETECTED("Replay attack detected"),
        DUPLICATE_IDENTIFIER("Duplicate packet identifier"),
        UNREGISTERED_CLIENT("Unregistered NAS client"),
        INVALID_SHARED_SECRET("Invalid shared secret"),
        PACKET_TOO_OLD("Packet timestamp too old"),
        MALFORMED_PACKET("Malformed packet structure"),
        CRYPTOGRAPHIC_ERROR("Cryptographic operation failed");
        
        private final String description;
        
        SecurityFailureType(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * Creates a security exception with a message.
     * 
     * @param message the error message
     */
    public RadiusSecurityException(String message) {
        super(message);
        this.failureType = null;
        this.clientAddress = null;
    }
    
    /**
     * Creates a security exception with a message and cause.
     * 
     * @param message the error message
     * @param cause the underlying cause
     */
    public RadiusSecurityException(String message, Throwable cause) {
        super(message, cause);
        this.failureType = null;
        this.clientAddress = null;
    }
    
    /**
     * Creates a security exception with failure type.
     * 
     * @param failureType the type of security failure
     * @param clientAddress the client address involved in the failure
     */
    public RadiusSecurityException(SecurityFailureType failureType, String clientAddress) {
        super(formatSecurityMessage(failureType, clientAddress));
        this.failureType = failureType;
        this.clientAddress = clientAddress;
    }
    
    /**
     * Creates a security exception with failure type and additional details.
     * 
     * @param failureType the type of security failure
     * @param clientAddress the client address involved in the failure
     * @param additionalDetails additional details about the failure
     */
    public RadiusSecurityException(SecurityFailureType failureType, String clientAddress, String additionalDetails) {
        super(formatSecurityMessage(failureType, clientAddress) + ": " + additionalDetails);
        this.failureType = failureType;
        this.clientAddress = clientAddress;
    }
    
    /**
     * Creates a security exception with failure type, client address, and cause.
     * 
     * @param failureType the type of security failure
     * @param clientAddress the client address involved in the failure
     * @param cause the underlying cause
     */
    public RadiusSecurityException(SecurityFailureType failureType, String clientAddress, Throwable cause) {
        super(formatSecurityMessage(failureType, clientAddress), cause);
        this.failureType = failureType;
        this.clientAddress = clientAddress;
    }
    
    /**
     * Creates a security exception with failure type, client address, additional details, and cause.
     * 
     * @param failureType the type of security failure
     * @param clientAddress the client address involved in the failure
     * @param additionalDetails additional details about the failure
     * @param cause the underlying cause
     */
    public RadiusSecurityException(SecurityFailureType failureType, String clientAddress, String additionalDetails, Throwable cause) {
        super(formatSecurityMessage(failureType, clientAddress) + ": " + additionalDetails, cause);
        this.failureType = failureType;
        this.clientAddress = clientAddress;
    }
    
    /**
     * Gets the type of security failure.
     * 
     * @return failure type, or null if not specified
     */
    public SecurityFailureType getFailureType() {
        return failureType;
    }
    
    /**
     * Gets the client address involved in the security failure.
     * 
     * @return client address, or null if not specified
     */
    public String getClientAddress() {
        return clientAddress;
    }
    
    /**
     * Checks if this security exception includes a specific failure type.
     * 
     * @return true if failure type is specified, false otherwise
     */
    public boolean hasFailureType() {
        return failureType != null;
    }
    
    /**
     * Checks if this security exception is related to authentication validation.
     * 
     * @return true if authenticator-related, false otherwise
     */
    public boolean isAuthenticatorFailure() {
        return failureType == SecurityFailureType.INVALID_REQUEST_AUTHENTICATOR ||
               failureType == SecurityFailureType.INVALID_RESPONSE_AUTHENTICATOR ||
               failureType == SecurityFailureType.INVALID_MESSAGE_AUTHENTICATOR;
    }
    
    /**
     * Checks if this security exception is related to replay protection.
     * 
     * @return true if replay-related, false otherwise
     */
    public boolean isReplayFailure() {
        return failureType == SecurityFailureType.REPLAY_ATTACK_DETECTED ||
               failureType == SecurityFailureType.DUPLICATE_IDENTIFIER ||
               failureType == SecurityFailureType.PACKET_TOO_OLD;
    }
    
    /**
     * Formats a security failure message.
     * 
     * @param failureType the failure type
     * @param clientAddress the client address
     * @return formatted message
     */
    private static String formatSecurityMessage(SecurityFailureType failureType, String clientAddress) {
        if (failureType == null) {
            return "Security failure";
        }
        
        String baseMessage = failureType.getDescription();
        if (clientAddress != null && !clientAddress.isEmpty()) {
            return baseMessage + " from client " + clientAddress;
        }
        
        return baseMessage;
    }
    
    /**
     * Creates a security exception for invalid Request Authenticator.
     * 
     * @param clientAddress the client address
     * @return security exception
     */
    public static RadiusSecurityException invalidRequestAuthenticator(String clientAddress) {
        return new RadiusSecurityException(SecurityFailureType.INVALID_REQUEST_AUTHENTICATOR, clientAddress);
    }
    
    /**
     * Creates a security exception for invalid Message-Authenticator.
     * 
     * @param clientAddress the client address
     * @return security exception
     */
    public static RadiusSecurityException invalidMessageAuthenticator(String clientAddress) {
        return new RadiusSecurityException(SecurityFailureType.INVALID_MESSAGE_AUTHENTICATOR, clientAddress);
    }
    
    /**
     * Creates a security exception for replay attack detection.
     * 
     * @param clientAddress the client address
     * @param packetId the duplicate packet identifier
     * @return security exception
     */
    public static RadiusSecurityException replayAttackDetected(String clientAddress, int packetId) {
        return new RadiusSecurityException(SecurityFailureType.REPLAY_ATTACK_DETECTED, clientAddress,
            "Duplicate packet ID: " + packetId);
    }
    
    /**
     * Creates a security exception for unregistered client.
     * 
     * @param clientAddress the unregistered client address
     * @return security exception
     */
    public static RadiusSecurityException unregisteredClient(String clientAddress) {
        return new RadiusSecurityException(SecurityFailureType.UNREGISTERED_CLIENT, clientAddress);
    }
    
    /**
     * Creates a security exception for cryptographic errors.
     * 
     * @param operation the cryptographic operation that failed
     * @param cause the underlying cause
     * @return security exception
     */
    public static RadiusSecurityException cryptographicError(String operation, Throwable cause) {
        return new RadiusSecurityException(SecurityFailureType.CRYPTOGRAPHIC_ERROR, null, 
            "Failed during " + operation, cause);
    }
}