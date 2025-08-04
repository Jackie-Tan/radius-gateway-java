package com.radiusgateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory for creating appropriate RADIUS handler instances based on configuration.
 * Encapsulates the logic for determining which handler to use and configuring it properly.
 */
public class HandlerFactory {
    
    private static final Logger logger = LoggerFactory.getLogger(HandlerFactory.class);
    
    /**
     * Creates a RADIUS handler based on the specified OTP mode and configuration.
     * 
     * @param authBackend the authentication backend to use
     * @param otpMode the OTP mode (combined, separate, two-stage, otp-only)
     * @param configManager configuration manager for retrieving settings
     * @return configured RADIUS handler
     * @throws IllegalArgumentException if OTP mode is invalid or configuration is missing
     */
    public static RadiusHandler createHandler(AuthBackend authBackend, 
                                            String otpMode, 
                                            ConfigurationManager configManager) {
        if (authBackend == null) {
            throw new IllegalArgumentException("AuthBackend cannot be null");
        }
        if (otpMode == null || otpMode.trim().isEmpty()) {
            throw new IllegalArgumentException("OTP mode cannot be null or empty");
        }
        if (configManager == null) {
            throw new IllegalArgumentException("ConfigurationManager cannot be null");
        }
        
        String mode = otpMode.trim().toLowerCase();
        
        switch (mode) {
            case "combined":
                return createCombinedHandler(authBackend, configManager);
            
            case "separate":
                return createSeparateHandler(authBackend, configManager);
            
            case "two-stage":
                return createTwoStageHandler(authBackend, configManager);
            
            case "otp-only":
                return createOtpOnlyHandler(authBackend, configManager);
            
            default:
                throw new IllegalArgumentException("Invalid OTP mode: " + otpMode + 
                    ". Supported modes: combined, separate, two-stage, otp-only");
        }
    }
    
    /**
     * Creates a combined password+OTP handler.
     */
    private static RadiusHandler createCombinedHandler(AuthBackend authBackend, 
                                                     ConfigurationManager configManager) {
        int otpLength = getOtpLength(configManager);
        logger.info("Creating combined password+OTP handler with OTP length: {}", otpLength);
        return new CombinedPasswordOtpHandler(authBackend, otpLength);
    }
    
    /**
     * Creates a separate password and OTP handler.
     */
    private static RadiusHandler createSeparateHandler(AuthBackend authBackend, 
                                                     ConfigurationManager configManager) {
        int otpAttributeType = getOtpAttributeType(configManager);
        logger.info("Creating separate OTP handler with attribute type: {}", otpAttributeType);
        return new SeparatePasswordOtpHandler(authBackend, otpAttributeType);
    }
    
    /**
     * Creates a two-stage authentication handler.
     */
    private static RadiusHandler createTwoStageHandler(AuthBackend authBackend, 
                                                     ConfigurationManager configManager) {
        int challengeTimeout = getChallengeTimeout(configManager);
        String challengeMessage = getChallengeMessage(configManager);
        logger.info("Creating two-stage OTP handler with timeout: {}s, message: '{}'", 
                   challengeTimeout, challengeMessage);
        return new TwoStagePasswordOtpHandler(authBackend, challengeTimeout, challengeMessage);
    }
    
    /**
     * Creates an OTP-only authentication handler.
     */
    private static RadiusHandler createOtpOnlyHandler(AuthBackend authBackend, 
                                                    ConfigurationManager configManager) {
        int otpLength = getOtpLength(configManager);
        logger.info("Creating OTP-only handler with expected OTP length: {}", otpLength);
        return new OtpOnlyHandler(authBackend, otpLength);
    }
    
    /**
     * Gets the configured OTP length with validation.
     */
    private static int getOtpLength(ConfigurationManager configManager) {
        String otpLengthStr = configManager.getProperty("auth.otp.length", "6");
        try {
            int otpLength = Integer.parseInt(otpLengthStr);
            if (otpLength <= 0 || otpLength > 20) {
                throw new IllegalArgumentException("OTP length must be between 1 and 20, got: " + otpLength);
            }
            return otpLength;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid OTP length configuration: " + otpLengthStr, e);
        }
    }
    
    /**
     * Gets the configured OTP attribute type with validation.
     */
    private static int getOtpAttributeType(ConfigurationManager configManager) {
        String attributeTypeStr = configManager.getProperty("auth.otp.attribute.type", "26");
        try {
            int attributeType = Integer.parseInt(attributeTypeStr);
            if (attributeType <= 0 || attributeType > 255) {
                throw new IllegalArgumentException("OTP attribute type must be between 1 and 255, got: " + attributeType);
            }
            return attributeType;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid OTP attribute type configuration: " + attributeTypeStr, e);
        }
    }
    
    /**
     * Gets the configured challenge timeout with validation.
     */
    private static int getChallengeTimeout(ConfigurationManager configManager) {
        String timeoutStr = configManager.getProperty("auth.challenge.timeout", "300");
        try {
            int timeout = Integer.parseInt(timeoutStr);
            if (timeout <= 0 || timeout > 3600) {
                throw new IllegalArgumentException("Challenge timeout must be between 1 and 3600 seconds, got: " + timeout);
            }
            return timeout;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid challenge timeout configuration: " + timeoutStr, e);
        }
    }
    
    /**
     * Gets the configured challenge message with validation.
     */
    private static String getChallengeMessage(ConfigurationManager configManager) {
        String message = configManager.getProperty("auth.challenge.message", "Enter your OTP code");
        if (message == null || message.trim().isEmpty()) {
            throw new IllegalArgumentException("Challenge message cannot be empty");
        }
        if (message.length() > 253) {
            throw new IllegalArgumentException("Challenge message too long (max 253 characters): " + message.length());
        }
        return message.trim();
    }
    
    /**
     * Validates that the given OTP mode is supported.
     * 
     * @param otpMode the OTP mode to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidOtpMode(String otpMode) {
        if (otpMode == null) {
            return false;
        }
        
        String mode = otpMode.trim().toLowerCase();
        return "combined".equals(mode) || 
               "separate".equals(mode) || 
               "two-stage".equals(mode) || 
               "otp-only".equals(mode);
    }
    
    /**
     * Gets a list of supported OTP modes.
     * 
     * @return array of supported mode names
     */
    public static String[] getSupportedModes() {
        return new String[]{"combined", "separate", "two-stage", "otp-only"};
    }
    
    /**
     * Gets a description of the specified OTP mode.
     * 
     * @param otpMode the OTP mode
     * @return description of the mode
     */
    public static String getModeDescription(String otpMode) {
        if (otpMode == null) {
            return "Unknown mode";
        }
        
        switch (otpMode.trim().toLowerCase()) {
            case "combined":
                return "Combined password+OTP in single field (traditional)";
            case "separate":
                return "Separate password and OTP fields (modern)";
            case "two-stage":
                return "Two-stage challenge/response authentication (VPN-style)";
            case "otp-only":
                return "OTP-only authentication (token-based)";
            default:
                return "Unknown mode: " + otpMode;
        }
    }
}