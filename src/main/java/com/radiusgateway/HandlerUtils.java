package com.radiusgateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract base class providing common functionality for RADIUS handlers.
 * Standardizes validation, error handling, and logging patterns.
 */
public abstract class HandlerUtils implements RadiusHandler {
    
    protected final Logger logger;
    protected final AuthBackend authBackend;
    
    protected HandlerUtils(AuthBackend authBackend) {
        if (authBackend == null) {
            throw new IllegalArgumentException("AuthBackend cannot be null");
        }
        
        this.authBackend = authBackend;
        this.logger = LoggerFactory.getLogger(this.getClass());
    }
    
    /**
     * Validates the basic request structure and extracts username.
     * 
     * @param request the RADIUS request to validate
     * @return validation result containing username if successful
     */
    protected ValidationResult validateBasicRequest(RadiusRequest request) {
        try {
            String clientAddress = request.getClientAddress().getHostAddress();
            
            // Validate username
            String username = request.getUsername();
            if (!RadiusUtils.isValidUsername(username)) {
                logger.warn("Access request from {} with invalid username: '{}'", 
                          clientAddress, username != null ? username : "[null]");
                return ValidationResult.failure("Invalid username");
            }
            
            return ValidationResult.success(username.trim());
            
        } catch (Exception e) {
            logger.error("Error validating request from {}: {}", 
                        request.getClientAddress().getHostAddress(), e.getMessage());
            return ValidationResult.failure("Request validation error");
        }
    }
    
    /**
     * Extracts and validates password from the request.
     * 
     * @param request the RADIUS request
     * @param username the username for logging context
     * @param required whether password is required (false for OTP-only modes)
     * @return validation result containing password if successful
     */
    protected ValidationResult validatePassword(RadiusRequest request, String username, boolean required) {
        try {
            String password = request.decryptPassword();
            String clientAddress = request.getClientAddress().getHostAddress();
            
            if (required && (password == null || password.isEmpty())) {
                logger.warn("Access request from {} for user '{}' with missing password", 
                          clientAddress, username);
                return ValidationResult.failure("Missing password");
            }
            
            return ValidationResult.success(password);
            
        } catch (RadiusPacket.RadiusException e) {
            logger.warn("Password decryption error for user '{}' from {}: {}", 
                       username, request.getClientAddress().getHostAddress(), e.getMessage());
            return ValidationResult.failure("Password decryption error");
        } catch (Exception e) {
            logger.error("Error extracting password for user '{}' from {}: {}", 
                        username, request.getClientAddress().getHostAddress(), e.getMessage());
            return ValidationResult.failure("Password extraction error");
        }
    }
    
    /**
     * Processes authentication result and creates appropriate RADIUS response.
     * 
     * @param result the authentication result from backend
     * @param username the username for logging context
     * @param clientAddress the client address for logging context
     * @return RADIUS response
     */
    protected RadiusResponse processAuthenticationResult(AuthBackend.AuthResult result, 
                                                       String username, 
                                                       String clientAddress) {
        if (result.isSuccess()) {
            logger.info("Authentication successful for user '{}' from {}", username, clientAddress);
            return result.getReplyMessage() != null 
                ? RadiusResponse.accept(result.getReplyMessage())
                : RadiusResponse.accept();
        } else {
            logger.warn("Authentication failed for user '{}' from {}: {}", 
                       username, clientAddress, result.getFailureReason());
            return result.getReplyMessage() != null
                ? RadiusResponse.reject(result.getReplyMessage())
                : RadiusResponse.reject("Authentication failed");
        }
    }
    
    /**
     * Handles exceptions that occur during request processing.
     * 
     * @param e the exception that occurred
     * @param clientAddress the client address for logging context
     * @return error response
     */
    protected RadiusResponse handleProcessingError(Exception e, String clientAddress) {
        if (e instanceof RadiusPacket.RadiusException) {
            logger.error("RADIUS processing error for request from {}: {}", 
                        clientAddress, e.getMessage());
            return RadiusResponse.reject("Processing error");
        } else {
            logger.error("Unexpected error processing request from {}", clientAddress, e);
            return RadiusResponse.reject("Internal error");
        }
    }
    
    /**
     * Validates OTP format using RadiusUtils with specified parameters.
     * 
     * @param otp the OTP to validate
     * @param expectedLength expected OTP length
     * @param tolerance acceptable deviation from expected length
     * @return true if OTP format is valid, false otherwise
     */
    protected boolean isValidOtpFormat(String otp, int expectedLength, int tolerance) {
        return RadiusUtils.isValidOtpFormat(otp, expectedLength, tolerance);
    }
    
    /**
     * Validates basic OTP format (4-8 digits).
     * 
     * @param otp the OTP to validate
     * @return true if OTP format is valid, false otherwise
     */
    protected boolean isValidOtpFormat(String otp) {
        return RadiusUtils.isValidOtpFormat(otp);
    }
    
    /**
     * Represents the result of a validation operation.
     */
    protected static class ValidationResult {
        private final boolean success;
        private final String value;
        private final String errorMessage;
        
        private ValidationResult(boolean success, String value, String errorMessage) {
            this.success = success;
            this.value = value;
            this.errorMessage = errorMessage;
        }
        
        public static ValidationResult success(String value) {
            return new ValidationResult(true, value, null);
        }
        
        public static ValidationResult failure(String errorMessage) {
            return new ValidationResult(false, null, errorMessage);
        }
        
        public boolean isSuccess() {
            return success;
        }
        
        public String getValue() {
            return value;
        }
        
        public String getErrorMessage() {
            return errorMessage;
        }
        
        public RadiusResponse toErrorResponse() {
            return RadiusResponse.reject(errorMessage != null ? errorMessage : "Validation failed");
        }
    }
}