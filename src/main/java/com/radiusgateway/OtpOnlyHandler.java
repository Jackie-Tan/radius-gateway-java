package com.radiusgateway;

/**
 * RADIUS handler for OTP-only authentication where users enter only the OTP/token
 * in the password field. No traditional password is required.
 * 
 * This mode is useful for:
 * - Hardware token authentication (RSA SecurID)
 * - SMS/Email OTP systems
 * - Time-based OTP (TOTP) applications
 * - Passwordless authentication flows
 */
public class OtpOnlyHandler extends HandlerUtils {
    
    private final int expectedOtpLength;
    
    public OtpOnlyHandler(AuthBackend authBackend) {
        this(authBackend, 6); // Default 6-digit OTP
    }
    
    public OtpOnlyHandler(AuthBackend authBackend, int expectedOtpLength) {
        super(authBackend);
        if (expectedOtpLength <= 0) {
            throw new IllegalArgumentException("Expected OTP length must be positive");
        }
        
        this.expectedOtpLength = expectedOtpLength;
    }
    
    @Override
    public RadiusResponse handleAccessRequest(RadiusRequest request) {
        try {
            String clientAddress = request.getClientAddress().getHostAddress();
            
            // Validate basic request and username
            ValidationResult usernameValidation = validateBasicRequest(request);
            if (!usernameValidation.isSuccess()) {
                return usernameValidation.toErrorResponse();
            }
            String username = usernameValidation.getValue();
            
            // Extract OTP from password field (OTP-only mode)
            ValidationResult passwordValidation = validatePassword(request, username, true);
            if (!passwordValidation.isSuccess()) {
                return passwordValidation.toErrorResponse();
            }
            String otp = passwordValidation.getValue();
            
            // Validate OTP format
            if (!isValidOtpFormat(otp, expectedOtpLength, 2)) {
                logger.warn("Access request from {} for user '{}' with invalid OTP format", 
                          clientAddress, username);
                return RadiusResponse.reject("Invalid OTP format");
            }
            
            logger.debug("Authenticating user '{}' with OTP-only from {}", username, clientAddress);
            
            // Authenticate with OTP only (no password)
            AuthBackend.AuthResult result = authBackend.authenticate(username, null, otp);
            
            return processAuthenticationResult(result, username, clientAddress);
            
        } catch (Exception e) {
            return handleProcessingError(e, request.getClientAddress().getHostAddress());
        }
    }
    
    
    /**
     * Gets the expected OTP length for this handler.
     */
    public int getExpectedOtpLength() {
        return expectedOtpLength;
    }
    
    /**
     * Checks if the given string appears to be a valid OTP for this handler.
     */
    public boolean isValidOtp(String otp) {
        return isValidOtpFormat(otp, expectedOtpLength, 2);
    }
}