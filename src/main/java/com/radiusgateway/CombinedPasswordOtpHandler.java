package com.radiusgateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CombinedPasswordOtpHandler implements RadiusHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(CombinedPasswordOtpHandler.class);
    
    private final AuthBackend authBackend;
    private final int otpLength;
    
    public CombinedPasswordOtpHandler(AuthBackend authBackend) {
        this(authBackend, 6); // Default OTP length of 6 digits
    }
    
    public CombinedPasswordOtpHandler(AuthBackend authBackend, int otpLength) {
        if (authBackend == null) {
            throw new IllegalArgumentException("AuthBackend cannot be null");
        }
        if (otpLength <= 0) {
            throw new IllegalArgumentException("OTP length must be positive");
        }
        
        this.authBackend = authBackend;
        this.otpLength = otpLength;
    }
    
    @Override
    public RadiusResponse handleAccessRequest(RadiusRequest request) {
        try {
            String username = request.getUsername();
            if (username == null || username.trim().isEmpty()) {
                logger.warn("Access request from {} with missing username", 
                          request.getClientAddress().getHostAddress());
                return RadiusResponse.reject("Missing username");
            }
            
            String combinedPassword = request.decryptPassword();
            if (combinedPassword == null || combinedPassword.isEmpty()) {
                logger.warn("Access request from {} for user '{}' with missing password", 
                          request.getClientAddress().getHostAddress(), username);
                return RadiusResponse.reject("Missing password");
            }
            
            // Split password and OTP using fixed-length OTP
            PasswordOtpPair pair = splitPasswordAndOtp(combinedPassword);
            if (pair == null) {
                logger.warn("Access request from {} for user '{}' with invalid password format", 
                          request.getClientAddress().getHostAddress(), username);
                return RadiusResponse.reject("Invalid password format");
            }
            
            logger.debug("Processing authentication for user '{}' from {}", 
                        username, request.getClientAddress().getHostAddress());
            
            // Authenticate using backend
            AuthBackend.AuthResult result = authBackend.authenticate(
                username.trim(), 
                pair.password, 
                pair.otp
            );
            
            if (result.isSuccess()) {
                logger.info("Authentication successful for user '{}' from {}", 
                          username, request.getClientAddress().getHostAddress());
                return result.getReplyMessage() != null 
                    ? RadiusResponse.accept(result.getReplyMessage())
                    : RadiusResponse.accept();
            } else {
                logger.warn("Authentication failed for user '{}' from {}: {}", 
                          username, request.getClientAddress().getHostAddress(), 
                          result.getFailureReason());
                return result.getReplyMessage() != null
                    ? RadiusResponse.reject(result.getReplyMessage())
                    : RadiusResponse.reject("Authentication failed");
            }
            
        } catch (RadiusPacket.RadiusException e) {
            logger.error("RADIUS processing error for request from {}: {}", 
                        request.getClientAddress().getHostAddress(), e.getMessage());
            return RadiusResponse.reject("Processing error");
        } catch (Exception e) {
            logger.error("Unexpected error processing request from {}", 
                        request.getClientAddress().getHostAddress(), e);
            return RadiusResponse.reject("Internal error");
        }
    }
    
    private PasswordOtpPair splitPasswordAndOtp(String combinedPassword) {
        if (combinedPassword.length() <= otpLength) {
            // Combined password is too short to contain both password and OTP
            return null;
        }
        
        String password = combinedPassword.substring(0, combinedPassword.length() - otpLength);
        String otp = combinedPassword.substring(combinedPassword.length() - otpLength);
        
        // Validate OTP format (should be all digits)
        if (!otp.matches("\\d+")) {
            return null;
        }
        
        return new PasswordOtpPair(password, otp);
    }
    
    public int getOtpLength() {
        return otpLength;
    }
    
    private static class PasswordOtpPair {
        final String password;
        final String otp;
        
        PasswordOtpPair(String password, String otp) {
            this.password = password;
            this.otp = otp;
        }
    }
}