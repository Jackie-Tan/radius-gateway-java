package com.radiusgateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * RADIUS handler that expects password and OTP to be sent in separate RADIUS attributes.
 * This is useful for VPN clients that can send OTP in a dedicated field.
 */
public class SeparatePasswordOtpHandler implements RadiusHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(SeparatePasswordOtpHandler.class);
    
    private final AuthBackend authBackend;
    private final int otpAttributeType;
    
    public SeparatePasswordOtpHandler(AuthBackend authBackend) {
        this(authBackend, RadiusPacket.VENDOR_SPECIFIC); // Default to vendor-specific attribute
    }
    
    public SeparatePasswordOtpHandler(AuthBackend authBackend, int otpAttributeType) {
        if (authBackend == null) {
            throw new IllegalArgumentException("AuthBackend cannot be null");
        }
        
        this.authBackend = authBackend;
        this.otpAttributeType = otpAttributeType;
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
            
            String password = request.decryptPassword();
            if (password == null || password.isEmpty()) {
                logger.warn("Access request from {} for user '{}' with missing password", 
                          request.getClientAddress().getHostAddress(), username);
                return RadiusResponse.reject("Missing password");
            }
            
            // Extract OTP from separate attribute
            String otp = extractOtpFromRequest(request);
            if (otp == null || otp.isEmpty()) {
                logger.warn("Access request from {} for user '{}' with missing OTP", 
                          request.getClientAddress().getHostAddress(), username);
                return RadiusResponse.reject("Missing OTP");
            }
            
            logger.debug("Authenticating user '{}' with separate password and OTP from {}", 
                        username, request.getClientAddress().getHostAddress());
            
            // Authenticate with backend
            AuthBackend.AuthResult result = authBackend.authenticate(username, password, otp);
            
            if (result.isSuccess()) {
                logger.info("Authentication successful for user '{}' from {}", 
                          username, request.getClientAddress().getHostAddress());
                return RadiusResponse.accept(result.getReplyMessage());
            } else {
                logger.warn("Authentication failed for user '{}' from {}: {}", 
                          username, request.getClientAddress().getHostAddress(), result.getFailureReason());
                return RadiusResponse.reject(result.getReplyMessage());
            }
            
        } catch (Exception e) {
            logger.error("Error processing access request from {}", 
                        request.getClientAddress().getHostAddress(), e);
            return RadiusResponse.reject("Internal server error");
        }
    }
    
    private String extractOtpFromRequest(RadiusRequest request) {
        try {
            // Try to extract OTP from the configured attribute type
            RadiusPacket.RadiusAttribute otpAttribute = request.getPacket().getAttribute(otpAttributeType);
            
            if (otpAttribute != null) {
                // For vendor-specific attributes, extract the actual OTP value
                if (otpAttributeType == RadiusPacket.VENDOR_SPECIFIC) {
                    return extractOtpFromVendorSpecific(otpAttribute);
                } else {
                    // For other attribute types, treat as string
                    return new String(otpAttribute.getValue());
                }
            }
            
            // Fallback: try common OTP attribute locations
            // Some VPN clients might use other attributes for OTP
            return tryExtractOtpFromCommonAttributes(request);
            
        } catch (Exception e) {
            logger.warn("Failed to extract OTP from request: {}", e.getMessage());
            return null;
        }
    }
    
    private String extractOtpFromVendorSpecific(RadiusPacket.RadiusAttribute attribute) {
        byte[] value = attribute.getValue();
        
        // Vendor-Specific format: Vendor-Id (4 bytes) + Vendor-Type (1 byte) + Vendor-Length (1 byte) + Data
        if (value.length < 6) {
            return null;
        }
        
        // Skip vendor ID (4 bytes), vendor type (1 byte), vendor length (1 byte)
        // Extract the actual OTP data
        int otpLength = value.length - 6;
        if (otpLength > 0) {
            byte[] otpData = new byte[otpLength];
            System.arraycopy(value, 6, otpData, 0, otpLength);
            return new String(otpData).trim();
        }
        
        return null;
    }
    
    private String tryExtractOtpFromCommonAttributes(RadiusRequest request) {
        // Try common locations where VPN clients might put OTP
        
        // Try State attribute (sometimes used for OTP)
        RadiusPacket.RadiusAttribute stateAttr = request.getPacket().getAttribute(RadiusPacket.STATE);
        if (stateAttr != null) {
            String stateValue = new String(stateAttr.getValue()).trim();
            if (stateValue.matches("\\d{4,8}")) { // 4-8 digit OTP
                logger.debug("Found OTP in State attribute");
                return stateValue;
            }
        }
        
        // Could add more fallback locations here based on specific VPN client behavior
        
        return null;
    }
    
    public int getOtpAttributeType() {
        return otpAttributeType;
    }
}