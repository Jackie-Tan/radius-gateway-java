package com.radiusgateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * RADIUS handler that implements two-stage authentication:
 * Stage 1: Username + Password → Access-Challenge (prompt for OTP)
 * Stage 2: Username + OTP + State → Access-Accept/Reject
 * 
 * This matches the authentication flow shown in modern VPN clients where
 * password is validated first, then user is prompted for OTP/2FA.
 */
public class TwoStagePasswordOtpHandler implements RadiusHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(TwoStagePasswordOtpHandler.class);
    
    private final AuthBackend authBackend;
    private final ChallengeState challengeState;
    private final String challengeMessage;
    
    public TwoStagePasswordOtpHandler(AuthBackend authBackend, int challengeTimeoutSeconds) {
        this(authBackend, challengeTimeoutSeconds, "Enter your OTP code");
    }
    
    public TwoStagePasswordOtpHandler(AuthBackend authBackend, int challengeTimeoutSeconds, String challengeMessage) {
        if (authBackend == null) {
            throw new IllegalArgumentException("AuthBackend cannot be null");
        }
        
        this.authBackend = authBackend;
        this.challengeState = new ChallengeState(challengeTimeoutSeconds);
        this.challengeMessage = challengeMessage != null ? challengeMessage : "Enter your OTP code";
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
            
            String clientAddress = request.getClientAddress().getHostAddress();
            
            // Check if this is a challenge response (Stage 2) or initial request (Stage 1)
            byte[] stateAttribute = getStateAttribute(request);
            
            if (stateAttribute != null) {
                // Stage 2: Challenge response with OTP
                return handleChallengeResponse(request, username, clientAddress, stateAttribute);
            } else {
                // Stage 1: Initial authentication with password
                return handleInitialAuthentication(request, username, clientAddress);
            }
            
        } catch (Exception e) {
            logger.error("Error processing access request from {}", 
                        request.getClientAddress().getHostAddress(), e);
            return RadiusResponse.reject("Internal server error");
        }
    }
    
    /**
     * Stage 1: Handle initial authentication with username and password.
     * If password is valid, return Access-Challenge to prompt for OTP.
     */
    private RadiusResponse handleInitialAuthentication(RadiusRequest request, String username, String clientAddress) {
        try {
            String password = request.decryptPassword();
            if (password == null || password.isEmpty()) {
                logger.warn("Access request from {} for user '{}' with missing password", 
                          clientAddress, username);
                return RadiusResponse.reject("Missing password");
            }
            
            logger.debug("Stage 1: Authenticating password for user '{}' from {}", username, clientAddress);
            
            // Authenticate password only (no OTP yet)
            AuthBackend.AuthResult result = authBackend.authenticate(username, password);
            
            if (result.isSuccess()) {
                // Password is valid, create challenge for OTP
                byte[] challengeStateId = challengeState.createChallenge(username, clientAddress);
                
                logger.info("Stage 1: Password authentication successful for user '{}' from {}. Sending OTP challenge.", 
                          username, clientAddress);
                
                return RadiusResponse.challenge(challengeMessage, challengeStateId);
            } else {
                logger.warn("Stage 1: Password authentication failed for user '{}' from {}: {}", 
                          username, clientAddress, result.getFailureReason());
                return RadiusResponse.reject(result.getReplyMessage());
            }
            
        } catch (Exception e) {
            logger.error("Stage 1: Error authenticating password for user '{}' from {}", 
                        username, clientAddress, e);
            return RadiusResponse.reject("Authentication error");
        }
    }
    
    /**
     * Stage 2: Handle challenge response with OTP.
     * Validate the OTP and return final authentication result.
     */
    private RadiusResponse handleChallengeResponse(RadiusRequest request, String username, 
                                                 String clientAddress, byte[] stateAttribute) {
        try {
            // Validate the challenge state
            ChallengeState.ChallengeSession session = challengeState.validateAndConsume(
                stateAttribute, username, clientAddress);
            
            if (session == null) {
                logger.warn("Stage 2: Invalid or expired challenge state for user '{}' from {}", 
                          username, clientAddress);
                return RadiusResponse.reject("Invalid or expired authentication session");
            }
            
            // Extract OTP from password field (in challenge response, OTP is sent as password)
            String otp = request.decryptPassword();
            if (otp == null || otp.isEmpty()) {
                logger.warn("Stage 2: Missing OTP for user '{}' from {}", username, clientAddress);
                return RadiusResponse.reject("Missing OTP code");
            }
            
            logger.debug("Stage 2: Validating OTP for user '{}' from {}", username, clientAddress);
            
            // Authenticate with OTP (password was already validated in Stage 1)
            // Note: We use a dummy password since we only need OTP validation
            AuthBackend.AuthResult result = authBackend.authenticate(username, "", otp);
            
            if (result.isSuccess()) {
                logger.info("Stage 2: OTP authentication successful for user '{}' from {}. Access granted.", 
                          username, clientAddress);
                return RadiusResponse.accept(result.getReplyMessage());
            } else {
                logger.warn("Stage 2: OTP authentication failed for user '{}' from {}: {}", 
                          username, clientAddress, result.getFailureReason());
                return RadiusResponse.reject(result.getReplyMessage());
            }
            
        } catch (Exception e) {
            logger.error("Stage 2: Error validating OTP for user '{}' from {}", 
                        username, clientAddress, e);
            return RadiusResponse.reject("OTP validation error");
        }
    }
    
    /**
     * Extract State attribute from RADIUS request.
     */
    private byte[] getStateAttribute(RadiusRequest request) {
        RadiusPacket.RadiusAttribute stateAttr = request.getPacket().getAttribute(RadiusPacket.STATE);
        return stateAttr != null ? stateAttr.getValue() : null;
    }
    
    /**
     * Get the challenge message used for OTP prompts.
     */
    public String getChallengeMessage() {
        return challengeMessage;
    }
    
    /**
     * Get the number of active challenge sessions.
     */
    public int getActiveSessionCount() {
        return challengeState.getActiveSessionCount();
    }
    
    /**
     * Shutdown the challenge state manager.
     */
    public void shutdown() {
        if (challengeState != null) {
            challengeState.shutdown();
        }
    }
}