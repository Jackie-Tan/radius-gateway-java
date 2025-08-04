package com.radiusgateway;

public interface AuthBackend {
    
    AuthResult authenticate(String username, String password);
    
    AuthResult authenticate(String username, String password, String otp);
    
    public static class AuthResult {
        private final boolean success;
        private final String failureReason;
        private final String replyMessage;
        
        private AuthResult(boolean success, String failureReason, String replyMessage) {
            this.success = success;
            this.failureReason = failureReason;
            this.replyMessage = replyMessage;
        }
        
        public static AuthResult success() {
            return new AuthResult(true, null, null);
        }
        
        public static AuthResult success(String replyMessage) {
            return new AuthResult(true, null, replyMessage);
        }
        
        public static AuthResult failure(String reason) {
            return new AuthResult(false, reason, null);
        }
        
        public static AuthResult failure(String reason, String replyMessage) {
            return new AuthResult(false, reason, replyMessage);
        }
        
        public boolean isSuccess() {
            return success;
        }
        
        public String getFailureReason() {
            return failureReason;
        }
        
        public String getReplyMessage() {
            return replyMessage;
        }
        
        @Override
        public String toString() {
            if (success) {
                return "AuthResult{success=true" + 
                       (replyMessage != null ? ", replyMessage='" + replyMessage + "'" : "") + "}";
            } else {
                return "AuthResult{success=false, reason='" + failureReason + "'" +
                       (replyMessage != null ? ", replyMessage='" + replyMessage + "'" : "") + "}";
            }
        }
    }
}