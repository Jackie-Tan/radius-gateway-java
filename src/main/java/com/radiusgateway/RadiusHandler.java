package com.radiusgateway;

import java.net.InetAddress;

public interface RadiusHandler {
    
    RadiusResponse handleAccessRequest(RadiusRequest request);
    
    public static class RadiusRequest {
        private final RadiusPacket packet;
        private final InetAddress clientAddress;
        private final String sharedSecret;
        private final String username;
        private final byte[] encryptedPassword;
        
        public RadiusRequest(RadiusPacket packet, InetAddress clientAddress, String sharedSecret) {
            this.packet = packet;
            this.clientAddress = clientAddress;
            this.sharedSecret = sharedSecret;
            this.username = packet.getStringAttribute(RadiusPacket.USER_NAME);
            this.encryptedPassword = packet.getBinaryAttribute(RadiusPacket.USER_PASSWORD);
        }
        
        public RadiusPacket getPacket() {
            return packet;
        }
        
        public InetAddress getClientAddress() {
            return clientAddress;
        }
        
        public String getSharedSecret() {
            return sharedSecret;
        }
        
        public String getUsername() {
            return username;
        }
        
        public byte[] getEncryptedPassword() {
            return encryptedPassword != null ? encryptedPassword.clone() : null;
        }
        
        public String decryptPassword() throws RadiusPacket.RadiusException {
            if (encryptedPassword == null) {
                throw new RadiusPacket.RadiusException("No User-Password attribute found");
            }
            
            byte[] decrypted = RadiusCodec.decryptPassword(
                encryptedPassword, 
                packet.getAuthenticator(), 
                sharedSecret
            );
            
            return new String(decrypted);
        }
    }
    
    public static class RadiusResponse {
        private final int code;
        private final String replyMessage;
        private final byte[] state;
        
        private RadiusResponse(int code, String replyMessage, byte[] state) {
            this.code = code;
            this.replyMessage = replyMessage;
            this.state = state != null ? state.clone() : null;
        }
        
        public static RadiusResponse accept() {
            return new RadiusResponse(RadiusPacket.ACCESS_ACCEPT, null, null);
        }
        
        public static RadiusResponse accept(String replyMessage) {
            return new RadiusResponse(RadiusPacket.ACCESS_ACCEPT, replyMessage, null);
        }
        
        public static RadiusResponse reject() {
            return new RadiusResponse(RadiusPacket.ACCESS_REJECT, null, null);
        }
        
        public static RadiusResponse reject(String replyMessage) {
            return new RadiusResponse(RadiusPacket.ACCESS_REJECT, replyMessage, null);
        }
        
        public static RadiusResponse challenge(String replyMessage, byte[] state) {
            return new RadiusResponse(RadiusPacket.ACCESS_CHALLENGE, replyMessage, state);
        }
        
        public int getCode() {
            return code;
        }
        
        public String getReplyMessage() {
            return replyMessage;
        }
        
        public byte[] getState() {
            return state != null ? state.clone() : null;
        }
    }
}