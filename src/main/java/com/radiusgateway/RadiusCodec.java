package com.radiusgateway;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class RadiusCodec {
    
    private static final SecureRandom RANDOM = new SecureRandom();
    
    public static byte[] generateRequestAuthenticator() {
        byte[] authenticator = new byte[16];
        RANDOM.nextBytes(authenticator);
        return authenticator;
    }
    
    public static byte[] computeResponseAuthenticator(RadiusPacket responsePacket, 
                                                     byte[] requestAuthenticator, 
                                                     String sharedSecret) throws RadiusPacket.RadiusException {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            
            // Create response packet bytes with zero authenticator
            byte[] packetBytes = responsePacket.encode();
            
            // Replace authenticator field with request authenticator
            System.arraycopy(requestAuthenticator, 0, packetBytes, 4, 16);
            
            md.update(packetBytes);
            md.update(sharedSecret.getBytes());
            
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RadiusPacket.RadiusException("MD5 algorithm not available", e);
        }
    }
    
    public static boolean validateRequestAuthenticator(RadiusPacket packet, String sharedSecret) throws RadiusPacket.RadiusException {
        try {
            byte[] authenticator = packet.getAuthenticator();
            if (authenticator == null || authenticator.length != 16) {
                return false;
            }
            
            // For Access-Request packets, Request Authenticator should be random (non-zero)
            if (packet.getCode() == RadiusPacket.ACCESS_REQUEST) {
                // Check that authenticator is not all zeros
                boolean allZero = true;
                for (byte b : authenticator) {
                    if (b != 0) {
                        allZero = false;
                        break;
                    }
                }
                return !allZero; // Valid if not all zeros
            }
            
            // For other packet types (Access-Accept, Access-Reject, etc.)
            // Response Authenticator = MD5(Code + ID + Length + Request Authenticator + Response Attributes + Secret)
            return validateResponseAuthenticator(packet, sharedSecret);
            
        } catch (Exception e) {
            throw new RadiusPacket.RadiusException("Request Authenticator validation failed", e);
        }
    }
    
    private static boolean validateResponseAuthenticator(RadiusPacket packet, String sharedSecret) throws RadiusPacket.RadiusException {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            
            // Create packet bytes with zero authenticator for computation
            byte[] packetBytes = packet.encode();
            
            // Zero out the authenticator field for computation
            for (int i = 4; i < 20; i++) {
                packetBytes[i] = 0;
            }
            
            md.update(packetBytes);
            md.update(sharedSecret.getBytes());
            
            byte[] computedAuth = md.digest();
            byte[] receivedAuth = packet.getAuthenticator();
            
            // Compare computed and received authenticators
            return java.util.Arrays.equals(computedAuth, receivedAuth);
            
        } catch (NoSuchAlgorithmException e) {
            throw new RadiusPacket.RadiusException("MD5 algorithm not available", e);
        }
    }
    
    public static byte[] decryptPassword(byte[] encryptedPassword, 
                                       byte[] requestAuthenticator, 
                                       String sharedSecret) throws RadiusPacket.RadiusException {
        try {
            if (encryptedPassword.length == 0 || encryptedPassword.length % 16 != 0) {
                throw new RadiusPacket.RadiusException("Invalid encrypted password length: " + encryptedPassword.length);
            }
            
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] result = new byte[encryptedPassword.length];
            
            byte[] b = new byte[16];
            System.arraycopy(requestAuthenticator, 0, b, 0, 16);
            
            for (int i = 0; i < encryptedPassword.length; i += 16) {
                md.reset();
                md.update(sharedSecret.getBytes());
                md.update(b);
                byte[] hash = md.digest();
                
                for (int j = 0; j < 16 && i + j < encryptedPassword.length; j++) {
                    result[i + j] = (byte) (encryptedPassword[i + j] ^ hash[j]);
                    b[j] = encryptedPassword[i + j];
                }
            }
            
            // Remove null padding
            int actualLength = result.length;
            for (int i = result.length - 1; i >= 0; i--) {
                if (result[i] == 0) {
                    actualLength = i;
                } else {
                    break;
                }
            }
            
            return Arrays.copyOf(result, actualLength);
        } catch (NoSuchAlgorithmException e) {
            throw new RadiusPacket.RadiusException("MD5 algorithm not available", e);
        }
    }
    
    public static byte[] encryptPassword(String password, 
                                       byte[] requestAuthenticator, 
                                       String sharedSecret) throws RadiusPacket.RadiusException {
        try {
            byte[] passwordBytes = password.getBytes();
            
            // Pad to multiple of 16 bytes
            int paddedLength = ((passwordBytes.length + 15) / 16) * 16;
            byte[] paddedPassword = new byte[paddedLength];
            System.arraycopy(passwordBytes, 0, paddedPassword, 0, passwordBytes.length);
            
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] result = new byte[paddedLength];
            
            byte[] b = new byte[16];
            System.arraycopy(requestAuthenticator, 0, b, 0, 16);
            
            for (int i = 0; i < paddedLength; i += 16) {
                md.reset();
                md.update(sharedSecret.getBytes());
                md.update(b);
                byte[] hash = md.digest();
                
                for (int j = 0; j < 16; j++) {
                    result[i + j] = (byte) (paddedPassword[i + j] ^ hash[j]);
                    b[j] = result[i + j];
                }
            }
            
            return result;
        } catch (NoSuchAlgorithmException e) {
            throw new RadiusPacket.RadiusException("MD5 algorithm not available", e);
        }
    }
    
    public static byte[] computeMessageAuthenticator(RadiusPacket packet, 
                                                   String sharedSecret) throws RadiusPacket.RadiusException {
        // TODO: Implement Message-Authenticator (AVP 80) per RFC 2869 §5.14
        // This is a medium priority security feature
        throw new RadiusPacket.RadiusException("Message-Authenticator not implemented yet");
    }
    
    public static boolean validateMessageAuthenticator(RadiusPacket packet, 
                                                     String sharedSecret) throws RadiusPacket.RadiusException {
        // TODO: Implement Message-Authenticator validation per RFC 2869 §5.14
        // For now, return true if no Message-Authenticator is present
        RadiusPacket.RadiusAttribute msgAuth = packet.getAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR);
        if (msgAuth == null) {
            return true; // No Message-Authenticator to validate
        }
        
        // TODO: Validate the Message-Authenticator
        throw new RadiusPacket.RadiusException("Message-Authenticator validation not implemented yet");
    }
    
    public static String bytesToHex(byte[] bytes) {
        return RadiusUtils.bytesToHex(bytes);
    }
    
    public static byte[] hexToBytes(String hex) {
        return RadiusUtils.hexToBytes(hex);
    }
}