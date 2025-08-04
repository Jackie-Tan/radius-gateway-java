package com.radiusgateway;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.util.ArrayList;

class RadiusCodecTest {
    
    @Test
    void testGenerateRequestAuthenticator() {
        byte[] auth1 = RadiusCodec.generateRequestAuthenticator();
        byte[] auth2 = RadiusCodec.generateRequestAuthenticator();
        
        assertEquals(16, auth1.length);
        assertEquals(16, auth2.length);
        assertFalse(java.util.Arrays.equals(auth1, auth2)); // Should be random
    }
    
    @Test
    void testPasswordEncryptionDecryption() throws RadiusPacket.RadiusException {
        String originalPassword = "mySecretPassword";
        String sharedSecret = "testSecret";
        byte[] requestAuth = RadiusCodec.generateRequestAuthenticator();
        
        byte[] encrypted = RadiusCodec.encryptPassword(originalPassword, requestAuth, sharedSecret);
        byte[] decrypted = RadiusCodec.decryptPassword(encrypted, requestAuth, sharedSecret);
        
        assertEquals(originalPassword, new String(decrypted));
    }
    
    @Test
    void testPasswordEncryptionLength() throws RadiusPacket.RadiusException {
        String password = "test";
        String sharedSecret = "secret";
        byte[] requestAuth = new byte[16];
        
        byte[] encrypted = RadiusCodec.encryptPassword(password, requestAuth, sharedSecret);
        
        // Should be padded to multiple of 16
        assertEquals(16, encrypted.length);
        assertTrue(encrypted.length % 16 == 0);
    }
    
    @Test
    void testDecryptInvalidLength() {
        String sharedSecret = "secret";
        byte[] requestAuth = new byte[16];
        byte[] invalidEncrypted = new byte[15]; // Not multiple of 16
        
        assertThrows(RadiusPacket.RadiusException.class, () -> {
            RadiusCodec.decryptPassword(invalidEncrypted, requestAuth, sharedSecret);
        });
    }
    
    @Test
    void testComputeResponseAuthenticator() throws RadiusPacket.RadiusException {
        byte[] requestAuth = RadiusCodec.generateRequestAuthenticator();
        String sharedSecret = "testSecret";
        
        RadiusPacket responsePacket = new RadiusPacket(
            RadiusPacket.ACCESS_ACCEPT, 42, new byte[16], new ArrayList<>());
        
        byte[] responseAuth = RadiusCodec.computeResponseAuthenticator(
            responsePacket, requestAuth, sharedSecret);
        
        assertEquals(16, responseAuth.length);
        
        // Computing again should give same result
        byte[] responseAuth2 = RadiusCodec.computeResponseAuthenticator(
            responsePacket, requestAuth, sharedSecret);
        
        assertArrayEquals(responseAuth, responseAuth2);
    }
    
    @Test
    void testHexConversion() {
        byte[] bytes = {(byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF};
        String hex = RadiusCodec.bytesToHex(bytes);
        
        assertEquals("0123456789abcdef", hex);
        
        byte[] converted = RadiusCodec.hexToBytes(hex);
        assertArrayEquals(bytes, converted);
    }
    
    @Test
    void testValidateRequestAuthenticator() throws RadiusPacket.RadiusException {
        // Test Request Authenticator validation (RFC 2865 §3)
        
        // Test 1: All-zero authenticator should be invalid for Access-Request
        RadiusPacket invalidPacket = new RadiusPacket(
            RadiusPacket.ACCESS_REQUEST, 1, new byte[16], new ArrayList<>());
        
        boolean result = RadiusCodec.validateRequestAuthenticator(invalidPacket, "secret");
        assertFalse(result); // All-zero authenticator is invalid for Access-Request
        
        // Test 2: Non-zero authenticator should be valid for Access-Request
        byte[] nonZeroAuth = new byte[16];
        nonZeroAuth[0] = 1; // Make it non-zero
        RadiusPacket validPacket = new RadiusPacket(
            RadiusPacket.ACCESS_REQUEST, 1, nonZeroAuth, new ArrayList<>());
        
        result = RadiusCodec.validateRequestAuthenticator(validPacket, "secret");
        assertTrue(result); // Non-zero authenticator is valid for Access-Request
    }
}