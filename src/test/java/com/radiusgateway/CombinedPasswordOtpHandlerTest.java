package com.radiusgateway;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.net.InetAddress;
import java.util.Arrays;

class CombinedPasswordOtpHandlerTest {
    
    private TestAuthBackend authBackend;
    private CombinedPasswordOtpHandler handler;
    
    @BeforeEach
    void setUp() {
        authBackend = new TestAuthBackend();
        handler = new CombinedPasswordOtpHandler(authBackend, 6);
    }
    
    @Test
    void testConstructorValidation() {
        assertThrows(IllegalArgumentException.class, () -> {
            new CombinedPasswordOtpHandler(null);
        });
        
        assertThrows(IllegalArgumentException.class, () -> {
            new CombinedPasswordOtpHandler(authBackend, 0);
        });
        
        assertThrows(IllegalArgumentException.class, () -> {
            new CombinedPasswordOtpHandler(authBackend, -1);
        });
    }
    
    @Test
    void testSuccessfulAuthentication() throws Exception {
        authBackend.setResult(AuthBackend.AuthResult.success("Welcome!"));
        
        RadiusHandler.RadiusRequest request = createTestRequest("testuser", "password123456");
        RadiusHandler.RadiusResponse response = handler.handleAccessRequest(request);
        
        assertEquals(RadiusPacket.ACCESS_ACCEPT, response.getCode());
        assertEquals("Welcome!", response.getReplyMessage());
        
        // Verify backend was called with correct parameters
        assertEquals("testuser", authBackend.lastUsername);
        assertEquals("password", authBackend.lastPassword);
        assertEquals("123456", authBackend.lastOtp);
    }
    
    @Test
    void testFailedAuthentication() throws Exception {
        authBackend.setResult(AuthBackend.AuthResult.failure("Invalid credentials"));
        
        RadiusHandler.RadiusRequest request = createTestRequest("testuser", "wrongpass123456");
        RadiusHandler.RadiusResponse response = handler.handleAccessRequest(request);
        
        assertEquals(RadiusPacket.ACCESS_REJECT, response.getCode());
        assertEquals("Authentication failed", response.getReplyMessage());
    }
    
    @Test
    void testMissingUsername() throws Exception {
        RadiusHandler.RadiusRequest request = createTestRequest(null, "password123456");
        RadiusHandler.RadiusResponse response = handler.handleAccessRequest(request);
        
        assertEquals(RadiusPacket.ACCESS_REJECT, response.getCode());
        assertEquals("Missing username", response.getReplyMessage());
    }
    
    @Test
    void testMissingPassword() throws Exception {
        RadiusHandler.RadiusRequest request = createTestRequest("testuser", null);
        RadiusHandler.RadiusResponse response = handler.handleAccessRequest(request);
        
        assertEquals(RadiusPacket.ACCESS_REJECT, response.getCode());
        assertEquals("Missing password", response.getReplyMessage());
    }
    
    @Test
    void testInvalidPasswordFormat() throws Exception {
        // Password too short to contain OTP
        RadiusHandler.RadiusRequest request = createTestRequest("testuser", "pass");
        RadiusHandler.RadiusResponse response = handler.handleAccessRequest(request);
        
        assertEquals(RadiusPacket.ACCESS_REJECT, response.getCode());
        assertEquals("Invalid password format", response.getReplyMessage());
    }
    
    @Test
    void testInvalidOtpFormat() throws Exception {
        // OTP contains non-digits
        RadiusHandler.RadiusRequest request = createTestRequest("testuser", "passwordabc123");
        RadiusHandler.RadiusResponse response = handler.handleAccessRequest(request);
        
        assertEquals(RadiusPacket.ACCESS_REJECT, response.getCode());
        assertEquals("Invalid password format", response.getReplyMessage());
    }
    
    @Test
    void testGetOtpLength() {
        assertEquals(6, handler.getOtpLength());
        
        CombinedPasswordOtpHandler handler3 = new CombinedPasswordOtpHandler(authBackend, 3);
        assertEquals(3, handler3.getOtpLength());
    }
    
    private RadiusHandler.RadiusRequest createTestRequest(String username, String password) throws Exception {
        RadiusPacket.RadiusAttribute[] attributes = {};
        if (username != null) {
            attributes = Arrays.copyOf(attributes, attributes.length + 1);
            attributes[attributes.length - 1] = new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, username);
        }
        
        if (password != null) {
            // For testing, we'll use the encrypted password directly
            // In real usage, this would be properly encrypted
            attributes = Arrays.copyOf(attributes, attributes.length + 1);
            attributes[attributes.length - 1] = new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, password.getBytes());
        }
        
        RadiusPacket packet = new RadiusPacket(
            RadiusPacket.ACCESS_REQUEST, 
            1, 
            new byte[16], 
            Arrays.asList(attributes)
        );
        
        return new TestRadiusRequest(packet, InetAddress.getLoopbackAddress(), "secret", password);
    }
    
    private static class TestAuthBackend implements AuthBackend {
        String lastUsername;
        String lastPassword;
        String lastOtp;
        AuthResult result = AuthResult.failure("Not configured");
        
        void setResult(AuthResult result) {
            this.result = result;
        }
        
        @Override
        public AuthResult authenticate(String username, String password) {
            return authenticate(username, password, null);
        }
        
        @Override
        public AuthResult authenticate(String username, String password, String otp) {
            this.lastUsername = username;
            this.lastPassword = password;
            this.lastOtp = otp;
            return result;
        }
    }
    
    private static class TestRadiusRequest extends RadiusHandler.RadiusRequest {
        private final String testPassword;
        
        TestRadiusRequest(RadiusPacket packet, InetAddress clientAddress, String sharedSecret, String testPassword) {
            super(packet, clientAddress, sharedSecret);
            this.testPassword = testPassword;
        }
        
        @Override
        public String decryptPassword() throws RadiusPacket.RadiusException {
            if (testPassword == null) {
                return null; // Return null for missing password test
            }
            return testPassword;
        }
    }
}