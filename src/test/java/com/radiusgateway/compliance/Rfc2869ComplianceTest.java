package com.radiusgateway.compliance;

import com.radiusgateway.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Nested;
import static org.junit.jupiter.api.Assertions.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.List;

/**
 * RFC 2869 Compliance Test Suite
 * 
 * Tests compliance with RFC 2869 - RADIUS Extensions
 * Focuses on Message-Authenticator attribute validation (§5.14)
 */
@DisplayName("RFC 2869 - RADIUS Extensions Compliance Tests")
class Rfc2869ComplianceTest {

    private RadiusSecurityValidator securityValidator;
    private String testSharedSecret;
    private String testClientAddress;

    @BeforeEach
    void setUp() {
        securityValidator = new RadiusSecurityValidatorImpl();
        testSharedSecret = "test-shared-secret-for-rfc2869-compliance";
        testClientAddress = "127.0.0.1";
    }

    @Nested
    @DisplayName("§5.14 - Message-Authenticator Attribute Compliance")
    class MessageAuthenticatorCompliance {

        @Test
        @DisplayName("§5.14.1 - Message-Authenticator Attribute Format")
        void testMessageAuthenticatorAttributeFormat() throws Exception {
            // RFC 2869 §5.14: Message-Authenticator is exactly 16 bytes
            
            List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, new byte[16]));
            
            // Test valid 16-byte Message-Authenticator
            byte[] validMessageAuth = new byte[16]; // Will be computed correctly
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR, validMessageAuth));
            
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            RadiusPacket packet = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, attributes);
            
            // Verify attribute presence and format
            RadiusPacket.RadiusAttribute msgAuthAttr = packet.getAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR);
            assertNotNull(msgAuthAttr, "Message-Authenticator attribute should be present");
            assertEquals(RadiusPacket.MESSAGE_AUTHENTICATOR, msgAuthAttr.getType(), 
                "Message-Authenticator attribute type must be 80");
            assertEquals(16, msgAuthAttr.getValue().length, 
                "Message-Authenticator must be exactly 16 bytes");
        }

        @Test
        @DisplayName("§5.14.2 - Message-Authenticator Length Validation")
        void testMessageAuthenticatorLengthValidation() throws Exception {
            // RFC 2869 §5.14: Message-Authenticator MUST be exactly 16 bytes
            
            List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, new byte[16]));
            
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            
            // Test invalid lengths
            int[] invalidLengths = {0, 1, 8, 15, 17, 20, 32};
            
            for (int invalidLength : invalidLengths) {
                List<RadiusPacket.RadiusAttribute> testAttributes = new ArrayList<>(attributes);
                byte[] invalidMessageAuth = new byte[invalidLength];
                testAttributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR, invalidMessageAuth));
                
                RadiusPacket invalidPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, testAttributes);
                
                // Should fail validation due to incorrect length
                assertThrows(RadiusValidationException.class, () -> {
                    securityValidator.validateAttributeBounds(invalidPacket);
                }, "Message-Authenticator with length " + invalidLength + " should fail validation");
            }
        }

        @Test
        @DisplayName("§5.14.3 - HMAC-MD5 Computation Compliance")
        void testHmacMd5ComputationCompliance() throws Exception {
            // RFC 2869 §5.14: Message-Authenticator = HMAC-MD5(packet with Message-Authenticator = 0, shared secret)
            
            List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, new byte[16]));
            
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            
            // Create packet without Message-Authenticator first
            RadiusPacket basePacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 42, authenticator, attributes);
            
            // Compute correct Message-Authenticator using manual HMAC-MD5 calculation
            byte[] correctMessageAuth = computeReferenceMessageAuthenticator(basePacket, testSharedSecret);
            
            // Add Message-Authenticator to packet
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR, correctMessageAuth));
            RadiusPacket packetWithMessageAuth = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 42, authenticator, attributes);
            
            // Verify our implementation matches RFC specification
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(packetWithMessageAuth, testSharedSecret, testClientAddress);
            }, "Correctly computed Message-Authenticator should pass validation");
            
            // Test with incorrect Message-Authenticator
            byte[] incorrectMessageAuth = new byte[16]; // All zeros
            List<RadiusPacket.RadiusAttribute> badAttributes = new ArrayList<>(attributes);
            badAttributes.set(badAttributes.size() - 1, 
                new RadiusPacket.RadiusAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR, incorrectMessageAuth));
            
            RadiusPacket badPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 42, authenticator, badAttributes);
            
            assertThrows(RadiusSecurityException.class, () -> {
                securityValidator.validatePacketSecurity(badPacket, testSharedSecret, testClientAddress);
            }, "Incorrect Message-Authenticator should fail validation");
        }

        @Test
        @DisplayName("§5.14.4 - Packet Modification for HMAC Computation")
        void testPacketModificationForHmac() throws Exception {
            // RFC 2869 §5.14: For HMAC computation, Message-Authenticator field must be set to zeros
            
            List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, new byte[16]));
            
            // Add Message-Authenticator with non-zero value
            byte[] originalMessageAuth = "original-16-byte".getBytes();
            // Pad to exactly 16 bytes
            byte[] paddedOriginalAuth = new byte[16];
            System.arraycopy(originalMessageAuth, 0, paddedOriginalAuth, 0, 
                Math.min(originalMessageAuth.length, 16));
            
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR, paddedOriginalAuth));
            
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            RadiusPacket originalPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, attributes);
            
            // Create packet with Message-Authenticator set to zeros (as required for HMAC computation)
            RadiusPacket modifiedPacket = createPacketWithZeroMessageAuth(originalPacket);
            
            // Verify Message-Authenticator is zeroed in modified packet
            RadiusPacket.RadiusAttribute modifiedMsgAuth = modifiedPacket.getAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR);
            assertNotNull(modifiedMsgAuth, "Modified packet should still have Message-Authenticator attribute");
            
            byte[] zeroCheck = new byte[16];
            assertArrayEquals(zeroCheck, modifiedMsgAuth.getValue(), 
                "Message-Authenticator should be zeroed for HMAC computation");
            
            // Verify other attributes remain unchanged
            assertEquals(originalPacket.getCode(), modifiedPacket.getCode(), "Packet code should be unchanged");
            assertEquals(originalPacket.getIdentifier(), modifiedPacket.getIdentifier(), "Packet identifier should be unchanged");
            assertArrayEquals(originalPacket.getAuthenticator(), modifiedPacket.getAuthenticator(), 
                "Request Authenticator should be unchanged");
            
            // Verify non-Message-Authenticator attributes are preserved
            assertEquals(originalPacket.getAttribute(RadiusPacket.USER_NAME).getStringValue(),
                modifiedPacket.getAttribute(RadiusPacket.USER_NAME).getStringValue(),
                "User-Name attribute should be preserved");
        }

        @Test
        @DisplayName("§5.14.5 - Message-Authenticator Attribute Occurrence")
        void testMessageAuthenticatorOccurrence() throws Exception {
            // RFC 2869 §5.14: Message-Authenticator MUST NOT appear more than once
            
            List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, new byte[16]));
            
            // Add multiple Message-Authenticator attributes (should fail)
            byte[] messageAuth1 = new byte[16];
            byte[] messageAuth2 = new byte[16];
            
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR, messageAuth1));
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR, messageAuth2));
            
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            RadiusPacket invalidPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, attributes);
            
            // Should fail validation due to duplicate Message-Authenticator attributes
            assertThrows(RadiusValidationException.class, () -> {
                securityValidator.validateAttributeBounds(invalidPacket);
            }, "Multiple Message-Authenticator attributes should fail validation");
        }

        @Test
        @DisplayName("§5.14.6 - Optional Message-Authenticator Handling")
        void testOptionalMessageAuthenticatorHandling() throws Exception {
            // RFC 2869 §5.14: Message-Authenticator is optional, packet should be valid without it
            
            List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, new byte[16]));
            // No Message-Authenticator attribute
            
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            RadiusPacket packetWithoutMessageAuth = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, attributes);
            
            // Should pass validation even without Message-Authenticator
            assertDoesNotThrow(() -> {
                securityValidator.validateAttributeBounds(packetWithoutMessageAuth);
            }, "Packet without Message-Authenticator should pass basic validation");
            
            // Security validator should handle missing Message-Authenticator gracefully
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(packetWithoutMessageAuth, testSharedSecret, testClientAddress);
            }, "Security validation should handle missing Message-Authenticator gracefully");
        }

        @Test
        @DisplayName("§5.14.7 - Constant-Time Comparison Security")
        void testConstantTimeComparisonSecurity() throws Exception {
            // RFC 2869 §5.14: HMAC comparison should use constant-time comparison to prevent timing attacks
            
            List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, new byte[16]));
            
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            
            // Create packet with correct Message-Authenticator
            RadiusPacket basePacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, attributes);
            byte[] correctMessageAuth = computeReferenceMessageAuthenticator(basePacket, testSharedSecret);
            
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR, correctMessageAuth));
            RadiusPacket validPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, attributes);
            
            // Test with slightly different Message-Authenticator (timing attack simulation)
            byte[] slightlyDifferentAuth = correctMessageAuth.clone();
            slightlyDifferentAuth[0] = (byte) (slightlyDifferentAuth[0] ^ 0x01); // Flip one bit
            
            List<RadiusPacket.RadiusAttribute> badAttributes = new ArrayList<>(attributes);
            badAttributes.set(badAttributes.size() - 1,
                new RadiusPacket.RadiusAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR, slightlyDifferentAuth));
            RadiusPacket invalidPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, badAttributes);
            
            // Both should fail in roughly the same time (constant-time comparison)
            long startTime1 = System.nanoTime();
            try {
                securityValidator.validatePacketSecurity(invalidPacket, testSharedSecret, testClientAddress);
                fail("Invalid Message-Authenticator should fail validation");
            } catch (RadiusSecurityException e) {
                // Expected
            }
            long time1 = System.nanoTime() - startTime1;
            
            // Test with completely different Message-Authenticator
            byte[] completelyDifferentAuth = new byte[16];
            for (int i = 0; i < 16; i++) {
                completelyDifferentAuth[i] = (byte) (0xFF ^ correctMessageAuth[i]);
            }
            
            badAttributes.set(badAttributes.size() - 1,
                new RadiusPacket.RadiusAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR, completelyDifferentAuth));
            RadiusPacket invalidPacket2 = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, badAttributes);
            
            long startTime2 = System.nanoTime();
            try {
                securityValidator.validatePacketSecurity(invalidPacket2, testSharedSecret, testClientAddress);
                fail("Invalid Message-Authenticator should fail validation");
            } catch (RadiusSecurityException e) {
                // Expected
            }
            long time2 = System.nanoTime() - startTime2;
            
            // Times should be similar (within reasonable variance) - indicates constant-time comparison
            double ratio = (double) Math.max(time1, time2) / Math.min(time1, time2);
            assertTrue(ratio < 10.0, // Allow up to 10x variance for system scheduling effects
                "Timing difference suggests non-constant-time comparison (ratio: " + ratio + ")");
        }
    }

    @Nested
    @DisplayName("Message-Authenticator Integration Tests")
    class MessageAuthenticatorIntegrationTests {

        @Test
        @DisplayName("End-to-End Message-Authenticator Validation")
        void testEndToEndMessageAuthenticatorValidation() throws Exception {
            // Test complete workflow with Message-Authenticator from packet creation to validation
            
            // Create NAS registry
            NasRegistry nasRegistry = new NasRegistry();
            nasRegistry.registerClient(java.net.InetAddress.getByName(testClientAddress), testSharedSecret, "Test NAS");
            
            // Create authentication handler
            AuthBackend authBackend = new AuthBackend() {
                @Override
                public AuthBackend.AuthResult authenticate(String username, String password) {
                    if ("testuser".equals(username) && "testpass".equals(password)) {
                        return AuthBackend.AuthResult.success("Authentication successful");
                    }
                    return AuthBackend.AuthResult.failure("Invalid credentials", "Authentication failed");
                }
                
                @Override
                public AuthBackend.AuthResult authenticate(String username, String password, String otp) {
                    if ("testuser".equals(username) && "testpass".equals(password)) {
                        return AuthBackend.AuthResult.success("Authentication successful");
                    }
                    return AuthBackend.AuthResult.failure("Invalid credentials", "Authentication failed");
                }
            };
            
            RadiusHandler handler = new CombinedPasswordOtpHandler(authBackend, 6);
            
            // Create server with security validator (use available port for testing)
            RadiusServer server = new RadiusServer(1813, nasRegistry, handler, securityValidator); // Use port 1813 for testing
            
            try {
                server.start();
                
                // Create request packet with Message-Authenticator
                List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
                attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
                
                // Encrypt password
                byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
                byte[] encryptedPassword = RadiusCodec.encryptPassword("testpass123456", authenticator, testSharedSecret);
                attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, encryptedPassword));
                
                // Create base packet for Message-Authenticator computation
                RadiusPacket basePacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 123, authenticator, attributes);
                byte[] messageAuth = computeReferenceMessageAuthenticator(basePacket, testSharedSecret);
                
                // Add Message-Authenticator to final packet
                attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR, messageAuth));
                RadiusPacket requestPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 123, authenticator, attributes);
                
                // Verify packet passes all security validations
                assertDoesNotThrow(() -> {
                    securityValidator.validatePacketSecurity(requestPacket, testSharedSecret, testClientAddress);
                }, "Complete packet with Message-Authenticator should pass all security validations");
                
            } finally {
                server.stop();
            }
        }
    }

    // Helper methods

    /**
     * Creates a reference HMAC-MD5 computation for Message-Authenticator validation
     * This serves as a reference implementation to verify our security validator
     */
    private byte[] computeReferenceMessageAuthenticator(RadiusPacket packet, String sharedSecret) throws Exception {
        // Create packet copy with Message-Authenticator set to zeros
        RadiusPacket tempPacket = createPacketWithZeroMessageAuth(packet);
        
        // Encode packet for HMAC computation
        byte[] packetData = tempPacket.encode();
        
        // Compute HMAC-MD5
        Mac hmacMd5 = Mac.getInstance("HmacMD5");
        SecretKeySpec secretKey = new SecretKeySpec(sharedSecret.getBytes(), "HmacMD5");
        hmacMd5.init(secretKey);
        
        return hmacMd5.doFinal(packetData);
    }

    /**
     * Creates a copy of packet with Message-Authenticator attribute set to zeros
     */
    private RadiusPacket createPacketWithZeroMessageAuth(RadiusPacket originalPacket) {
        List<RadiusPacket.RadiusAttribute> modifiedAttributes = new ArrayList<>();
        
        // Copy all attributes, but zero out Message-Authenticator if present
        for (RadiusPacket.RadiusAttribute attr : originalPacket.getAttributes()) {
            if (attr.getType() == RadiusPacket.MESSAGE_AUTHENTICATOR) {
                // Replace with zero-filled Message-Authenticator
                modifiedAttributes.add(new RadiusPacket.RadiusAttribute(
                    RadiusPacket.MESSAGE_AUTHENTICATOR, new byte[16]));
            } else {
                modifiedAttributes.add(attr);
            }
        }
        
        // If original packet doesn't have Message-Authenticator, add zero-filled one
        boolean hasMessageAuth = originalPacket.getAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR) != null;
        if (!hasMessageAuth) {
            modifiedAttributes.add(new RadiusPacket.RadiusAttribute(
                RadiusPacket.MESSAGE_AUTHENTICATOR, new byte[16]));
        }
        
        return new RadiusPacket(
            originalPacket.getCode(),
            originalPacket.getIdentifier(),
            originalPacket.getAuthenticator(),
            modifiedAttributes
        );
    }
}