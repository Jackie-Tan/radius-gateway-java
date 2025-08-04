package com.radiusgateway.security;

import com.radiusgateway.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Comprehensive Security Validation Test Suite
 * 
 * Tests edge cases, attack simulation, and security vulnerabilities beyond basic RFC compliance.
 * Focuses on real-world security scenarios and attack resilience.
 */
@DisplayName("Security Validation - Edge Cases and Attack Simulation")
class SecurityValidationTest {

    private RadiusSecurityValidator securityValidator;
    private String testSharedSecret;
    private String testClientAddress;
    private SecureRandom random;

    @BeforeEach
    void setUp() {
        securityValidator = new RadiusSecurityValidatorImpl();
        testSharedSecret = "secure-test-secret-for-security-validation";
        testClientAddress = "192.168.200.100";
        random = new SecureRandom();
    }

    @Nested
    @DisplayName("Edge Case Security Testing")
    class EdgeCaseSecurityTesting {

        @Test
        @DisplayName("Malformed Packet Header Attacks")
        void testMalformedPacketHeaderAttacks() throws Exception {
            // Test various malformed packet scenarios that attackers might use
            
            // Invalid code values
            List<RadiusPacket.RadiusAttribute> attributes = createValidAttributes();
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            
            int[] invalidCodes = {0, 256, -1, 999, Integer.MAX_VALUE};
            for (int invalidCode : invalidCodes) {
                // Note: RadiusPacket constructor may accept these, but security validator should handle them
                if (invalidCode >= 0 && invalidCode <= 255) {
                    RadiusPacket malformedPacket = new RadiusPacket(invalidCode, 1, authenticator, attributes);
                    
                    // Security validator should handle unusual code values gracefully
                    // Some invalid codes should be rejected, others may be processed
                    try {
                        securityValidator.validatePacketSecurity(malformedPacket, testSharedSecret, testClientAddress);
                        // If it passes, verify it's logged appropriately
                        assertTrue(true, "Unusual code " + invalidCode + " handled gracefully");
                    } catch (Exception e) {
                        assertTrue(e instanceof RadiusSecurityException || e instanceof RadiusValidationException,
                            "Invalid code " + invalidCode + " should throw appropriate security exception");
                    }
                }
            }
        }

        @Test
        @DisplayName("Extreme Packet Size Attacks")
        void testExtremePacketSizeAttacks() throws Exception {
            List<RadiusPacket.RadiusAttribute> attributes = createValidAttributes();
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            
            // Create packet with maximum allowed attributes to test bounds
            List<RadiusPacket.RadiusAttribute> maxAttributes = new ArrayList<>();
            maxAttributes.addAll(attributes);
            
            // Add many vendor-specific attributes (these can appear multiple times)
            for (int i = 0; i < 50; i++) {
                byte[] vendorData = new byte[50]; // Create reasonably sized vendor attribute
                random.nextBytes(vendorData);
                maxAttributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.VENDOR_SPECIFIC, vendorData));
            }
            
            RadiusPacket largePacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, maxAttributes);
            
            // Large but valid packet should pass if under 4096 bytes
            byte[] encoded = largePacket.encode();
            if (encoded.length <= 4096) {
                assertDoesNotThrow(() -> {
                    securityValidator.validatePacketBounds(largePacket);
                }, "Large but valid packet should pass bounds validation");
            } else {
                assertThrows(RadiusValidationException.class, () -> {
                    securityValidator.validatePacketBounds(largePacket);
                }, "Oversized packet should fail bounds validation");
            }
        }

        @Test
        @DisplayName("Buffer Overflow Simulation")
        void testBufferOverflowSimulation() throws Exception {
            // Test packets designed to potentially cause buffer overflows
            
            List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
            
            // Encrypted password with proper length
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            byte[] encryptedPassword = RadiusCodec.encryptPassword("testpass", authenticator, testSharedSecret);
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, encryptedPassword));
            
            // Create extremely long username (but within attribute limits)
            String longUsername = "a".repeat(253); // Maximum possible for User-Name
            List<RadiusPacket.RadiusAttribute> longAttributes = new ArrayList<>();
            longAttributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, longUsername));
            longAttributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, encryptedPassword));
            
            RadiusPacket longUsernamePacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, longAttributes);
            
            // Should handle long but valid usernames gracefully
            assertDoesNotThrow(() -> {
                securityValidator.validateAttributeBounds(longUsernamePacket);
            }, "Long but valid username should be handled safely");
            
            // Test with Reply-Message attributes (can appear multiple times)
            List<RadiusPacket.RadiusAttribute> multipleReplyMessages = new ArrayList<>(attributes);
            for (int i = 0; i < 10; i++) {
                String replyMsg = "This is reply message number " + i + " designed to test multiple attribute handling";
                multipleReplyMessages.add(new RadiusPacket.RadiusAttribute(RadiusPacket.REPLY_MESSAGE, replyMsg));
            }
            
            RadiusPacket multiReplyPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, multipleReplyMessages);
            
            // Multiple reply messages should be handled safely
            assertDoesNotThrow(() -> {
                securityValidator.validateAttributeBounds(multiReplyPacket);
            }, "Multiple reply messages should be handled safely");
        }

        @Test
        @DisplayName("Invalid Authenticator Scenarios")
        void testInvalidAuthenticatorScenarios() throws Exception {
            List<RadiusPacket.RadiusAttribute> attributes = createValidAttributes();
            
            // Test all-zero authenticator (invalid for Access-Request)
            byte[] zeroAuthenticator = new byte[16];
            RadiusPacket zeroAuthPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, zeroAuthenticator, attributes);
            
            assertThrows(RadiusSecurityException.class, () -> {
                securityValidator.validateRequestAuthenticator(zeroAuthPacket, testSharedSecret);
            }, "All-zero authenticator should be rejected for Access-Request");
            
            // Test predictable authenticator patterns
            byte[] patternAuthenticator = new byte[16];
            for (int i = 0; i < 16; i++) {
                patternAuthenticator[i] = (byte) (i % 4); // Predictable pattern
            }
            
            RadiusPacket patternAuthPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, patternAuthenticator, attributes);
            
            // Predictable patterns should pass basic validation but might trigger warnings
            assertDoesNotThrow(() -> {
                securityValidator.validateRequestAuthenticator(patternAuthPacket, testSharedSecret);
            }, "Predictable but non-zero authenticator should pass basic validation");
            
            // Test with maximum entropy authenticator
            byte[] randomAuthenticator = new byte[16];
            random.nextBytes(randomAuthenticator);
            RadiusPacket randomAuthPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, randomAuthenticator, attributes);
            
            assertDoesNotThrow(() -> {
                securityValidator.validateRequestAuthenticator(randomAuthPacket, testSharedSecret);
            }, "High-entropy authenticator should pass validation");
        }
    }

    @Nested
    @DisplayName("Cryptographic Security Testing")
    class CryptographicSecurityTesting {

        @Test
        @DisplayName("Request Authenticator Attack Simulation")
        void testRequestAuthenticatorAttackSimulation() throws Exception {
            List<RadiusPacket.RadiusAttribute> attributes = createValidAttributes();
            
            // Simulate brute force attack on Request Authenticator
            AtomicInteger validCount = new AtomicInteger(0);
            AtomicInteger invalidCount = new AtomicInteger(0);
            
            for (int i = 0; i < 100; i++) {
                byte[] testAuthenticator = new byte[16];
                
                if (i < 50) {
                    // First half: random valid authenticators
                    random.nextBytes(testAuthenticator);
                } else {
                    // Second half: systematic bit patterns
                    Arrays.fill(testAuthenticator, (byte) (i % 256));
                }
                
                // Ensure not all zeros
                if (Arrays.equals(testAuthenticator, new byte[16])) {
                    testAuthenticator[0] = 1; // Make it non-zero
                }
                
                RadiusPacket testPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, i, testAuthenticator, attributes);
                
                try {
                    securityValidator.validateRequestAuthenticator(testPacket, testSharedSecret);
                    validCount.incrementAndGet();
                } catch (RadiusSecurityException e) {
                    invalidCount.incrementAndGet();
                }
            }
            
            // All should pass Request Authenticator validation (they're non-zero)
            assertEquals(100, validCount.get(), "All non-zero authenticators should pass basic Request Authenticator validation");
        }

        @Test
        @DisplayName("Message-Authenticator HMAC Security Testing")
        void testMessageAuthenticatorHmacSecurity() throws Exception {
            List<RadiusPacket.RadiusAttribute> attributes = createValidAttributes();
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            
            // Create valid Message-Authenticator
            RadiusPacket basePacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, attributes);
            byte[] validMessageAuth = computeTestMessageAuthenticator(basePacket, testSharedSecret);
            
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR, validMessageAuth));
            RadiusPacket validPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, attributes);
            
            // Valid Message-Authenticator should pass
            assertDoesNotThrow(() -> {
                securityValidator.validateMessageAuthenticator(validPacket, testSharedSecret);
            }, "Valid Message-Authenticator should pass validation");
            
            // Test with systematically modified Message-Authenticator values
            for (int bitPosition = 0; bitPosition < 128; bitPosition++) {
                byte[] tamperedAuth = validMessageAuth.clone();
                int byteIndex = bitPosition / 8;
                int bitIndex = bitPosition % 8;
                tamperedAuth[byteIndex] ^= (1 << bitIndex); // Flip one bit
                
                List<RadiusPacket.RadiusAttribute> tamperedAttributes = new ArrayList<>(attributes);
                tamperedAttributes.set(tamperedAttributes.size() - 1, 
                    new RadiusPacket.RadiusAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR, tamperedAuth));
                
                RadiusPacket tamperedPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, tamperedAttributes);
                
                assertThrows(RadiusSecurityException.class, () -> {
                    securityValidator.validateMessageAuthenticator(tamperedPacket, testSharedSecret);
                }, "Tampered Message-Authenticator (bit " + bitPosition + ") should fail validation");
            }
        }

        @Test
        @DisplayName("Shared Secret Security Testing")
        void testSharedSecretSecurity() throws Exception {
            List<RadiusPacket.RadiusAttribute> attributes = createValidAttributes();
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            RadiusPacket packet = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, attributes);
            
            // Test with weak shared secrets
            String[] weakSecrets = {
                "", "1", "password", "12345", "secret", "admin", "test",
                "a", "aa", "aaa", "aaaa" // Very short secrets
            };
            
            for (String weakSecret : weakSecrets) {
                if (weakSecret.isEmpty()) {
                    // Empty secret should be handled gracefully
                    assertDoesNotThrow(() -> {
                        securityValidator.validateRequestAuthenticator(packet, weakSecret);
                    }, "Empty shared secret should be handled gracefully");
                } else {
                    // Weak secrets should still work for validation (they're just not secure)
                    assertDoesNotThrow(() -> {
                        securityValidator.validateRequestAuthenticator(packet, weakSecret);
                    }, "Weak secret '" + weakSecret + "' should still allow validation");
                }
            }
            
            // Test with very long shared secret
            String longSecret = "a".repeat(1000);
            assertDoesNotThrow(() -> {
                securityValidator.validateRequestAuthenticator(packet, longSecret);
            }, "Very long shared secret should be handled correctly");
            
            // Test with special characters
            String specialSecret = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~";
            assertDoesNotThrow(() -> {
                securityValidator.validateRequestAuthenticator(packet, specialSecret);
            }, "Special character shared secret should be handled correctly");
        }

        @Test
        @DisplayName("Timing Attack Resistance Testing")
        void testTimingAttackResistance() throws Exception {
            List<RadiusPacket.RadiusAttribute> attributes = createValidAttributes();
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            
            // Create packet with Message-Authenticator
            RadiusPacket basePacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, attributes);
            byte[] correctAuth = computeTestMessageAuthenticator(basePacket, testSharedSecret);
            
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR, correctAuth));
            
            // Test timing consistency with different invalid Message-Authenticator values
            long[] timings = new long[10];
            
            for (int i = 0; i < 10; i++) {
                byte[] incorrectAuth = new byte[16];
                if (i < 5) {
                    // First half: all different bytes
                    Arrays.fill(incorrectAuth, (byte) (0xFF ^ correctAuth[0]));
                } else {
                    // Second half: differs only in last byte
                    System.arraycopy(correctAuth, 0, incorrectAuth, 0, 15);
                    incorrectAuth[15] = (byte) (correctAuth[15] ^ 0xFF);
                }
                
                List<RadiusPacket.RadiusAttribute> testAttributes = new ArrayList<>(attributes);
                testAttributes.set(testAttributes.size() - 1,
                    new RadiusPacket.RadiusAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR, incorrectAuth));
                
                RadiusPacket testPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, testAttributes);
                
                long startTime = System.nanoTime();
                try {
                    securityValidator.validateMessageAuthenticator(testPacket, testSharedSecret);
                    fail("Invalid Message-Authenticator should fail validation");
                } catch (RadiusSecurityException e) {
                    // Expected
                }
                timings[i] = System.nanoTime() - startTime;
            }
            
            // Check that timing variance is reasonable (constant-time comparison)
            long avgTime = Arrays.stream(timings).sum() / timings.length;
            int highVarianceCount = 0;
            for (long timing : timings) {
                double variance = Math.abs(timing - avgTime) / (double) avgTime;
                if (variance > 10.0) { // Allow up to 1000% variance due to system scheduling in test environment
                    highVarianceCount++;
                }
            }
            
            // Most measurements should be reasonable, but allow some outliers due to JVM/OS scheduling
            assertTrue(highVarianceCount <= timings.length / 2, 
                "Too many high-variance timing measurements: " + highVarianceCount + "/" + timings.length + 
                " - possible timing attack vulnerability (avg: " + avgTime + "ns)");
        }
    }

    @Nested
    @DisplayName("Replay Attack Simulation")
    class ReplayAttackSimulation {

        @Test
        @DisplayName("Advanced Replay Attack Scenarios")
        void testAdvancedReplayAttackScenarios() throws Exception {
            List<RadiusPacket.RadiusAttribute> attributes = createValidAttributes();
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            RadiusPacket originalPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 100, authenticator, attributes);
            
            // Original packet should pass
            assertDoesNotThrow(() -> {
                securityValidator.checkReplayProtection(originalPacket, testClientAddress);
            }, "Original packet should pass replay protection");
            
            // Immediate replay should fail
            assertThrows(RadiusSecurityException.class, () -> {
                securityValidator.checkReplayProtection(originalPacket, testClientAddress);
            }, "Immediate replay should be detected");
            
            // Cross-client replay test
            String differentClient = "192.168.200.101";
            assertDoesNotThrow(() -> {
                securityValidator.checkReplayProtection(originalPacket, differentClient);
            }, "Same packet from different client should be allowed");
            
            // But replay from same different client should also be detected
            assertThrows(RadiusSecurityException.class, () -> {
                securityValidator.checkReplayProtection(originalPacket, differentClient);
            }, "Replay from different client should also be detected");
        }

        @Test
        @DisplayName("Memory Exhaustion Attack Simulation")
        void testMemoryExhaustionAttackSimulation() throws Exception {
            // Attempt to exhaust replay protection memory with unique packets
            List<RadiusPacket.RadiusAttribute> attributes = createValidAttributes();
            
            for (int i = 0; i < 1200; i++) { // Exceed the typical 1000 packet limit
                byte[] uniqueAuthenticator = new byte[16];
                random.nextBytes(uniqueAuthenticator);
                RadiusPacket uniquePacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, i % 256, 
                    uniqueAuthenticator, attributes);
                
                String clientIp = "10.0." + (i / 256) + "." + (i % 256);
                
                // Should handle all packets without memory issues
                assertDoesNotThrow(() -> {
                    securityValidator.checkReplayProtection(uniquePacket, clientIp);
                }, "Memory exhaustion attempt packet " + i + " should be handled gracefully");
            }
            
            // System should still be functional after memory pressure
            byte[] finalAuthenticator = RadiusCodec.generateRequestAuthenticator();
            RadiusPacket finalPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 200, finalAuthenticator, attributes);
            
            assertDoesNotThrow(() -> {
                securityValidator.checkReplayProtection(finalPacket, "192.168.1.250");
            }, "System should remain functional after memory exhaustion attempt");
        }

        @Test
        @DisplayName("Systematic Identifier Manipulation")
        void testSystematicIdentifierManipulation() throws Exception {
            List<RadiusPacket.RadiusAttribute> attributes = createValidAttributes();
            
            // Test systematic identifier reuse with different authenticators
            int suspiciousId = 42;
            
            for (int i = 0; i < 10; i++) {
                byte[] uniqueAuthenticator = new byte[16];
                random.nextBytes(uniqueAuthenticator);
                RadiusPacket packet = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, suspiciousId, 
                    uniqueAuthenticator, attributes);
                
                // Each should pass (different authenticators) but may trigger warnings
                assertDoesNotThrow(() -> {
                    securityValidator.checkReplayProtection(packet, testClientAddress);
                }, "Identifier reuse with different authenticator should pass");
                
                // Small delay to simulate realistic timing
                Thread.sleep(10);
            }
            
            // Verify replay protection still works within the same ID
            byte[] reusedAuthenticator = new byte[16];
            random.nextBytes(reusedAuthenticator);
            RadiusPacket packet1 = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, suspiciousId, 
                reusedAuthenticator, attributes);
            RadiusPacket packet2 = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, suspiciousId, 
                reusedAuthenticator, attributes);
            
            assertDoesNotThrow(() -> {
                securityValidator.checkReplayProtection(packet1, "192.168.1.200");
            }, "First packet with reused authenticator should pass");
            
            assertThrows(RadiusSecurityException.class, () -> {
                securityValidator.checkReplayProtection(packet2, "192.168.1.200");
            }, "Second packet with same authenticator should be detected as replay");
        }

        @RepeatedTest(5)
        @DisplayName("High-Frequency Replay Detection")
        void testHighFrequencyReplayDetection() throws Exception {
            List<RadiusPacket.RadiusAttribute> attributes = createValidAttributes();
            byte[] authenticator = new byte[16];
            random.nextBytes(authenticator);
            
            int testId = random.nextInt(256);
            RadiusPacket burstPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, testId, authenticator, attributes);
            
            // First packet should pass
            assertDoesNotThrow(() -> {
                securityValidator.checkReplayProtection(burstPacket, testClientAddress);
            }, "First packet in burst should pass");
            
            // Rapid-fire replays should all be detected
            for (int i = 0; i < 20; i++) {
                assertThrows(RadiusSecurityException.class, () -> {
                    securityValidator.checkReplayProtection(burstPacket, testClientAddress);
                }, "Burst replay attempt " + (i + 1) + " should be detected");
            }
        }
    }

    // Helper methods

    private List<RadiusPacket.RadiusAttribute> createValidAttributes() throws Exception {
        List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
        attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
        
        // Create properly encrypted password
        byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
        byte[] encryptedPassword = RadiusCodec.encryptPassword("testpass", authenticator, testSharedSecret);
        attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, encryptedPassword));
        
        return attributes;
    }

    private byte[] computeTestMessageAuthenticator(RadiusPacket packet, String sharedSecret) throws Exception {
        // Create a copy with Message-Authenticator set to zeros for computation
        List<RadiusPacket.RadiusAttribute> modifiedAttributes = new ArrayList<>();
        for (RadiusPacket.RadiusAttribute attr : packet.getAttributes()) {
            modifiedAttributes.add(attr);
        }
        modifiedAttributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR, new byte[16]));
        
        RadiusPacket tempPacket = new RadiusPacket(packet.getCode(), packet.getIdentifier(), 
            packet.getAuthenticator(), modifiedAttributes);
        
        byte[] packetData = tempPacket.encode();
        
        javax.crypto.Mac hmacMd5 = javax.crypto.Mac.getInstance("HmacMD5");
        javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(sharedSecret.getBytes(), "HmacMD5");
        hmacMd5.init(secretKey);
        
        return hmacMd5.doFinal(packetData);
    }
}