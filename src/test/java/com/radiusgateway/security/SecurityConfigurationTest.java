package com.radiusgateway.security;

import com.radiusgateway.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Nested;
import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.EnumSet;

/**
 * Security Configuration Test Suite
 * 
 * Tests various combinations of security features and their interactions.
 * Validates proper behavior when features are enabled/disabled individually and in combination.
 */
@DisplayName("Security Configuration - Feature Combination Testing")
class SecurityConfigurationTest {

    private RadiusSecurityValidator securityValidator;
    private String testSharedSecret;
    private String testClientAddress;
    private SecureRandom random;

    @BeforeEach
    void setUp() {
        securityValidator = new RadiusSecurityValidatorImpl();
        testSharedSecret = "configuration-test-shared-secret";
        testClientAddress = "192.168.100.50";
        random = new SecureRandom();
    }

    @Nested
    @DisplayName("Individual Feature Configuration")
    class IndividualFeatureConfiguration {

        @Test
        @DisplayName("Request Authenticator Validation Toggle")
        void testRequestAuthenticatorValidationToggle() throws Exception {
            RadiusPacket validPacket = createValidTestPacket(1);
            
            // Enable Request Authenticator validation
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.REQUEST_AUTHENTICATOR_VALIDATION, true);
            
            // Valid packet should pass
            assertDoesNotThrow(() -> {
                securityValidator.validateRequestAuthenticator(validPacket, testSharedSecret);
            }, "Valid packet should pass when Request Authenticator validation is enabled");
            
            // Create packet with all-zero authenticator (invalid)
            List<RadiusPacket.RadiusAttribute> attrs = createValidAttributes();
            byte[] zeroAuth = new byte[16]; // All zeros
            RadiusPacket invalidPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 2, zeroAuth, attrs);
            
            // Invalid packet should fail when validation is enabled
            assertThrows(RadiusSecurityException.class, () -> {
                securityValidator.validateRequestAuthenticator(invalidPacket, testSharedSecret);
            }, "Invalid authenticator should fail when validation is enabled");
            
            // Disable Request Authenticator validation
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.REQUEST_AUTHENTICATOR_VALIDATION, false);
            
            // Invalid packet should now pass (validation disabled)
            assertDoesNotThrow(() -> {
                securityValidator.validateRequestAuthenticator(invalidPacket, testSharedSecret);
            }, "Invalid authenticator should pass when validation is disabled");
        }

        @Test
        @DisplayName("Message-Authenticator Validation Toggle")
        void testMessageAuthenticatorValidationToggle() throws Exception {
            List<RadiusPacket.RadiusAttribute> attrs = createValidAttributes();
            byte[] auth = RadiusCodec.generateRequestAuthenticator();
            
            // Add invalid Message-Authenticator
            byte[] invalidMessageAuth = new byte[16];
            random.nextBytes(invalidMessageAuth);
            attrs.add(new RadiusPacket.RadiusAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR, invalidMessageAuth));
            
            RadiusPacket packetWithInvalidMessageAuth = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 3, auth, attrs);
            
            // Enable Message-Authenticator validation
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.MESSAGE_AUTHENTICATOR_VALIDATION, true);
            
            // Should fail with validation enabled
            assertThrows(RadiusSecurityException.class, () -> {
                securityValidator.validateMessageAuthenticator(packetWithInvalidMessageAuth, testSharedSecret);
            }, "Invalid Message-Authenticator should fail when validation is enabled");
            
            // Disable Message-Authenticator validation
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.MESSAGE_AUTHENTICATOR_VALIDATION, false);
            
            // Should pass with validation disabled
            assertDoesNotThrow(() -> {
                securityValidator.validateMessageAuthenticator(packetWithInvalidMessageAuth, testSharedSecret);
            }, "Invalid Message-Authenticator should pass when validation is disabled");
        }

        @Test
        @DisplayName("Packet Bounds Validation Toggle")
        void testPacketBoundsValidationToggle() throws Exception {
            // Create a borderline valid packet that might fail strict bounds checking
            List<RadiusPacket.RadiusAttribute> attrs = createValidAttributes();
            byte[] auth = RadiusCodec.generateRequestAuthenticator();
            RadiusPacket packet = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 4, auth, attrs);
            
            // Enable packet bounds validation
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.PACKET_BOUNDS_VALIDATION, true);
            
            // Valid packet should pass
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketBounds(packet);
            }, "Valid packet should pass bounds validation");
            
            // Disable packet bounds validation
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.PACKET_BOUNDS_VALIDATION, false);
            
            // Should still pass (but validation is disabled)
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketBounds(packet);
            }, "Packet should pass when bounds validation is disabled");
        }

        @Test
        @DisplayName("Replay Protection Toggle")
        void testReplayProtectionToggle() throws Exception {
            RadiusPacket packet = createValidTestPacket(5);
            
            // Enable replay protection
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.REPLAY_PROTECTION, true);
            
            // First request should pass
            assertDoesNotThrow(() -> {
                securityValidator.checkReplayProtection(packet, testClientAddress);
            }, "First packet should pass replay protection");
            
            // Immediate replay should fail
            assertThrows(RadiusSecurityException.class, () -> {
                securityValidator.checkReplayProtection(packet, testClientAddress);
            }, "Replay should be detected when protection is enabled");
            
            // Disable replay protection
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.REPLAY_PROTECTION, false);
            
            // Same packet should now pass (replay protection disabled)
            assertDoesNotThrow(() -> {
                securityValidator.checkReplayProtection(packet, testClientAddress);
            }, "Replay should pass when protection is disabled");
        }

        @Test
        @DisplayName("Strict RFC Compliance Toggle")
        void testStrictRfcComplianceToggle() throws Exception {
            RadiusPacket packet = createValidTestPacket(6);
            
            // Enable strict RFC compliance
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.STRICT_RFC_COMPLIANCE, true);
            
            // Packet should still pass (it's valid)
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketBounds(packet);
            }, "Valid packet should pass strict RFC compliance");
            
            // Disable strict RFC compliance
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.STRICT_RFC_COMPLIANCE, false);
            
            // Should still pass
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketBounds(packet);
            }, "Valid packet should pass normal RFC compliance");
        }
    }

    @Nested
    @DisplayName("Feature Combination Testing")
    class FeatureCombinationTesting {

        @Test
        @DisplayName("All Security Features Enabled")
        void testAllSecurityFeaturesEnabled() throws Exception {
            // Enable all security features
            for (RadiusSecurityValidator.SecurityFeature feature : RadiusSecurityValidator.SecurityFeature.values()) {
                securityValidator.configureSecurityFeature(feature, true);
            }
            
            RadiusPacket validPacket = createValidTestPacket(10);
            
            // Comprehensive security validation should pass for valid packet
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(validPacket, testSharedSecret, testClientAddress);
            }, "Valid packet should pass comprehensive security validation with all features enabled");
            
            // Test invalid packet scenarios
            List<RadiusPacket.RadiusAttribute> attrs = createValidAttributes();
            byte[] zeroAuth = new byte[16];
            RadiusPacket invalidPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 11, zeroAuth, attrs);
            
            // Should fail with all security features enabled
            assertThrows(RadiusSecurityException.class, () -> {
                securityValidator.validatePacketSecurity(invalidPacket, testSharedSecret, testClientAddress);
            }, "Invalid packet should fail with all security features enabled");
        }

        @Test
        @DisplayName("All Security Features Disabled")
        void testAllSecurityFeaturesDisabled() throws Exception {
            // Disable all security features
            for (RadiusSecurityValidator.SecurityFeature feature : RadiusSecurityValidator.SecurityFeature.values()) {
                securityValidator.configureSecurityFeature(feature, false);
            }
            
            // Even invalid packets should pass with all security disabled
            List<RadiusPacket.RadiusAttribute> attrs = createValidAttributes();
            byte[] zeroAuth = new byte[16];
            RadiusPacket questionablePacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 12, zeroAuth, attrs);
            
            // Should pass with all security features disabled
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(questionablePacket, testSharedSecret, testClientAddress);
            }, "Questionable packet should pass with all security features disabled");
        }

        @Test
        @DisplayName("Mixed Security Configuration")
        void testMixedSecurityConfiguration() throws Exception {
            // Configure mixed security features
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.PACKET_BOUNDS_VALIDATION, true);
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.ATTRIBUTE_BOUNDS_VALIDATION, true);
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.REQUEST_AUTHENTICATOR_VALIDATION, false);
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.MESSAGE_AUTHENTICATOR_VALIDATION, false);
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.REPLAY_PROTECTION, true);
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.STRICT_RFC_COMPLIANCE, false);
            
            RadiusPacket packet = createValidTestPacket(13);
            
            // Should pass with this mixed configuration
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(packet, testSharedSecret, testClientAddress);
            }, "Valid packet should pass with mixed security configuration");
            
            // Test packet with zero authenticator (should pass since authenticator validation is disabled)
            List<RadiusPacket.RadiusAttribute> attrs = createValidAttributes();
            byte[] zeroAuth = new byte[16];
            RadiusPacket zeroAuthPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 14, zeroAuth, attrs);
            
            // Should pass since Request Authenticator validation is disabled
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(zeroAuthPacket, testSharedSecret, "192.168.100.51");
            }, "Zero authenticator packet should pass when authenticator validation is disabled");
        }

        @Test
        @DisplayName("Cryptographic Features Only")
        void testCryptographicFeaturesOnly() throws Exception {
            // Enable only cryptographic security features
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.REQUEST_AUTHENTICATOR_VALIDATION, true);
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.MESSAGE_AUTHENTICATOR_VALIDATION, true);
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.PACKET_BOUNDS_VALIDATION, false);
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.ATTRIBUTE_BOUNDS_VALIDATION, false);
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.REPLAY_PROTECTION, false);
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.STRICT_RFC_COMPLIANCE, false);
            
            RadiusPacket validPacket = createValidTestPacket(15);
            
            // Should pass with cryptographic validation only
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(validPacket, testSharedSecret, testClientAddress);
            }, "Valid packet should pass with cryptographic features only");
        }

        @Test
        @DisplayName("Bounds Checking Only")
        void testBoundsCheckingOnly() throws Exception {
            // Enable only bounds checking features
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.PACKET_BOUNDS_VALIDATION, true);
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.ATTRIBUTE_BOUNDS_VALIDATION, true);
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.REQUEST_AUTHENTICATOR_VALIDATION, false);
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.MESSAGE_AUTHENTICATOR_VALIDATION, false);
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.REPLAY_PROTECTION, false);
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.STRICT_RFC_COMPLIANCE, false);
            
            RadiusPacket validPacket = createValidTestPacket(16);
            
            // Should pass with bounds checking only
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(validPacket, testSharedSecret, testClientAddress);
            }, "Valid packet should pass with bounds checking only");
            
            // Even packet with zero authenticator should pass (since authenticator validation is disabled)
            List<RadiusPacket.RadiusAttribute> attrs = createValidAttributes();
            byte[] zeroAuth = new byte[16];
            RadiusPacket zeroAuthPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 17, zeroAuth, attrs);
            
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(zeroAuthPacket, testSharedSecret, testClientAddress);
            }, "Zero authenticator packet should pass with bounds checking only");
        }
    }

    @Nested
    @DisplayName("Configuration Edge Cases")
    class ConfigurationEdgeCases {

        @Test
        @DisplayName("Rapid Feature Toggle")
        void testRapidFeatureToggle() throws Exception {
            RadiusPacket packet = createValidTestPacket(20);
            
            // Rapidly toggle features
            for (int i = 0; i < 10; i++) {
                boolean enable = (i % 2 == 0);
                final int iteration = i;
                
                securityValidator.configureSecurityFeature(
                    RadiusSecurityValidator.SecurityFeature.REPLAY_PROTECTION, enable);
                securityValidator.configureSecurityFeature(
                    RadiusSecurityValidator.SecurityFeature.MESSAGE_AUTHENTICATOR_VALIDATION, enable);
                
                // Should handle rapid configuration changes gracefully
                assertDoesNotThrow(() -> {
                    securityValidator.validatePacketSecurity(packet, testSharedSecret, 
                        testClientAddress + "." + iteration);
                }, "Rapid feature toggle iteration " + iteration + " should be handled gracefully");
            }
        }

        @Test
        @DisplayName("Feature Configuration During Active Validation")
        void testFeatureConfigurationDuringValidation() throws Exception {
            // This test simulates configuration changes during active packet processing
            RadiusPacket packet = createValidTestPacket(21);
            
            // Start with all features enabled
            for (RadiusSecurityValidator.SecurityFeature feature : RadiusSecurityValidator.SecurityFeature.values()) {
                securityValidator.configureSecurityFeature(feature, true);
            }
            
            // Validate packet multiple times while changing configuration
            for (int i = 0; i < 5; i++) {
                final int iteration = i;
                
                // Change configuration mid-process
                securityValidator.configureSecurityFeature(
                    RadiusSecurityValidator.SecurityFeature.STRICT_RFC_COMPLIANCE, i % 2 == 0);
                
                assertDoesNotThrow(() -> {
                    securityValidator.validatePacketSecurity(packet, testSharedSecret, 
                        testClientAddress + "." + iteration);
                }, "Configuration change during validation should be handled gracefully");
            }
        }

        @Test
        @DisplayName("Invalid Feature Configuration Resilience")
        void testInvalidFeatureConfigurationResilience() throws Exception {
            RadiusPacket packet = createValidTestPacket(22);
            
            // Test with null feature (should be handled gracefully)
            assertDoesNotThrow(() -> {
                try {
                    securityValidator.configureSecurityFeature(null, true);
                } catch (IllegalArgumentException | NullPointerException e) {
                    // Expected - null feature should be rejected
                }
            }, "Null feature configuration should be handled gracefully");
            
            // Packet validation should still work after invalid configuration attempt
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(packet, testSharedSecret, testClientAddress);
            }, "Packet validation should work after invalid configuration attempt");
        }

        @Test
        @DisplayName("Configuration Persistence")
        void testConfigurationPersistence() throws Exception {
            // Configure specific features
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.REPLAY_PROTECTION, false);
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.MESSAGE_AUTHENTICATOR_VALIDATION, false);
            
            RadiusPacket packet1 = createValidTestPacket(23);
            RadiusPacket packet2 = createValidTestPacket(24);
            
            // First validation
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(packet1, testSharedSecret, testClientAddress);
            }, "First validation should respect configuration");
            
            // Second validation should maintain same configuration
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(packet2, testSharedSecret, testClientAddress);
            }, "Second validation should maintain configuration persistence");
            
            // Test that replay protection is indeed disabled
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(packet1, testSharedSecret, testClientAddress);
            }, "Replay should pass when protection is disabled");
        }
    }

    // Helper methods

    private RadiusPacket createValidTestPacket(int identifier) throws Exception {
        List<RadiusPacket.RadiusAttribute> attributes = createValidAttributes();
        byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
        return new RadiusPacket(RadiusPacket.ACCESS_REQUEST, identifier % 256, authenticator, attributes);
    }

    private List<RadiusPacket.RadiusAttribute> createValidAttributes() throws Exception {
        List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
        attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "configtest"));
        
        byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
        byte[] encryptedPassword = RadiusCodec.encryptPassword("testpass", authenticator, testSharedSecret);
        attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, encryptedPassword));
        
        return attributes;
    }
}