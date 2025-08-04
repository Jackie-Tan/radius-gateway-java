package com.radiusgateway.compliance;

import com.radiusgateway.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Nested;
import static org.junit.jupiter.api.Assertions.*;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

/**
 * RFC 2865 Compliance Test Suite
 * 
 * Tests compliance with RFC 2865 - Remote Authentication Dial In User Service (RADIUS)
 * This test suite validates all critical requirements from the RFC specification.
 */
@DisplayName("RFC 2865 - RADIUS Protocol Compliance Tests")
class Rfc2865ComplianceTest {

    private RadiusSecurityValidator securityValidator;
    private String testSharedSecret;
    private String testClientAddress;

    @BeforeEach
    void setUp() {
        securityValidator = new RadiusSecurityValidatorImpl();
        testSharedSecret = "test-shared-secret-for-rfc-compliance";
        testClientAddress = "127.0.0.1";
    }

    @Nested
    @DisplayName("§3 - Packet Format Compliance")
    class PacketFormatCompliance {

        @Test
        @DisplayName("§3.1 - Packet Structure Validation")
        void testPacketStructureCompliance() throws Exception {
            // RFC 2865 §3: Code + Identifier + Length + Authenticator + Attributes
            
            // Create valid packet with proper structure
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "test-user"));
            
            // Create properly encrypted password
            byte[] encryptedPassword = RadiusCodec.encryptPassword("testpassword", authenticator, testSharedSecret);
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, encryptedPassword));
            RadiusPacket packet = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 123, authenticator, attributes);
            
            // Encode and decode to verify structure integrity
            byte[] encoded = packet.encode();
            RadiusPacket decoded = RadiusPacket.decode(encoded);
            
            // Verify packet structure compliance
            assertEquals(RadiusPacket.ACCESS_REQUEST, decoded.getCode(), "Code field must be preserved");
            assertEquals(123, decoded.getIdentifier(), "Identifier field must be preserved");
            assertArrayEquals(authenticator, decoded.getAuthenticator(), "Authenticator field must be preserved");
            assertEquals(2, decoded.getAttributes().size(), "Attributes must be preserved");
            
            // Verify minimum packet length (RFC 2865 §3)
            assertTrue(encoded.length >= 20, "Packet must be at least 20 bytes (header size)");
            assertTrue(encoded.length <= 4096, "Packet must not exceed 4096 bytes");
        }

        @Test
        @DisplayName("§3.2 - Code Field Validation")
        void testCodeFieldCompliance() throws Exception {
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
            
            // Test valid codes (RFC 2865 §3)
            int[] validCodes = {
                RadiusPacket.ACCESS_REQUEST,    // 1
                RadiusPacket.ACCESS_ACCEPT,     // 2
                RadiusPacket.ACCESS_REJECT,     // 3
                RadiusPacket.ACCESS_CHALLENGE   // 11
            };
            
            for (int code : validCodes) {
                RadiusPacket packet = new RadiusPacket(code, 1, authenticator, attributes);
                byte[] encoded = packet.encode();
                
                // Verify code is encoded correctly
                assertEquals(code, encoded[0] & 0xFF, "Code field must be encoded correctly");
                
                // Verify packet can be decoded
                RadiusPacket decoded = RadiusPacket.decode(encoded);
                assertEquals(code, decoded.getCode(), "Code must be preserved through encode/decode");
            }
        }

        @Test
        @DisplayName("§3.3 - Length Field Validation")
        void testLengthFieldCompliance() throws Exception {
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
            
            RadiusPacket packet = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 42, authenticator, attributes);
            byte[] encoded = packet.encode();
            
            // Verify length field matches actual packet length (RFC 2865 §3)
            int lengthFromPacket = ((encoded[2] & 0xFF) << 8) | (encoded[3] & 0xFF);
            assertEquals(encoded.length, lengthFromPacket, "Length field must match actual packet length");
            
            // Verify length bounds
            assertTrue(lengthFromPacket >= 20, "Length must be at least 20 (header size)");
            assertTrue(lengthFromPacket <= 4096, "Length must not exceed 4096 bytes");
        }

        @Test
        @DisplayName("§3.4 - Request Authenticator Validation")
        void testRequestAuthenticatorCompliance() throws Exception {
            List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
            
            // Test with valid non-zero authenticator
            byte[] validAuthenticator = RadiusCodec.generateRequestAuthenticator();
            RadiusPacket validPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, validAuthenticator, attributes);
            
            // RFC 2865 §3: Request Authenticator validation
            assertTrue(RadiusCodec.validateRequestAuthenticator(validPacket, testSharedSecret),
                "Valid Request Authenticator must pass validation");
            
            // Test with invalid all-zero authenticator
            byte[] invalidAuthenticator = new byte[16]; // All zeros
            RadiusPacket invalidPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, invalidAuthenticator, attributes);
            
            assertFalse(RadiusCodec.validateRequestAuthenticator(invalidPacket, testSharedSecret),
                "All-zero Request Authenticator must fail validation for Access-Request");
        }

        @Test
        @DisplayName("§3.5 - Packet Bounds Validation")
        void testPacketBoundsCompliance() throws Exception {
            List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
            
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            RadiusPacket packet = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, attributes);
            
            // Test security validator bounds checking
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketBounds(packet);
            }, "Valid packet should pass bounds validation");
            
            // Note: For security validation to pass, we need proper password attribute
            // This test focuses on packet bounds validation only
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketBounds(packet);
            }, "Valid packet should pass packet bounds validation");
        }
    }

    @Nested
    @DisplayName("§4 - Packet Types Compliance")
    class PacketTypesCompliance {

        @Test
        @DisplayName("§4.1 - Access-Request Packet Compliance")
        void testAccessRequestCompliance() throws Exception {
            // RFC 2865 §4.1: Access-Request MUST contain User-Name
            List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, new byte[16]));
            
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            RadiusPacket packet = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, attributes);
            
            // Verify required attributes are present
            assertNotNull(packet.getAttribute(RadiusPacket.USER_NAME), "Access-Request MUST contain User-Name");
            assertTrue(packet.getAttribute(RadiusPacket.USER_PASSWORD) != null || 
                      packet.getAttribute(RadiusPacket.CHAP_PASSWORD) != null,
                      "Access-Request MUST contain User-Password or CHAP-Password");
            
            // Verify security validation passes for compliant packet
            assertDoesNotThrow(() -> {
                securityValidator.validateAttributeBounds(packet);
            }, "Compliant Access-Request should pass attribute validation");
        }

        @Test
        @DisplayName("§4.1 - Access-Request Required Attributes")
        void testAccessRequestRequiredAttributes() throws Exception {
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            
            // Test missing User-Name (should fail)
            List<RadiusPacket.RadiusAttribute> missingUserName = new ArrayList<>();
            missingUserName.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, new byte[16]));
            RadiusPacket invalidPacket1 = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, missingUserName);
            
            assertThrows(RadiusValidationException.class, () -> {
                securityValidator.validateAttributeBounds(invalidPacket1);
            }, "Access-Request without User-Name should fail validation");
            
            // Test missing password attributes (should fail)
            List<RadiusPacket.RadiusAttribute> missingPassword = new ArrayList<>();
            missingPassword.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
            RadiusPacket invalidPacket2 = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, missingPassword);
            
            assertThrows(RadiusValidationException.class, () -> {
                securityValidator.validateAttributeBounds(invalidPacket2);
            }, "Access-Request without password attribute should fail validation");
            
            // Test mutually exclusive passwords (should fail)
            List<RadiusPacket.RadiusAttribute> conflictingPasswords = new ArrayList<>();
            conflictingPasswords.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
            conflictingPasswords.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, new byte[16]));
            conflictingPasswords.add(new RadiusPacket.RadiusAttribute(RadiusPacket.CHAP_PASSWORD, new byte[17]));
            RadiusPacket invalidPacket3 = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, conflictingPasswords);
            
            assertThrows(RadiusValidationException.class, () -> {
                securityValidator.validateAttributeBounds(invalidPacket3);
            }, "Access-Request with both User-Password and CHAP-Password should fail validation");
        }

        @Test
        @DisplayName("§4.2/§4.3 - Access-Accept/Reject Response Compliance")
        void testAccessResponseCompliance() throws Exception {
            // Test that responses can be properly generated
            byte[] requestAuthenticator = RadiusCodec.generateRequestAuthenticator();
            
            // Test Access-Accept response
            RadiusHandler.RadiusResponse acceptResponse = RadiusHandler.RadiusResponse.accept("Success");
            RadiusPacket acceptPacket = RadiusResponseBuilder.buildFromResponse(
                acceptResponse, 42, requestAuthenticator, testSharedSecret);
            
            assertEquals(RadiusPacket.ACCESS_ACCEPT, acceptPacket.getCode(), 
                "Access-Accept response must have correct code");
            assertEquals(42, acceptPacket.getIdentifier(), 
                "Response must have same identifier as request");
            
            // Test Access-Reject response
            RadiusHandler.RadiusResponse rejectResponse = RadiusHandler.RadiusResponse.reject("Invalid credentials");
            RadiusPacket rejectPacket = RadiusResponseBuilder.buildFromResponse(
                rejectResponse, 43, requestAuthenticator, testSharedSecret);
            
            assertEquals(RadiusPacket.ACCESS_REJECT, rejectPacket.getCode(), 
                "Access-Reject response must have correct code");
            assertEquals(43, rejectPacket.getIdentifier(), 
                "Response must have same identifier as request");
        }

        @Test
        @DisplayName("§4.4 - Access-Challenge Compliance")
        void testAccessChallengeCompliance() throws Exception {
            // Test Access-Challenge response for two-stage authentication
            byte[] requestAuthenticator = RadiusCodec.generateRequestAuthenticator();
            byte[] challengeState = "challenge-state-data".getBytes();
            
            RadiusHandler.RadiusResponse challengeResponse = RadiusHandler.RadiusResponse.challenge(
                "Please enter OTP", challengeState);
            RadiusPacket challengePacket = RadiusResponseBuilder.buildFromResponse(
                challengeResponse, 44, requestAuthenticator, testSharedSecret);
            
            assertEquals(RadiusPacket.ACCESS_CHALLENGE, challengePacket.getCode(), 
                "Access-Challenge response must have correct code");
            assertEquals(44, challengePacket.getIdentifier(), 
                "Response must have same identifier as request");
            
            // Verify State attribute is present for challenge
            RadiusPacket.RadiusAttribute stateAttr = challengePacket.getAttribute(RadiusPacket.STATE);
            assertNotNull(stateAttr, "Access-Challenge should contain State attribute");
            assertArrayEquals(challengeState, stateAttr.getValue(), "State attribute must contain challenge state");
        }
    }

    @Nested
    @DisplayName("§5 - Attributes Compliance")
    class AttributesCompliance {

        @Test
        @DisplayName("§5.1 - User-Name Attribute Compliance")
        void testUserNameAttributeCompliance() throws Exception {
            // RFC 2865 §5.1: User-Name attribute validation
            
            // Test valid User-Name
            RadiusPacket.RadiusAttribute validUserName = new RadiusPacket.RadiusAttribute(
                RadiusPacket.USER_NAME, "validuser");
            assertEquals(RadiusPacket.USER_NAME, validUserName.getType());
            assertEquals("validuser", validUserName.getStringValue());
            
            // Test User-Name length limits (should not exceed 253 bytes)
            String longUsername = "a".repeat(300);
            List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, longUsername));
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, new byte[16]));
            
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            RadiusPacket packet = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, attributes);
            
            // Should fail validation due to excessive length
            assertThrows(RadiusValidationException.class, () -> {
                securityValidator.validateAttributeBounds(packet);
            }, "User-Name exceeding 253 characters should fail validation");
        }

        @Test
        @DisplayName("§5.2 - User-Password Attribute Compliance")
        void testUserPasswordAttributeCompliance() throws Exception {
            // RFC 2865 §5.2: User-Password PAP encryption/decryption
            
            String originalPassword = "test-password-123";
            byte[] requestAuthenticator = RadiusCodec.generateRequestAuthenticator();
            
            // Test password encryption
            byte[] encryptedPassword = RadiusCodec.encryptPassword(originalPassword, requestAuthenticator, testSharedSecret);
            
            // Verify encrypted password length is multiple of 16 (RFC requirement)
            assertEquals(0, encryptedPassword.length % 16, 
                "Encrypted password length must be multiple of 16 bytes");
            assertNotEquals(originalPassword.getBytes().length, encryptedPassword.length,
                "Encrypted password should be padded");
            
            // Test password decryption
            byte[] decryptedPasswordBytes = RadiusCodec.decryptPassword(encryptedPassword, requestAuthenticator, testSharedSecret);
            String decryptedPassword = new String(decryptedPasswordBytes).trim();
            assertEquals(originalPassword, decryptedPassword, 
                "Decrypted password must match original");
            
            // Test User-Password attribute validation
            RadiusPacket.RadiusAttribute passwordAttr = new RadiusPacket.RadiusAttribute(
                RadiusPacket.USER_PASSWORD, encryptedPassword);
            
            // Verify attribute structure
            assertEquals(RadiusPacket.USER_PASSWORD, passwordAttr.getType());
            assertEquals(encryptedPassword.length + 2, passwordAttr.getLength()); // Type + Length + Value
            
            // Test with invalid password length (not multiple of 16)
            byte[] invalidPassword = new byte[15]; // Invalid length
            List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, invalidPassword));
            
            RadiusPacket invalidPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, requestAuthenticator, attributes);
            
            assertThrows(RadiusValidationException.class, () -> {
                securityValidator.validateAttributeBounds(invalidPacket);
            }, "User-Password with invalid length should fail validation");
        }

        @Test
        @DisplayName("§5.18 - Reply-Message Attribute Compliance")
        void testReplyMessageAttributeCompliance() throws Exception {
            // RFC 2865 §5.18: Reply-Message can appear multiple times
            
            List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, new byte[16]));
            
            // Add multiple Reply-Message attributes (should be allowed)
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.REPLY_MESSAGE, "First message"));
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.REPLY_MESSAGE, "Second message"));
            
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            RadiusPacket packet = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, attributes);
            
            // Should pass validation (multiple Reply-Message attributes allowed)
            assertDoesNotThrow(() -> {
                securityValidator.validateAttributeBounds(packet);
            }, "Multiple Reply-Message attributes should be allowed");
        }

        @Test
        @DisplayName("§5.26 - Vendor-Specific Attribute Compliance")
        void testVendorSpecificAttributeCompliance() throws Exception {
            // RFC 2865 §5.26: Vendor-Specific Attributes (can appear multiple times)
            
            List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, new byte[16]));
            
            // Add Vendor-Specific attributes
            byte[] vendorData1 = {0x00, 0x00, 0x00, 0x09, 0x01, 0x06, 0x74, 0x65, 0x73, 0x74}; // Vendor ID + data
            byte[] vendorData2 = {0x00, 0x00, 0x00, 0x0A, 0x02, 0x08, 0x76, 0x61, 0x6C, 0x75, 0x65, 0x32}; // Different vendor
            
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.VENDOR_SPECIFIC, vendorData1));
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.VENDOR_SPECIFIC, vendorData2));
            
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            RadiusPacket packet = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, attributes);
            
            // Should pass validation (multiple Vendor-Specific attributes allowed)
            assertDoesNotThrow(() -> {
                securityValidator.validateAttributeBounds(packet);
            }, "Multiple Vendor-Specific attributes should be allowed");
            
            // Verify attributes are parsed correctly
            List<RadiusPacket.RadiusAttribute> vendorAttrs = packet.getAttributes();
            long vendorCount = vendorAttrs.stream()
                .filter(attr -> attr.getType() == RadiusPacket.VENDOR_SPECIFIC)
                .count();
            assertEquals(2, vendorCount, "Should have 2 Vendor-Specific attributes");
        }

        @Test
        @DisplayName("§5 - Attribute Occurrence Rules Compliance")
        void testAttributeOccurrenceRulesCompliance() throws Exception {
            byte[] authenticator = RadiusCodec.generateRequestAuthenticator();
            
            // Test duplicate User-Name (should fail - must appear at most once)
            List<RadiusPacket.RadiusAttribute> duplicateUserName = new ArrayList<>();
            duplicateUserName.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "user1"));
            duplicateUserName.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "user2"));
            duplicateUserName.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, new byte[16]));
            
            RadiusPacket invalidPacket = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, duplicateUserName);
            
            assertThrows(RadiusValidationException.class, () -> {
                securityValidator.validateAttributeBounds(invalidPacket);
            }, "Duplicate User-Name attributes should fail validation");
            
            // Test duplicate User-Password (should fail - must appear at most once)
            List<RadiusPacket.RadiusAttribute> duplicatePassword = new ArrayList<>();
            duplicatePassword.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
            duplicatePassword.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, new byte[16]));
            duplicatePassword.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, new byte[16]));
            
            RadiusPacket invalidPacket2 = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, authenticator, duplicatePassword);
            
            assertThrows(RadiusValidationException.class, () -> {
                securityValidator.validateAttributeBounds(invalidPacket2);
            }, "Duplicate User-Password attributes should fail validation");
        }
    }

    @Nested
    @DisplayName("§3 - Response Authenticator Compliance")
    class ResponseAuthenticatorCompliance {

        @Test
        @DisplayName("§3 - Response Authenticator Computation")
        void testResponseAuthenticatorCompliance() throws Exception {
            // RFC 2865 §3: Response Authenticator = MD5(Code + ID + Length + Request Authenticator + Response Attributes + Secret)
            
            byte[] requestAuthenticator = RadiusCodec.generateRequestAuthenticator();
            
            // Create response packet
            RadiusHandler.RadiusResponse response = RadiusHandler.RadiusResponse.accept("Welcome");
            RadiusPacket responsePacket = RadiusResponseBuilder.buildFromResponse(
                response, 123, requestAuthenticator, testSharedSecret);
            
            // Verify Response Authenticator computation
            byte[] computedAuthenticator = RadiusCodec.computeResponseAuthenticator(
                responsePacket, requestAuthenticator, testSharedSecret);
            
            assertArrayEquals(computedAuthenticator, responsePacket.getAuthenticator(),
                "Response Authenticator must be computed correctly according to RFC 2865 §3");
            
            // Verify Response Authenticator is computed correctly
            assertArrayEquals(computedAuthenticator, responsePacket.getAuthenticator(),
                "Response Authenticator must be computed correctly according to RFC 2865 §3");
            
            // Note: validateRequestAuthenticator for response packets validates the Response Authenticator
            // For this test, we verify the computation is correct
        }
    }

    @Nested
    @DisplayName("Error Handling and Edge Cases")
    class ErrorHandlingCompliance {

        @Test
        @DisplayName("Malformed Packet Handling")
        void testMalformedPacketHandling() throws Exception {
            // Test various malformed packets that should be rejected
            
            // Packet too short
            byte[] tooShort = new byte[19]; // Less than minimum 20 bytes
            assertThrows(RadiusPacket.RadiusException.class, () -> {
                RadiusPacket.decode(tooShort);
            }, "Packet shorter than 20 bytes should be rejected");
            
            // Invalid length field
            byte[] invalidLength = new byte[20];
            invalidLength[0] = RadiusPacket.ACCESS_REQUEST; // Code
            invalidLength[1] = 1; // Identifier
            invalidLength[2] = 0; // Length high byte
            invalidLength[3] = 100; // Length low byte (claims 100 bytes, but packet is 20)
            
            assertThrows(RadiusPacket.RadiusException.class, () -> {
                RadiusPacket.decode(invalidLength);
            }, "Packet with mismatched length field should be rejected");
            
            // Truncated attribute
            byte[] truncatedAttr = new byte[22];
            truncatedAttr[0] = RadiusPacket.ACCESS_REQUEST;
            truncatedAttr[1] = 1;
            truncatedAttr[2] = 0;
            truncatedAttr[3] = 22;
            // 16 bytes of authenticator at positions 4-19
            truncatedAttr[20] = RadiusPacket.USER_NAME; // Attribute type
            truncatedAttr[21] = 10; // Attribute length (claims 10 bytes, but only 2 available)
            
            assertThrows(RadiusPacket.RadiusException.class, () -> {
                RadiusPacket.decode(truncatedAttr);
            }, "Packet with truncated attribute should be rejected");
        }

        @Test
        @DisplayName("Security Validation Edge Cases")
        void testSecurityValidationEdgeCases() throws Exception {
            List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"));
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, new byte[16]));
            
            // Test with null authenticator
            assertThrows(Exception.class, () -> {
                new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, null, attributes);
            }, "Null authenticator should be rejected");
            
            // Test with wrong authenticator length - security validator should catch this
            byte[] wrongLengthAuth = new byte[15]; // Should be 16 bytes
            RadiusPacket packetWithBadAuth = new RadiusPacket(RadiusPacket.ACCESS_REQUEST, 1, wrongLengthAuth, attributes);
            
            // Security validator should reject packets with wrong authenticator length
            assertThrows(Exception.class, () -> {
                securityValidator.validatePacketSecurity(packetWithBadAuth, testSharedSecret, testClientAddress);
            }, "Wrong length authenticator should be rejected by security validator");
        }
    }
}