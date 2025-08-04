package com.radiusgateway;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.util.Arrays;
import java.util.List;

class RadiusPacketTest {
    
    @Test
    void testPacketCreation() {
        byte[] authenticator = new byte[16];
        Arrays.fill(authenticator, (byte) 0x01);
        
        List<RadiusPacket.RadiusAttribute> attributes = Arrays.asList(
            new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser"),
            new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, "testpass")
        );
        
        RadiusPacket packet = new RadiusPacket(
            RadiusPacket.ACCESS_REQUEST, 123, authenticator, attributes);
        
        assertEquals(RadiusPacket.ACCESS_REQUEST, packet.getCode());
        assertEquals(123, packet.getIdentifier());
        assertArrayEquals(authenticator, packet.getAuthenticator());
        assertEquals(2, packet.getAttributes().size());
    }
    
    @Test
    void testPacketEncodeAndDecode() throws RadiusPacket.RadiusException {
        byte[] authenticator = new byte[16];
        Arrays.fill(authenticator, (byte) 0x02);
        
        List<RadiusPacket.RadiusAttribute> attributes = Arrays.asList(
            new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "alice"),
            new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, "secret123")
        );
        
        RadiusPacket originalPacket = new RadiusPacket(
            RadiusPacket.ACCESS_REQUEST, 42, authenticator, attributes);
        
        byte[] encoded = originalPacket.encode();
        RadiusPacket decodedPacket = RadiusPacket.decode(encoded);
        
        assertEquals(originalPacket.getCode(), decodedPacket.getCode());
        assertEquals(originalPacket.getIdentifier(), decodedPacket.getIdentifier());
        assertArrayEquals(originalPacket.getAuthenticator(), decodedPacket.getAuthenticator());
        
        assertEquals("alice", decodedPacket.getStringAttribute(RadiusPacket.USER_NAME));
        assertEquals("secret123", decodedPacket.getStringAttribute(RadiusPacket.USER_PASSWORD));
    }
    
    @Test
    void testAttributeAccess() {
        RadiusPacket.RadiusAttribute attr = new RadiusPacket.RadiusAttribute(
            RadiusPacket.USER_NAME, "testuser");
        
        assertEquals(RadiusPacket.USER_NAME, attr.getType());
        assertEquals("testuser", attr.getStringValue());
        assertEquals(10, attr.getLength()); // 2 + "testuser".length()
    }
    
    @Test
    void testInvalidPacketTooShort() {
        byte[] shortPacket = new byte[10]; // Too short for RADIUS header
        
        assertThrows(RadiusPacket.RadiusException.class, () -> {
            RadiusPacket.decode(shortPacket);
        });
    }
    
    @Test
    void testInvalidPacketLengthMismatch() {
        byte[] packet = new byte[50];
        packet[0] = RadiusPacket.ACCESS_REQUEST;
        packet[1] = 1; // identifier
        packet[2] = 0; // length high byte
        packet[3] = 100; // length low byte - wrong length
        
        assertThrows(RadiusPacket.RadiusException.class, () -> {
            RadiusPacket.decode(packet);
        });
    }
    
    @Test
    void testMalformedAttribute() {
        byte[] packet = new byte[22];
        packet[0] = RadiusPacket.ACCESS_REQUEST;
        packet[1] = 1;
        packet[2] = 0;
        packet[3] = 22; // length
        // 16 bytes authenticator filled with zeros by default
        packet[20] = RadiusPacket.USER_NAME; // attribute type
        packet[21] = 1; // invalid length (too short)
        
        assertThrows(RadiusPacket.RadiusException.class, () -> {
            RadiusPacket.decode(packet);
        });
    }
}