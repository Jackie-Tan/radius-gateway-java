package com.radiusgateway;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.net.InetAddress;
import java.net.UnknownHostException;

class NasRegistryTest {
    
    private NasRegistry registry;
    private InetAddress testAddress;
    
    @BeforeEach
    void setUp() throws UnknownHostException {
        registry = new NasRegistry();
        testAddress = InetAddress.getLoopbackAddress();
    }
    
    @Test
    void testRegisterAndCheckClient() {
        assertFalse(registry.isClientRegistered(testAddress));
        
        registry.registerClient(testAddress, "secret123");
        
        assertTrue(registry.isClientRegistered(testAddress));
        assertEquals("secret123", registry.getSharedSecret(testAddress));
        assertEquals(1, registry.getClientCount());
    }
    
    @Test
    void testRegisterClientWithDescription() {
        registry.registerClient(testAddress, "secret", "Test VPN Gateway");
        
        NasRegistry.NasClient client = registry.getClient(testAddress);
        assertNotNull(client);
        assertEquals("Test VPN Gateway", client.getDescription());
        assertEquals("secret", client.getSharedSecret());
        assertEquals(testAddress, client.getAddress());
    }
    
    @Test
    void testUnregisterClient() {
        registry.registerClient(testAddress, "secret");
        assertTrue(registry.isClientRegistered(testAddress));
        
        registry.unregisterClient(testAddress);
        assertFalse(registry.isClientRegistered(testAddress));
        assertNull(registry.getSharedSecret(testAddress));
        assertEquals(0, registry.getClientCount());
    }
    
    @Test
    void testInvalidRegistration() {
        assertThrows(IllegalArgumentException.class, () -> {
            registry.registerClient(null, "secret");
        });
        
        assertThrows(IllegalArgumentException.class, () -> {
            registry.registerClient(testAddress, null);
        });
        
        assertThrows(IllegalArgumentException.class, () -> {
            registry.registerClient(testAddress, "");
        });
        
        assertThrows(IllegalArgumentException.class, () -> {
            registry.registerClient(testAddress, "  ");
        });
    }
    
    @Test
    void testNasClientStatistics() {
        registry.registerClient(testAddress, "secret", "Test Client");
        NasRegistry.NasClient client = registry.getClient(testAddress);
        
        long registrationTime = client.getRegistrationTime();
        assertTrue(registrationTime > 0);
        assertEquals(registrationTime, client.getLastAccessTime());
        assertEquals(0, client.getRequestCount());
        
        // Simulate access
        client.recordAccess();
        assertEquals(1, client.getRequestCount());
        assertTrue(client.getLastAccessTime() >= registrationTime);
        
        client.recordAccess();
        assertEquals(2, client.getRequestCount());
    }
    
    @Test
    void testClearRegistry() throws UnknownHostException {
        registry.registerClient(testAddress, "secret1");
        registry.registerClient(InetAddress.getByName("192.168.1.1"), "secret2");
        
        assertEquals(2, registry.getClientCount());
        
        registry.clear();
        assertEquals(0, registry.getClientCount());
        assertFalse(registry.isClientRegistered(testAddress));
    }
    
    @Test
    void testClientToString() {
        registry.registerClient(testAddress, "secret", "Test Gateway");
        NasRegistry.NasClient client = registry.getClient(testAddress);
        
        String str = client.toString();
        assertTrue(str.contains(testAddress.getHostAddress()));
        assertTrue(str.contains("Test Gateway"));
        assertTrue(str.contains("requests=0"));
    }
}