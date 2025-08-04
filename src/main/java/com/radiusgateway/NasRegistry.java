package com.radiusgateway;

import java.net.InetAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class NasRegistry {
    
    private final ConcurrentMap<InetAddress, NasClient> clients = new ConcurrentHashMap<>();
    
    public void registerClient(InetAddress address, String sharedSecret) {
        registerClient(address, sharedSecret, "Unknown NAS");
    }
    
    public void registerClient(InetAddress address, String sharedSecret, String description) {
        if (address == null) {
            throw new IllegalArgumentException("Client address cannot be null");
        }
        if (sharedSecret == null || sharedSecret.trim().isEmpty()) {
            throw new IllegalArgumentException("Shared secret cannot be null or empty");
        }
        
        clients.put(address, new NasClient(address, sharedSecret.trim(), description));
    }
    
    public void unregisterClient(InetAddress address) {
        clients.remove(address);
    }
    
    public boolean isClientRegistered(InetAddress address) {
        return clients.containsKey(address);
    }
    
    public String getSharedSecret(InetAddress address) {
        NasClient client = clients.get(address);
        return client != null ? client.getSharedSecret() : null;
    }
    
    public NasClient getClient(InetAddress address) {
        return clients.get(address);
    }
    
    public int getClientCount() {
        return clients.size();
    }
    
    public void clear() {
        clients.clear();
    }
    
    public static class NasClient {
        private final InetAddress address;
        private final String sharedSecret;
        private final String description;
        private final long registrationTime;
        private volatile long lastAccessTime;
        private volatile long requestCount;
        
        public NasClient(InetAddress address, String sharedSecret, String description) {
            this.address = address;
            this.sharedSecret = sharedSecret;
            this.description = description;
            this.registrationTime = System.currentTimeMillis();
            this.lastAccessTime = registrationTime;
            this.requestCount = 0;
        }
        
        public InetAddress getAddress() {
            return address;
        }
        
        public String getSharedSecret() {
            return sharedSecret;
        }
        
        public String getDescription() {
            return description;
        }
        
        public long getRegistrationTime() {
            return registrationTime;
        }
        
        public long getLastAccessTime() {
            return lastAccessTime;
        }
        
        public long getRequestCount() {
            return requestCount;
        }
        
        void recordAccess() {
            this.lastAccessTime = System.currentTimeMillis();
            this.requestCount++;
        }
        
        @Override
        public String toString() {
            return String.format("NasClient{address=%s, description='%s', requests=%d}", 
                               address.getHostAddress(), description, requestCount);
        }
    }
}