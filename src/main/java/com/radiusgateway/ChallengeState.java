package com.radiusgateway;

import java.security.SecureRandom;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Manages challenge state for two-stage RADIUS authentication.
 * Tracks active authentication sessions between challenge and response.
 */
public class ChallengeState {
    
    private static final int DEFAULT_TIMEOUT_SECONDS = 300; // 5 minutes
    private static final int STATE_LENGTH = 16; // 16 bytes for state attribute
    
    private final ConcurrentHashMap<String, ChallengeSession> activeSessions;
    private final ScheduledExecutorService cleanupExecutor;
    private final SecureRandom secureRandom;
    private final int timeoutSeconds;
    
    public ChallengeState() {
        this(DEFAULT_TIMEOUT_SECONDS);
    }
    
    public ChallengeState(int timeoutSeconds) {
        this.activeSessions = new ConcurrentHashMap<>();
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ChallengeState-Cleanup");
            t.setDaemon(true);
            return t;
        });
        this.secureRandom = new SecureRandom();
        this.timeoutSeconds = timeoutSeconds;
        
        // Schedule cleanup task every minute
        cleanupExecutor.scheduleAtFixedRate(this::cleanupExpiredSessions, 
                                          60, 60, TimeUnit.SECONDS);
    }
    
    /**
     * Creates a new challenge session and returns the state identifier.
     */
    public byte[] createChallenge(String username, String clientAddress) {
        // Generate random state identifier
        byte[] stateId = new byte[STATE_LENGTH];
        secureRandom.nextBytes(stateId);
        
        String stateKey = RadiusUtils.bytesToHex(stateId);
        long expiryTime = System.currentTimeMillis() + (timeoutSeconds * 1000L);
        
        ChallengeSession session = new ChallengeSession(username, clientAddress, expiryTime);
        activeSessions.put(stateKey, session);
        
        return stateId;
    }
    
    /**
     * Validates a challenge response and returns the associated session.
     * Returns null if state is invalid or expired.
     */
    public ChallengeSession validateAndConsume(byte[] stateId, String username, String clientAddress) {
        if (stateId == null || stateId.length != STATE_LENGTH) {
            return null;
        }
        
        String stateKey = RadiusUtils.bytesToHex(stateId);
        ChallengeSession session = activeSessions.remove(stateKey);
        
        if (session == null) {
            return null; // No active session
        }
        
        if (System.currentTimeMillis() > session.getExpiryTime()) {
            return null; // Session expired
        }
        
        if (!session.getUsername().equals(username) || 
            !session.getClientAddress().equals(clientAddress)) {
            return null; // Session mismatch
        }
        
        return session;
    }
    
    /**
     * Removes expired sessions from memory.
     */
    private void cleanupExpiredSessions() {
        long currentTime = System.currentTimeMillis();
        activeSessions.entrySet().removeIf(entry -> 
            currentTime > entry.getValue().getExpiryTime());
    }
    
    /**
     * Gets the number of active challenge sessions.
     */
    public int getActiveSessionCount() {
        return activeSessions.size();
    }
    
    /**
     * Shuts down the cleanup executor.
     */
    public void shutdown() {
        cleanupExecutor.shutdown();
        try {
            if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            cleanupExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
    
    
    /**
     * Represents an active challenge session.
     */
    public static class ChallengeSession {
        private final String username;
        private final String clientAddress;
        private final long expiryTime;
        private final long creationTime;
        
        public ChallengeSession(String username, String clientAddress, long expiryTime) {
            this.username = username;
            this.clientAddress = clientAddress;
            this.expiryTime = expiryTime;
            this.creationTime = System.currentTimeMillis();
        }
        
        public String getUsername() {
            return username;
        }
        
        public String getClientAddress() {
            return clientAddress;
        }
        
        public long getExpiryTime() {
            return expiryTime;
        }
        
        public long getCreationTime() {
            return creationTime;
        }
        
        public boolean isExpired() {
            return System.currentTimeMillis() > expiryTime;
        }
        
        @Override
        public String toString() {
            return String.format("ChallengeSession{username='%s', clientAddress='%s', " +
                               "creationTime=%d, expiryTime=%d}", 
                               username, clientAddress, creationTime, expiryTime);
        }
    }
}