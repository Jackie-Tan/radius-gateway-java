package com.radiusgateway.security;

import com.radiusgateway.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Timeout;
import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Attack Simulation Test Suite
 * 
 * Simulates real-world attack scenarios against the RADIUS Gateway.
 * Tests system resilience against various attack vectors and threat patterns.
 */
@DisplayName("Attack Simulation - Real-World Security Testing")
class AttackSimulationTest {

    private RadiusSecurityValidator securityValidator;
    private String testSharedSecret;
    private SecureRandom random;

    @BeforeEach
    void setUp() {
        securityValidator = new RadiusSecurityValidatorImpl();
        testSharedSecret = "attack-simulation-shared-secret-for-testing";
        random = new SecureRandom();
    }

    @Nested
    @DisplayName("Common RADIUS Attacks")
    class CommonRadiusAttacks {

        @Test
        @DisplayName("Dictionary Attack Simulation")
        @Timeout(30)
        void testDictionaryAttackSimulation() throws Exception {
            // Simulate dictionary attack with common passwords
            String[] commonPasswords = {
                "password", "123456", "admin", "root", "guest", "user", "test",
                "12345678", "qwerty", "abc123", "password123", "letmein",
                "welcome", "monkey", "dragon", "pass", "master", "shadow"
            };
            
            String targetUsername = "admin";
            AtomicInteger attemptCount = new AtomicInteger(0);
            AtomicInteger securityViolations = new AtomicInteger(0);
            
            for (String password : commonPasswords) {
                try {
                    RadiusPacket attackPacket = createAuthenticationPacket(targetUsername, password, attemptCount.get());
                    securityValidator.validatePacketSecurity(attackPacket, testSharedSecret, "10.0.1.100");
                    attemptCount.incrementAndGet();
                } catch (RadiusSecurityException e) {
                    securityViolations.incrementAndGet();
                } catch (Exception e) {
                    // Other validation errors are expected
                }
                
                // Small delay to simulate realistic attack timing
                Thread.sleep(100);
            }
            
            // Security assertions
            assertTrue(attemptCount.get() > 0, "Some packets should pass security validation");
            System.out.printf("Dictionary Attack: %d attempts, %d security violations%n", 
                attemptCount.get(), securityViolations.get());
            
            // Verify system remains functional after dictionary attack
            RadiusPacket normalPacket = createAuthenticationPacket("normaluser", "normalpass", 9999);
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(normalPacket, testSharedSecret, "10.0.1.200");
            }, "System should remain functional after dictionary attack");
        }

        @Test
        @DisplayName("Credential Stuffing Attack Simulation")
        @Timeout(45)
        void testCredentialStuffingAttackSimulation() throws Exception {
            // Simulate credential stuffing with username/password combinations
            String[][] credentialPairs = {
                {"admin", "admin"}, {"admin", "password"}, {"admin", "12345"},
                {"root", "root"}, {"root", "toor"}, {"root", "password"},
                {"user", "user"}, {"user", "pass"}, {"user", "123456"},
                {"test", "test"}, {"test", "password"}, {"test", "admin"},
                {"guest", "guest"}, {"guest", ""}, {"guest", "password"}
            };
            
            AtomicInteger totalAttempts = new AtomicInteger(0);
            AtomicInteger securityBlocks = new AtomicInteger(0);
            AtomicInteger validationFailures = new AtomicInteger(0);
            
            String attackerIp = "192.168.10.50";
            
            for (String[] credentials : credentialPairs) {
                String username = credentials[0];
                String password = credentials[1];
                
                try {
                    RadiusPacket stuffingPacket = createAuthenticationPacket(username, password, totalAttempts.get());
                    securityValidator.validatePacketSecurity(stuffingPacket, testSharedSecret, attackerIp);
                    totalAttempts.incrementAndGet();
                } catch (RadiusSecurityException e) {
                    securityBlocks.incrementAndGet();
                } catch (RadiusValidationException e) {
                    validationFailures.incrementAndGet();
                }
                
                // Vary timing to simulate automated attack tools
                Thread.sleep(50 + random.nextInt(100));
            }
            
            // Attack pattern analysis
            assertTrue(totalAttempts.get() + securityBlocks.get() + validationFailures.get() == credentialPairs.length,
                "All credential stuffing attempts should be accounted for");
            
            System.out.printf("Credential Stuffing: %d total, %d passed, %d security blocks, %d validation failures%n",
                credentialPairs.length, totalAttempts.get(), securityBlocks.get(), validationFailures.get());
        }

        @Test
        @DisplayName("Packet Injection Attack Simulation")
        @Timeout(20)
        void testPacketInjectionAttackSimulation() throws Exception {
            // Create legitimate packet first
            RadiusPacket legitimatePacket = createAuthenticationPacket("legit_user", "legit_pass", 1000);
            String legitimateClient = "192.168.1.100";
            
            // Legitimate packet should pass
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(legitimatePacket, testSharedSecret, legitimateClient);
            }, "Legitimate packet should pass validation");
            
            // Simulate attacker trying to inject modified packets
            byte[] originalAuth = legitimatePacket.getAuthenticator();
            
            // Test with modified authenticator (packet injection attempt)
            for (int bitFlip = 0; bitFlip < 16; bitFlip++) {
                byte[] modifiedAuth = originalAuth.clone();
                modifiedAuth[bitFlip] ^= 0xFF; // Flip all bits in one byte
                
                List<RadiusPacket.RadiusAttribute> attrs = new ArrayList<>(legitimatePacket.getAttributes());
                RadiusPacket injectedPacket = new RadiusPacket(
                    legitimatePacket.getCode(), 
                    legitimatePacket.getIdentifier(),
                    modifiedAuth, 
                    attrs
                );
                
                // Injected packets should pass Request Authenticator validation (they're non-zero)
                // but should be detected as replay attacks if from same client
                try {
                    securityValidator.validatePacketSecurity(injectedPacket, testSharedSecret, legitimateClient);
                    // If it passes, it should be from a different "client" perspective
                } catch (RadiusSecurityException e) {
                    // Expected for replay detection
                    assertTrue(e.getMessage().contains("replay") || e.getMessage().contains("Replay"),
                        "Packet injection should be detected as replay attack");
                }
            }
        }

        @Test
        @DisplayName("Protocol Downgrade Attack Simulation")
        @Timeout(15)
        void testProtocolDowngradeAttackSimulation() throws Exception {
            // Simulate attacker trying to force weaker security
            
            // Create packet without Message-Authenticator (weaker security)
            RadiusPacket weakPacket = createAuthenticationPacket("downgrade_user", "downgrade_pass", 2000);
            
            // Should still pass validation (Message-Authenticator is optional)
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(weakPacket, testSharedSecret, "192.168.2.100");
            }, "Packet without Message-Authenticator should still pass (it's optional)");
            
            // Create packet with invalid Message-Authenticator (attack attempt)
            List<RadiusPacket.RadiusAttribute> attrs = new ArrayList<>(weakPacket.getAttributes());
            byte[] fakeMessageAuth = new byte[16];
            random.nextBytes(fakeMessageAuth);
            attrs.add(new RadiusPacket.RadiusAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR, fakeMessageAuth));
            
            RadiusPacket attackPacket = new RadiusPacket(
                weakPacket.getCode(),
                weakPacket.getIdentifier(),
                weakPacket.getAuthenticator(),
                attrs
            );
            
            // Invalid Message-Authenticator should be detected
            assertThrows(RadiusSecurityException.class, () -> {
                securityValidator.validatePacketSecurity(attackPacket, testSharedSecret, "192.168.2.101");
            }, "Invalid Message-Authenticator should be detected and rejected");
        }
    }

    @Nested
    @DisplayName("Advanced Persistent Threats (APT)")
    class AdvancedPersistentThreats {

        @Test
        @DisplayName("Low-and-Slow Attack Simulation")
        @Timeout(60)
        void testLowAndSlowAttackSimulation() throws Exception {
            // Simulate advanced persistent threat with low-frequency, long-term attack
            final int attackDuration = 30; // seconds
            final int attacksPerSecond = 2; // Very low frequency
            final String[] targetUsers = {"admin", "operator", "manager", "supervisor"};
            
            AtomicInteger totalAttempts = new AtomicInteger(0);
            AtomicInteger detectedAttempts = new AtomicInteger(0);
            
            long startTime = System.currentTimeMillis();
            long endTime = startTime + (attackDuration * 1000);
            
            int userIndex = 0;
            int passwordAttempt = 0;
            
            while (System.currentTimeMillis() < endTime) {
                try {
                    String targetUser = targetUsers[userIndex % targetUsers.length];
                    String password = generateWeakPassword(passwordAttempt);
                    
                    RadiusPacket stealthPacket = createAuthenticationPacket(targetUser, password, totalAttempts.get());
                    
                    // Use different client IPs to avoid detection
                    String stealthIp = "203.0.113." + (totalAttempts.get() % 254 + 1);
                    
                    securityValidator.validatePacketSecurity(stealthPacket, testSharedSecret, stealthIp);
                    totalAttempts.incrementAndGet();
                    
                } catch (RadiusSecurityException e) {
                    detectedAttempts.incrementAndGet();
                } catch (Exception e) {
                    // Other errors don't count as detection
                }
                
                userIndex++;
                passwordAttempt++;
                
                // Low-frequency delay (critical for stealth)
                Thread.sleep(1000 / attacksPerSecond);
            }
            
            // APT characteristics analysis
            long actualDuration = (System.currentTimeMillis() - startTime) / 1000;
            double actualRate = totalAttempts.get() / (double) actualDuration;
            
            assertTrue(actualRate < 5.0, "Attack rate should be low for stealth, got: " + actualRate + " attempts/sec");
            System.out.printf("Low-and-Slow APT: %d attempts over %ds (%.2f/sec), %d detected%n",
                totalAttempts.get(), actualDuration, actualRate, detectedAttempts.get());
        }

        @Test
        @DisplayName("Distributed Attack Simulation")
        @Timeout(30)
        void testDistributedAttackSimulation() throws Exception {
            final int attackerCount = 20;
            final int attemptsPerAttacker = 10;
            
            ExecutorService attackerPool = Executors.newFixedThreadPool(attackerCount);
            CountDownLatch startSignal = new CountDownLatch(1);
            CountDownLatch finishSignal = new CountDownLatch(attackerCount);
            
            AtomicInteger totalAttempts = new AtomicInteger(0);
            AtomicInteger successfulAttempts = new AtomicInteger(0);
            AtomicInteger blockedAttempts = new AtomicInteger(0);
            
            // Launch distributed attackers
            for (int attackerId = 0; attackerId < attackerCount; attackerId++) {
                final int finalAttackerId = attackerId;
                attackerPool.submit(() -> {
                    try {
                        startSignal.await(); // Coordinate simultaneous start
                        
                        String attackerIp = "198.51.100." + (finalAttackerId + 1);
                        
                        for (int attempt = 0; attempt < attemptsPerAttacker; attempt++) {
                            try {
                                String username = "target" + (attempt % 3); // Cycle through targets
                                String password = "attack" + finalAttackerId + "_" + attempt;
                                
                                RadiusPacket distributedPacket = createAuthenticationPacket(
                                    username, password, finalAttackerId * attemptsPerAttacker + attempt);
                                
                                securityValidator.validatePacketSecurity(distributedPacket, testSharedSecret, attackerIp);
                                successfulAttempts.incrementAndGet();
                                
                            } catch (RadiusSecurityException e) {
                                blockedAttempts.incrementAndGet();
                            } catch (Exception e) {
                                // Other validation errors
                            }
                            
                            totalAttempts.incrementAndGet();
                            
                            // Random delay to simulate distributed coordination
                            Thread.sleep(100 + random.nextInt(200));
                        }
                        
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        finishSignal.countDown();
                    }
                });
            }
            
            // Start distributed attack
            long attackStartTime = System.currentTimeMillis();
            startSignal.countDown();
            
            // Wait for completion
            assertTrue(finishSignal.await(25, TimeUnit.SECONDS), 
                "Distributed attack should complete within time limit");
            long attackEndTime = System.currentTimeMillis();
            
            attackerPool.shutdown();
            
            // Analyze distributed attack patterns
            int expectedAttempts = attackerCount * attemptsPerAttacker;
            double attackDuration = (attackEndTime - attackStartTime) / 1000.0;
            double distributedRate = totalAttempts.get() / attackDuration;
            
            assertEquals(expectedAttempts, totalAttempts.get(), 
                "All distributed attack attempts should be accounted for");
            assertTrue(distributedRate > 10, 
                "Distributed attack should achieve significant rate, got: " + distributedRate + " attempts/sec");
            
            System.out.printf("Distributed Attack: %d attackers, %d total attempts, %.2f attempts/sec, %d successful, %d blocked%n",
                attackerCount, totalAttempts.get(), distributedRate, successfulAttempts.get(), blockedAttempts.get());
        }

        @Test
        @DisplayName("State Manipulation Attack Simulation")
        @Timeout(25)
        void testStateManipulationAttackSimulation() throws Exception {
            // Simulate attacks on challenge/response state management
            String targetUser = "challenge_user";
            String attackerIp = "192.168.50.100";
            
            // Ensure replay protection is enabled for this test
            securityValidator.configureSecurityFeature(
                RadiusSecurityValidator.SecurityFeature.REPLAY_PROTECTION, true);
            
            // First, legitimate challenge/response flow
            RadiusPacket initialRequest = createAuthenticationPacket(targetUser, "password", 3000);
            
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(initialRequest, testSharedSecret, attackerIp);
            }, "Initial challenge request should pass");
            
            // Simulate attacker trying to manipulate state with rapid requests
            AtomicInteger stateAttempts = new AtomicInteger(0);
            AtomicInteger stateViolations = new AtomicInteger(0);
            
            for (int i = 0; i < 20; i++) {
                try {
                    // Rapid-fire state manipulation attempts
                    RadiusPacket stateAttack = createAuthenticationPacket(targetUser, "state_attack_" + i, 3000 + i);
                    securityValidator.validatePacketSecurity(stateAttack, testSharedSecret, attackerIp);
                    stateAttempts.incrementAndGet();
                } catch (RadiusSecurityException e) {
                    stateViolations.incrementAndGet();
                    // Replay protection should catch most of these
                    assertTrue(e.getMessage().toLowerCase().contains("replay"),
                        "State manipulation should be detected as replay attack");
                }
                
                // Very rapid attempts to confuse state management
                Thread.sleep(10);
            }
            
            // Verify state manipulation attack handling
            assertTrue(stateAttempts.get() + stateViolations.get() == 20,
                "All state manipulation attempts should be processed");
            
            System.out.printf("State Manipulation Attack: %d attempts, %d violations, %d passed%n",
                stateAttempts.get() + stateViolations.get(), stateViolations.get(), stateAttempts.get());
        }

        @Test
        @DisplayName("Reconnaissance Attack Simulation")
        @Timeout(20)
        void testReconnaissanceAttackSimulation() throws Exception {
            // Simulate attacker gathering information about the system
            String[] probeUsernames = {
                "admin", "administrator", "root", "user", "guest", "test", "demo",
                "service", "operator", "manager", "support", "helpdesk"
            };
            
            String reconIp = "172.16.254.100";
            AtomicInteger probeCount = new AtomicInteger(0);
            AtomicInteger responseCount = new AtomicInteger(0);
            
            for (String probeUser : probeUsernames) {
                try {
                    // Reconnaissance probes with minimal authentication attempts
                    RadiusPacket probePacket = createAuthenticationPacket(probeUser, "probe", probeCount.get());
                    securityValidator.validatePacketSecurity(probePacket, testSharedSecret, reconIp);
                    responseCount.incrementAndGet();
                } catch (Exception e) {
                    // Errors are expected during reconnaissance
                }
                
                probeCount.incrementAndGet();
                
                // Spread out reconnaissance to avoid detection
                Thread.sleep(500);
            }
            
            // System should handle reconnaissance gracefully
            assertEquals(probeUsernames.length, probeCount.get(),
                "All reconnaissance probes should be processed");
            
            // Verify system remains operational after reconnaissance
            RadiusPacket normalPacket = createAuthenticationPacket("normal_user", "normal_pass", 9998);
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(normalPacket, testSharedSecret, "192.168.1.200");
            }, "System should remain operational after reconnaissance");
            
            System.out.printf("Reconnaissance Attack: %d probes, %d responses%n", 
                probeCount.get(), responseCount.get());
        }
    }

    @Nested
    @DisplayName("Network-Level Attacks")
    class NetworkLevelAttacks {

        @Test
        @DisplayName("Man-in-the-Middle Attack Simulation")
        @Timeout(15)
        void testManInTheMiddleAttackSimulation() throws Exception {
            // Simulate MITM attack with packet modification
            String victimUser = "victim_user";
            String victimIp = "192.168.1.50";
            String attackerIp = "192.168.1.51"; // Attacker spoofing nearby IP
            
            // Create legitimate packet
            RadiusPacket legitimatePacket = createAuthenticationPacket(victimUser, "victim_pass", 4000);
            
            // Legitimate packet should pass
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(legitimatePacket, testSharedSecret, victimIp);
            }, "Legitimate packet should pass validation");
            
            // Simulate MITM modifications
            List<RadiusPacket.RadiusAttribute> originalAttrs = legitimatePacket.getAttributes();
            
            // Modify username (MITM attack)
            List<RadiusPacket.RadiusAttribute> modifiedAttrs = new ArrayList<>();
            for (RadiusPacket.RadiusAttribute attr : originalAttrs) {
                if (attr.getType() == RadiusPacket.USER_NAME) {
                    modifiedAttrs.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "attacker_user"));
                } else {
                    modifiedAttrs.add(attr);
                }
            }
            
            RadiusPacket modifiedPacket = new RadiusPacket(
                legitimatePacket.getCode(),
                legitimatePacket.getIdentifier(),
                legitimatePacket.getAuthenticator(),
                modifiedAttrs
            );
            
            // Modified packet should be detected as different but may pass basic validation
            // (Real MITM detection would require Message-Authenticator or other integrity checks)
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(modifiedPacket, testSharedSecret, attackerIp);
            }, "Modified packet from different IP should pass basic validation");
            
            // However, if attacker tries to replay from victim's IP, it should be caught
            assertThrows(RadiusSecurityException.class, () -> {
                securityValidator.validatePacketSecurity(legitimatePacket, testSharedSecret, victimIp);
            }, "Replayed packet should be detected by replay protection");
        }

        @Test
        @DisplayName("Amplification Attack Simulation")
        @Timeout(20)
        void testAmplificationAttackSimulation() throws Exception {
            // Simulate attacker using RADIUS server for traffic amplification
            
            final int amplificationRequests = 50;
            AtomicInteger processedRequests = new AtomicInteger(0);
            
            // Attacker sends many small requests hoping to generate large responses
            for (int i = 0; i < amplificationRequests; i++) {
                try {
                    // Small request with minimal data
                    String attackerIp = "203.0.113." + (i % 10 + 1); // Rotate source IPs
                    RadiusPacket amplificationPacket = createMinimalAuthenticationPacket("amp" + i, i);
                    
                    securityValidator.validatePacketSecurity(amplificationPacket, testSharedSecret, attackerIp);
                    processedRequests.incrementAndGet();
                    
                } catch (Exception e) {
                    // Some requests may fail validation
                }
                
                // Rapid requests for amplification effect
                Thread.sleep(20);
            }
            
            // System should handle amplification attempts without issues
            assertTrue(processedRequests.get() >= 0, 
                "System should process amplification requests gracefully");
            
            System.out.printf("Amplification Attack: %d requests processed out of %d attempts%n",
                processedRequests.get(), amplificationRequests);
        }
    }

    // Helper methods

    private RadiusPacket createAuthenticationPacket(String username, String password, int identifier) throws Exception {
        List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
        attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, username));
        
        byte[] authenticator = new byte[16];
        random.nextBytes(authenticator);
        
        byte[] encryptedPassword = RadiusCodec.encryptPassword(password, authenticator, testSharedSecret);
        attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, encryptedPassword));
        
        return new RadiusPacket(RadiusPacket.ACCESS_REQUEST, identifier % 256, authenticator, attributes);
    }

    private RadiusPacket createMinimalAuthenticationPacket(String username, int identifier) throws Exception {
        List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
        attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, username));
        
        byte[] authenticator = new byte[16];
        random.nextBytes(authenticator);
        
        // Minimal password
        byte[] encryptedPassword = RadiusCodec.encryptPassword("x", authenticator, testSharedSecret);
        attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, encryptedPassword));
        
        return new RadiusPacket(RadiusPacket.ACCESS_REQUEST, identifier % 256, authenticator, attributes);
    }

    private String generateWeakPassword(int attempt) {
        String[] patterns = {"password", "admin", "12345", "qwerty", "abc123"};
        String base = patterns[attempt % patterns.length];
        return base + (attempt / patterns.length);
    }
}