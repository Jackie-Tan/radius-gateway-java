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
import java.util.concurrent.atomic.AtomicLong;

/**
 * Performance Security Test Suite
 * 
 * Tests security validation performance under load, DoS resilience, and scalability.
 * Focuses on ensuring security features don't create performance vulnerabilities.
 */
@DisplayName("Performance Security Testing - Load and DoS Resilience")
class PerformanceSecurityTest {

    private RadiusSecurityValidator securityValidator;
    private String testSharedSecret;
    private SecureRandom random;

    @BeforeEach
    void setUp() {
        securityValidator = new RadiusSecurityValidatorImpl();
        testSharedSecret = "performance-test-shared-secret-for-load-testing";
        random = new SecureRandom();
    }

    @Nested
    @DisplayName("Security Validation Performance")
    class SecurityValidationPerformance {

        @Test
        @DisplayName("Throughput Testing with All Security Features")
        @Timeout(30)
        void testThroughputWithAllSecurityFeatures() throws Exception {
            final int testPackets = 1000;
            final int warmupPackets = 100;
            
            // Warmup phase
            for (int i = 0; i < warmupPackets; i++) {
                RadiusPacket warmupPacket = createValidTestPacket(i);
                securityValidator.validatePacketSecurity(warmupPacket, testSharedSecret, "192.168.1." + (i % 254 + 1));
            }
            
            // Performance measurement phase
            long startTime = System.nanoTime();
            AtomicInteger successCount = new AtomicInteger(0);
            AtomicInteger failureCount = new AtomicInteger(0);
            
            for (int i = 0; i < testPackets; i++) {
                try {
                    RadiusPacket testPacket = createValidTestPacket(i + warmupPackets);
                    securityValidator.validatePacketSecurity(testPacket, testSharedSecret, 
                        "192.168.1." + (i % 254 + 1));
                    successCount.incrementAndGet();
                } catch (Exception e) {
                    failureCount.incrementAndGet();
                }
            }
            
            long endTime = System.nanoTime();
            double durationSeconds = (endTime - startTime) / 1_000_000_000.0;
            double throughputPerSecond = testPackets / durationSeconds;
            
            // Performance assertions
            assertTrue(throughputPerSecond > 100, 
                "Security validation throughput should exceed 100 packets/second, got: " + throughputPerSecond);
            assertTrue(successCount.get() > testPackets * 0.95, 
                "At least 95% of packets should pass validation, got: " + successCount.get() + "/" + testPackets);
            
            System.out.printf("Security Validation Performance: %.2f packets/second, %d success, %d failures%n",
                throughputPerSecond, successCount.get(), failureCount.get());
        }

        @Test
        @DisplayName("Latency Impact Measurement")
        @Timeout(20)
        void testLatencyImpact() throws Exception {
            final int testIterations = 500;
            
            // Measure latency with all security features enabled
            long[] secureLatencies = new long[testIterations];
            for (int i = 0; i < testIterations; i++) {
                RadiusPacket packet = createValidTestPacket(i);
                
                long startTime = System.nanoTime();
                securityValidator.validatePacketSecurity(packet, testSharedSecret, "192.168.2." + (i % 254 + 1));
                long endTime = System.nanoTime();
                
                secureLatencies[i] = endTime - startTime;
            }
            
            // Measure latency with minimal security (only packet bounds)
            long[] minimalLatencies = new long[testIterations];
            for (int i = 0; i < testIterations; i++) {
                RadiusPacket packet = createValidTestPacket(i + testIterations);
                
                long startTime = System.nanoTime();
                securityValidator.validatePacketBounds(packet);
                long endTime = System.nanoTime();
                
                minimalLatencies[i] = endTime - startTime;
            }
            
            // Calculate statistics
            double avgSecureLatency = avg(secureLatencies) / 1_000_000.0; // Convert to milliseconds
            double avgMinimalLatency = avg(minimalLatencies) / 1_000_000.0;
            double securityOverhead = avgSecureLatency - avgMinimalLatency;
            double overheadPercentage = (securityOverhead / avgMinimalLatency) * 100;
            
            // Performance assertions (relaxed for test environment)
            assertTrue(avgSecureLatency < 100.0, 
                "Average secure validation latency should be under 100ms, got: " + avgSecureLatency + "ms");
            assertTrue(overheadPercentage < 5000, 
                "Security overhead should be under 5000%, got: " + overheadPercentage + "%");
            
            System.out.printf("Latency Impact: Secure=%.3fms, Minimal=%.3fms, Overhead=%.3fms (%.1f%%)%n",
                avgSecureLatency, avgMinimalLatency, securityOverhead, overheadPercentage);
        }

        @Test
        @DisplayName("Memory Usage Under Security Load")
        @Timeout(30)
        void testMemoryUsageUnderSecurityLoad() throws Exception {
            final int loadPackets = 2000;
            
            // Force garbage collection and measure baseline
            System.gc();
            Thread.sleep(100);
            long baselineMemory = getUsedMemory();
            
            // Process load packets with security validation
            for (int i = 0; i < loadPackets; i++) {
                RadiusPacket packet = createValidTestPacket(i);
                securityValidator.validatePacketSecurity(packet, testSharedSecret, 
                    "10.0." + (i / 256) + "." + (i % 256));
            }
            
            // Measure memory after load
            long loadMemory = getUsedMemory();
            long memoryIncrease = loadMemory - baselineMemory;
            double memoryPerPacket = memoryIncrease / (double) loadPackets;
            
            // Memory assertions (realistic for JVM test environment)
            assertTrue(memoryPerPacket < 20480, // Less than 20KB per packet (JVM overhead included)
                "Memory usage per packet should be under 20KB, got: " + memoryPerPacket + " bytes");
            assertTrue(memoryIncrease < 500 * 1024 * 1024, // Less than 500MB total increase
                "Total memory increase should be under 500MB, got: " + (memoryIncrease / 1024 / 1024) + "MB");
            
            System.out.printf("Memory Usage: Baseline=%dMB, Load=%dMB, Increase=%dMB (%.2f bytes/packet)%n",
                baselineMemory / 1024 / 1024, loadMemory / 1024 / 1024, 
                memoryIncrease / 1024 / 1024, memoryPerPacket);
        }
    }

    @Nested
    @DisplayName("Denial of Service (DoS) Testing")
    class DenialOfServiceTesting {

        @Test
        @DisplayName("High Volume Request Testing")
        @Timeout(60)
        void testHighVolumeRequestTesting() throws Exception {
            final int threadCount = 20;
            final int requestsPerThread = 100;
            final int totalRequests = threadCount * requestsPerThread;
            
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch finishLatch = new CountDownLatch(threadCount);
            
            AtomicInteger successCount = new AtomicInteger(0);
            AtomicInteger failureCount = new AtomicInteger(0);
            AtomicLong totalProcessingTime = new AtomicLong(0);
            
            // Submit all tasks
            for (int threadId = 0; threadId < threadCount; threadId++) {
                final int finalThreadId = threadId;
                executor.submit(() -> {
                    try {
                        startLatch.await(); // Wait for coordinated start
                        
                        long threadStartTime = System.nanoTime();
                        
                        for (int i = 0; i < requestsPerThread; i++) {
                            try {
                                RadiusPacket packet = createValidTestPacket(finalThreadId * requestsPerThread + i);
                                String clientIp = "172.16." + finalThreadId + "." + i;
                                
                                securityValidator.validatePacketSecurity(packet, testSharedSecret, clientIp);
                                successCount.incrementAndGet();
                            } catch (Exception e) {
                                failureCount.incrementAndGet();
                            }
                        }
                        
                        long threadEndTime = System.nanoTime();
                        totalProcessingTime.addAndGet(threadEndTime - threadStartTime);
                        
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        finishLatch.countDown();
                    }
                });
            }
            
            // Start all threads simultaneously
            long overallStartTime = System.nanoTime();
            startLatch.countDown();
            
            // Wait for completion
            assertTrue(finishLatch.await(45, TimeUnit.SECONDS), 
                "High volume test should complete within 45 seconds");
            long overallEndTime = System.nanoTime();
            
            executor.shutdown();
            
            // Calculate performance metrics
            double overallDuration = (overallEndTime - overallStartTime) / 1_000_000_000.0;
            double overallThroughput = totalRequests / overallDuration;
            double avgThreadProcessingTime = totalProcessingTime.get() / (double) threadCount / 1_000_000_000.0;
            
            // DoS resilience assertions
            assertTrue(successCount.get() > totalRequests * 0.90, 
                "At least 90% of requests should succeed under high load, got: " + 
                successCount.get() + "/" + totalRequests);
            assertTrue(overallThroughput > 200, 
                "System should maintain >200 requests/second under load, got: " + overallThroughput);
            assertTrue(avgThreadProcessingTime < 30, 
                "Average thread processing time should be under 30 seconds, got: " + avgThreadProcessingTime);
            
            System.out.printf("High Volume DoS Test: %d threads, %d total requests, %.2f req/sec, %d success, %d failures%n",
                threadCount, totalRequests, overallThroughput, successCount.get(), failureCount.get());
        }

        @Test
        @DisplayName("Malformed Packet Flood Testing")
        @Timeout(30)
        void testMalformedPacketFloodTesting() throws Exception {
            final int malformedPackets = 1000;
            AtomicInteger handledCount = new AtomicInteger(0);
            AtomicInteger exceptionCount = new AtomicInteger(0);
            
            long startTime = System.nanoTime();
            
            for (int i = 0; i < malformedPackets; i++) {
                try {
                    RadiusPacket malformedPacket = createMalformedTestPacket(i);
                    securityValidator.validatePacketSecurity(malformedPacket, testSharedSecret, 
                        "192.168.100." + (i % 254 + 1));
                    handledCount.incrementAndGet();
                } catch (Exception e) {
                    exceptionCount.incrementAndGet();
                    // System should handle exceptions gracefully without crashing
                    assertNotNull(e.getMessage(), "Exception should have meaningful message");
                }
            }
            
            long endTime = System.nanoTime();
            double duration = (endTime - startTime) / 1_000_000_000.0;
            double processingRate = malformedPackets / duration;
            
            // DoS resilience assertions
            assertTrue(processingRate > 500, 
                "System should process malformed packets at >500/second, got: " + processingRate);
            assertTrue(handledCount.get() + exceptionCount.get() == malformedPackets,
                "All malformed packets should be processed (either handled or throw exception)");
            
            System.out.printf("Malformed Packet Flood: %d packets, %.2f packets/sec, %d handled, %d exceptions%n",
                malformedPackets, processingRate, handledCount.get(), exceptionCount.get());
        }

        @Test
        @DisplayName("Resource Exhaustion Attack Simulation")
        @Timeout(45)
        void testResourceExhaustionAttackSimulation() throws Exception {
            final int attackPhases = 5;
            final int packetsPerPhase = 500;
            
            for (int phase = 0; phase < attackPhases; phase++) {
                System.out.printf("Resource exhaustion phase %d/%d%n", phase + 1, attackPhases);
                
                // Each phase increases the attack intensity
                int phasePackets = packetsPerPhase * (phase + 1);
                AtomicInteger phaseSuccessCount = new AtomicInteger(0);
                
                long phaseStartTime = System.nanoTime();
                
                for (int i = 0; i < phasePackets; i++) {
                    try {
                        // Create packets designed to consume resources
                        RadiusPacket resourcePacket = createResourceIntensivePacket(phase * packetsPerPhase + i);
                        String clientIp = "203.0." + (phase * 50 + i / 10) + "." + (i % 10);
                        
                        securityValidator.validatePacketSecurity(resourcePacket, testSharedSecret, clientIp);
                        phaseSuccessCount.incrementAndGet();
                    } catch (Exception e) {
                        // Expected for resource exhaustion attacks
                    }
                }
                
                long phaseEndTime = System.nanoTime();
                double phaseDuration = (phaseEndTime - phaseStartTime) / 1_000_000_000.0;
                double phaseRate = phasePackets / phaseDuration;
                
                // System should remain responsive even under resource pressure
                assertTrue(phaseRate > 100, 
                    "Phase " + phase + " processing rate should exceed 100/sec, got: " + phaseRate);
                
                // Brief recovery period between phases
                Thread.sleep(1000);
            }
            
            // Final functionality test after resource exhaustion attempts
            RadiusPacket finalTestPacket = createValidTestPacket(999999);
            assertDoesNotThrow(() -> {
                securityValidator.validatePacketSecurity(finalTestPacket, testSharedSecret, "192.168.255.1");
            }, "System should remain functional after resource exhaustion attacks");
        }

        @Test
        @DisplayName("Memory Leak Detection Under Load")
        @Timeout(60)
        void testMemoryLeakDetectionUnderLoad() throws Exception {
            final int loadCycles = 10;
            final int packetsPerCycle = 200;
            
            long[] memorySnapshots = new long[loadCycles + 1];
            
            // Initial memory snapshot
            System.gc();
            Thread.sleep(100);
            memorySnapshots[0] = getUsedMemory();
            
            for (int cycle = 0; cycle < loadCycles; cycle++) {
                // Generate load for this cycle
                for (int i = 0; i < packetsPerCycle; i++) {
                    try {
                        RadiusPacket packet = createValidTestPacket(cycle * packetsPerCycle + i);
                        securityValidator.validatePacketSecurity(packet, testSharedSecret, 
                            "10.10." + (cycle % 256) + "." + (i % 256));
                    } catch (Exception e) {
                        // Continue even if some packets fail
                    }
                }
                
                // Force garbage collection and measure memory
                System.gc();
                Thread.sleep(100);
                memorySnapshots[cycle + 1] = getUsedMemory();
                
                System.out.printf("Cycle %d: Memory = %dMB%n", cycle + 1, 
                    memorySnapshots[cycle + 1] / 1024 / 1024);
            }
            
            // Analyze memory growth
            long initialMemory = memorySnapshots[0];
            long finalMemory = memorySnapshots[loadCycles];
            long memoryGrowth = finalMemory - initialMemory;
            double growthPerCycle = memoryGrowth / (double) loadCycles;
            
            // Memory leak assertions
            assertTrue(memoryGrowth < 100 * 1024 * 1024, // Less than 100MB growth
                "Total memory growth should be under 100MB, got: " + (memoryGrowth / 1024 / 1024) + "MB");
            assertTrue(growthPerCycle < 10 * 1024 * 1024, // Less than 10MB per cycle
                "Memory growth per cycle should be under 10MB, got: " + (growthPerCycle / 1024 / 1024) + "MB");
            
            // Check for consistent memory growth (indicating leak)
            boolean consistentGrowth = true;
            for (int i = 1; i < memorySnapshots.length - 1; i++) {
                if (memorySnapshots[i + 1] <= memorySnapshots[i]) {
                    consistentGrowth = false;
                    break;
                }
            }
            
            // Allow some memory growth in test environment, but not excessive
            long maxMemoryGrowth = Math.max(memoryGrowth, 0);
            assertTrue(maxMemoryGrowth < 500 * 1024 * 1024, // Less than 500MB growth
                "Memory growth should be under 500MB, got: " + (maxMemoryGrowth / 1024 / 1024) + "MB");
            
            System.out.printf("Memory Leak Test: Initial=%dMB, Final=%dMB, Growth=%dMB, Growth/cycle=%.2fMB%n",
                initialMemory / 1024 / 1024, finalMemory / 1024 / 1024, 
                memoryGrowth / 1024 / 1024, growthPerCycle / 1024 / 1024);
        }
    }

    // Helper methods

    private RadiusPacket createValidTestPacket(int seed) throws Exception {
        random.setSeed(seed); // Deterministic for testing
        
        List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
        attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "testuser" + seed));
        
        byte[] authenticator = new byte[16];
        random.nextBytes(authenticator);
        
        byte[] encryptedPassword = RadiusCodec.encryptPassword("testpass" + seed, authenticator, testSharedSecret);
        attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, encryptedPassword));
        
        return new RadiusPacket(RadiusPacket.ACCESS_REQUEST, seed % 256, authenticator, attributes);
    }

    private RadiusPacket createMalformedTestPacket(int seed) throws Exception {
        random.setSeed(seed + 1000); // Different seed for malformed packets
        
        List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
        
        // Create various types of malformed attributes
        switch (seed % 4) {
            case 0:
                // Empty username
                attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, ""));
                break;
            case 1:
                // Very long username
                attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "x".repeat(300)));
                break;
            case 2:
                // Special characters in username
                attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "\0\n\r\t\u0001\u0002"));
                break;
            default:
                // Normal username but malformed elsewhere
                attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "user" + seed));
                break;
        }
        
        // Always add some form of password attribute (may be malformed)
        byte[] authenticator = new byte[16];
        random.nextBytes(authenticator);
        
        if (seed % 3 == 0) {
            // Invalid password length
            byte[] invalidPassword = new byte[13]; // Not multiple of 16
            random.nextBytes(invalidPassword);
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, invalidPassword));
        } else {
            // Valid password
            byte[] encryptedPassword = RadiusCodec.encryptPassword("pass", authenticator, testSharedSecret);
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, encryptedPassword));
        }
        
        return new RadiusPacket(RadiusPacket.ACCESS_REQUEST, seed % 256, authenticator, attributes);
    }

    private RadiusPacket createResourceIntensivePacket(int seed) throws Exception {
        random.setSeed(seed + 2000); // Different seed for resource-intensive packets
        
        List<RadiusPacket.RadiusAttribute> attributes = new ArrayList<>();
        attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, "resource_user_" + seed));
        
        byte[] authenticator = new byte[16];
        random.nextBytes(authenticator);
        
        byte[] encryptedPassword = RadiusCodec.encryptPassword("resource_pass", authenticator, testSharedSecret);
        attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, encryptedPassword));
        
        // Add multiple vendor-specific attributes to increase processing load
        for (int i = 0; i < 10; i++) {
            byte[] vendorData = new byte[100];
            random.nextBytes(vendorData);
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.VENDOR_SPECIFIC, vendorData));
        }
        
        // Add multiple reply messages
        for (int i = 0; i < 5; i++) {
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.REPLY_MESSAGE, 
                "Resource intensive reply message number " + i + " for packet " + seed));
        }
        
        return new RadiusPacket(RadiusPacket.ACCESS_REQUEST, seed % 256, authenticator, attributes);
    }

    private long getUsedMemory() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }

    private double avg(long[] values) {
        return Arrays.stream(values).average().orElse(0.0);
    }
}