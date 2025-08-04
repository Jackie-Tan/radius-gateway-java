package com.radiusgateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class RadiusServer {
    
    private static final Logger logger = LoggerFactory.getLogger(RadiusServer.class);
    private static final int DEFAULT_PORT = 1812;
    private static final int DEFAULT_BUFFER_SIZE = 4096;
    private static final int DEFAULT_THREAD_POOL_SIZE = 10;
    
    private final int port;
    private final NasRegistry nasRegistry;
    private final RadiusHandler radiusHandler;
    private final RadiusSecurityValidator securityValidator;
    private final ExecutorService executorService;
    private final AtomicBoolean running = new AtomicBoolean(false);
    
    private DatagramSocket socket;
    private Thread serverThread;
    
    public RadiusServer(NasRegistry nasRegistry, RadiusHandler radiusHandler) {
        this(DEFAULT_PORT, nasRegistry, radiusHandler, new RadiusSecurityValidatorImpl());
    }
    
    public RadiusServer(int port, NasRegistry nasRegistry, RadiusHandler radiusHandler) {
        this(port, nasRegistry, radiusHandler, new RadiusSecurityValidatorImpl(), DEFAULT_THREAD_POOL_SIZE);
    }
    
    public RadiusServer(int port, NasRegistry nasRegistry, RadiusHandler radiusHandler, RadiusSecurityValidator securityValidator) {
        this(port, nasRegistry, radiusHandler, securityValidator, DEFAULT_THREAD_POOL_SIZE);
    }
    
    public RadiusServer(int port, NasRegistry nasRegistry, RadiusHandler radiusHandler, RadiusSecurityValidator securityValidator, int threadPoolSize) {
        if (port <= 0 || port > 65535) {
            throw new IllegalArgumentException("Invalid port: " + port);
        }
        if (nasRegistry == null) {
            throw new IllegalArgumentException("NasRegistry cannot be null");
        }
        if (radiusHandler == null) {
            throw new IllegalArgumentException("RadiusHandler cannot be null");
        }
        if (securityValidator == null) {
            throw new IllegalArgumentException("RadiusSecurityValidator cannot be null");
        }
        if (threadPoolSize <= 0) {
            throw new IllegalArgumentException("Thread pool size must be positive");
        }
        
        this.port = port;
        this.nasRegistry = nasRegistry;
        this.radiusHandler = radiusHandler;
        this.securityValidator = securityValidator;
        this.executorService = Executors.newFixedThreadPool(threadPoolSize);
    }
    
    public void start() throws IOException {
        if (running.get()) {
            throw new IllegalStateException("Server is already running");
        }
        
        logger.info("Starting RADIUS server on port {}", port);
        
        socket = new DatagramSocket(port);
        running.set(true);
        
        serverThread = new Thread(this::serverLoop, "RadiusServer-" + port);
        serverThread.setDaemon(false);
        serverThread.start();
        
        logger.info("RADIUS server started successfully on port {}", port);
    }
    
    public void stop() {
        if (!running.get()) {
            return;
        }
        
        logger.info("Stopping RADIUS server on port {}", port);
        running.set(false);
        
        if (socket != null && !socket.isClosed()) {
            socket.close();
        }
        
        if (serverThread != null) {
            try {
                serverThread.join(5000); // Wait up to 5 seconds
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.warn("Interrupted while waiting for server thread to stop");
            }
        }
        
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(10, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            executorService.shutdownNow();
        }
        
        // Shutdown security validator
        if (securityValidator instanceof RadiusSecurityValidatorImpl) {
            ((RadiusSecurityValidatorImpl) securityValidator).shutdown();
        }
        
        logger.info("RADIUS server stopped");
    }
    
    public boolean isRunning() {
        return running.get();
    }
    
    public int getPort() {
        return port;
    }
    
    private void serverLoop() {
        byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
        
        while (running.get() && !socket.isClosed()) {
            try {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);
                
                // Process request in thread pool
                executorService.submit(() -> processRequest(packet));
                
            } catch (SocketException e) {
                if (running.get()) {
                    logger.error("Socket error in server loop", e);
                }
                // Socket closed, likely due to shutdown
                break;
            } catch (IOException e) {
                if (running.get()) {
                    logger.error("I/O error in server loop", e);
                }
            } catch (Exception e) {
                logger.error("Unexpected error in server loop", e);
            }
        }
        
        logger.debug("Server loop exited");
    }
    
    private void processRequest(DatagramPacket packet) {
        InetAddress clientAddress = packet.getAddress();
        int clientPort = packet.getPort();
        
        try {
            // Check if client is registered
            if (!nasRegistry.isClientRegistered(clientAddress)) {
                logger.warn("Rejecting request from unregistered client: {}", 
                          clientAddress.getHostAddress());
                return;
            }
            
            NasRegistry.NasClient nasClient = nasRegistry.getClient(clientAddress);
            nasClient.recordAccess();
            
            String sharedSecret = nasClient.getSharedSecret();
            
            // Parse RADIUS packet
            byte[] packetData = new byte[packet.getLength()];
            System.arraycopy(packet.getData(), packet.getOffset(), packetData, 0, packet.getLength());
            
            RadiusPacket requestPacket = RadiusPacket.decode(packetData);
            
            logger.debug("Received {} packet from {} (ID: {})", 
                        getPacketTypeName(requestPacket.getCode()),
                        clientAddress.getHostAddress(), 
                        requestPacket.getIdentifier());
            
            // Only handle Access-Request packets for now
            if (requestPacket.getCode() != RadiusPacket.ACCESS_REQUEST) {
                logger.warn("Ignoring unsupported packet type {} from {}", 
                          requestPacket.getCode(), clientAddress.getHostAddress());
                return;
            }
            
            // Comprehensive security validation (RFC 2865, RFC 2869, RFC 5080)
            try {
                securityValidator.validatePacketSecurity(requestPacket, sharedSecret, 
                                                       clientAddress.getHostAddress());
                logger.debug("Security validation passed for packet from {}", 
                           clientAddress.getHostAddress());
                
            } catch (RadiusSecurityException e) {
                logger.warn("Security validation failed for packet from {}: {}", 
                           clientAddress.getHostAddress(), e.getMessage());
                
                // For security violations, we typically don't send a response
                // to avoid providing information to attackers
                return;
                
            } catch (RadiusValidationException e) {
                logger.warn("Packet validation failed from {}: {}", 
                           clientAddress.getHostAddress(), e.getMessage());
                
                // For validation errors, we might send an Access-Reject
                // depending on the error type
                sendValidationErrorResponse(requestPacket, clientAddress, clientPort, 
                                          sharedSecret, e);
                return;
            }
            
            // Create request context
            RadiusHandler.RadiusRequest request = new RadiusHandler.RadiusRequest(
                requestPacket, clientAddress, sharedSecret);
            
            // Handle request
            RadiusHandler.RadiusResponse response = radiusHandler.handleAccessRequest(request);
            
            // Build response packet
            RadiusPacket responsePacket = RadiusResponseBuilder.buildFromResponse(
                response, 
                requestPacket.getIdentifier(),
                requestPacket.getAuthenticator(), 
                sharedSecret
            );
            
            // Send response
            byte[] responseData = responsePacket.encode();
            DatagramPacket responseUdpPacket = new DatagramPacket(
                responseData, responseData.length, clientAddress, clientPort);
            
            socket.send(responseUdpPacket);
            
            logger.debug("Sent {} response to {} (ID: {})", 
                        getPacketTypeName(responsePacket.getCode()),
                        clientAddress.getHostAddress(),
                        responsePacket.getIdentifier());
            
        } catch (RadiusPacket.RadiusException e) {
            logger.warn("Invalid RADIUS packet from {}: {}", 
                       clientAddress.getHostAddress(), e.getMessage());
        } catch (Exception e) {
            logger.error("Error processing request from {}", 
                        clientAddress.getHostAddress(), e);
        }
    }
    
    /**
     * Sends an appropriate response for validation errors.
     * For some validation errors, we send Access-Reject. For security violations,
     * we typically don't respond to avoid providing information to attackers.
     */
    private void sendValidationErrorResponse(RadiusPacket requestPacket, 
                                           InetAddress clientAddress, 
                                           int clientPort,
                                           String sharedSecret, 
                                           RadiusValidationException e) {
        try {
            // For most validation errors, send Access-Reject with appropriate message
            RadiusHandler.RadiusResponse errorResponse = RadiusHandler.RadiusResponse.reject(
                "Packet validation failed: " + e.getMessage()
            );
            
            RadiusPacket responsePacket = RadiusResponseBuilder.buildFromResponse(
                errorResponse,
                requestPacket.getIdentifier(),
                requestPacket.getAuthenticator(),
                sharedSecret
            );
            
            byte[] responseData = responsePacket.encode();
            DatagramPacket responseUdpPacket = new DatagramPacket(
                responseData, responseData.length, clientAddress, clientPort);
            
            socket.send(responseUdpPacket);
            
            logger.debug("Sent validation error response to {} (ID: {})", 
                        clientAddress.getHostAddress(), responsePacket.getIdentifier());
                        
        } catch (Exception sendError) {
            logger.error("Failed to send validation error response to {}: {}", 
                        clientAddress.getHostAddress(), sendError.getMessage());
        }
    }
    
    private String getPacketTypeName(int code) {
        switch (code) {
            case RadiusPacket.ACCESS_REQUEST:
                return "Access-Request";
            case RadiusPacket.ACCESS_ACCEPT:
                return "Access-Accept";
            case RadiusPacket.ACCESS_REJECT:
                return "Access-Reject";
            case RadiusPacket.ACCESS_CHALLENGE:
                return "Access-Challenge";
            case RadiusPacket.ACCOUNTING_REQUEST:
                return "Accounting-Request";
            case RadiusPacket.ACCOUNTING_RESPONSE:
                return "Accounting-Response";
            default:
                return "Unknown(" + code + ")";
        }
    }
    
    
    public static void main(String[] args) {
        // Delegate to RadiusServerLifecycle for lifecycle management
        RadiusServerLifecycle.main(args);
    }
}