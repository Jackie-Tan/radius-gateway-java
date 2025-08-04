package com.radiusgateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;

/**
 * Manages the lifecycle of RADIUS server instances including startup, shutdown,
 * and graceful handling of main application loop.
 */
public class RadiusServerLifecycle {
    
    private static final Logger logger = LoggerFactory.getLogger(RadiusServerLifecycle.class);
    
    private RadiusServer server;
    private Thread shutdownHook;
    
    /**
     * Starts RADIUS server with configuration.
     * 
     * @param configFile path to configuration file
     * @throws Exception if server startup fails
     */
    public void startWithConfiguration(String configFile) throws Exception {
        logger.info("Starting RADIUS Gateway with configuration: {}", configFile);
        
        // Load and validate configuration
        ConfigurationManager configManager = new ConfigurationManager(configFile);
        configManager.validateConfiguration();
        configManager.logConfigurationSummary();
        
        // Create components from configuration
        NasRegistry nasRegistry = configManager.createNasRegistry();
        AuthBackend authBackend = configManager.createAuthBackend();
        RadiusHandler handler = configManager.createRadiusHandler(authBackend);
        
        // Create server instance with default security validator
        server = new RadiusServer(
            configManager.getServerPort(), 
            nasRegistry, 
            handler, 
            new RadiusSecurityValidatorImpl(),
            configManager.getThreadPoolSize()
        );
        
        // Setup shutdown hook
        setupShutdownHook();
        
        // Start the server
        server.start();
        
        logger.info("RADIUS Gateway started successfully");
        logger.info("Ready to handle VPN Gateway authentication requests");
    }
    
    /**
     * Starts RADIUS server in demo mode.
     * 
     * @throws Exception if server startup fails
     */
    public void startDemoMode() throws Exception {
        logger.info("Starting RADIUS Gateway in demo mode");
        
        // Demo authentication backend
        AuthBackend demoBackend = new AuthBackend() {
            @Override
            public AuthResult authenticate(String username, String password) {
                return authenticate(username, password, null);
            }
            
            @Override
            public AuthResult authenticate(String username, String password, String otp) {
                // Demo implementation - accept test/test123 (password + 3-digit OTP)
                if ("test".equals(username) && "test".equals(password) && "123".equals(otp)) {
                    return AuthResult.success("Welcome!");
                }
                return AuthResult.failure("Invalid credentials");
            }
        };
        
        // Create components for demo
        NasRegistry nasRegistry = new NasRegistry();
        // Register localhost for testing
        nasRegistry.registerClient(InetAddress.getLoopbackAddress(), "secret", "Test Client");
        
        RadiusHandler handler = new CombinedPasswordOtpHandler(demoBackend, 3);
        server = new RadiusServer(nasRegistry, handler);
        
        // Setup shutdown hook
        setupShutdownHook();
        
        // Start the server
        server.start();
        
        logger.info("RADIUS Gateway started in demo mode");
        logger.info("Ready to handle test authentication requests");
    }
    
    /**
     * Runs the main application loop, keeping the server alive.
     * This method blocks until the server is stopped.
     */
    public void runMainLoop() {
        if (server == null) {
            throw new IllegalStateException("Server has not been started");
        }
        
        logger.info("Entering main application loop");
        
        // Keep main thread alive
        while (server.isRunning()) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                logger.info("Main loop interrupted, initiating shutdown");
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        logger.info("Main application loop exited");
    }
    
    /**
     * Gracefully stops the RADIUS server.
     */
    public void stop() {
        if (server != null && server.isRunning()) {
            logger.info("Stopping RADIUS server...");
            server.stop();
            logger.info("RADIUS server stopped");
        }
        
        // Remove shutdown hook if it was registered
        if (shutdownHook != null) {
            try {
                Runtime.getRuntime().removeShutdownHook(shutdownHook);
                shutdownHook = null;
            } catch (IllegalStateException e) {
                // Ignore - JVM is already shutting down
            }
        }
    }
    
    /**
     * Gets the current server instance.
     * 
     * @return the RadiusServer instance, or null if not started
     */
    public RadiusServer getServer() {
        return server;
    }
    
    /**
     * Checks if the server is currently running.
     * 
     * @return true if server is running, false otherwise
     */
    public boolean isRunning() {
        return server != null && server.isRunning();
    }
    
    /**
     * Sets up a JVM shutdown hook to gracefully stop the server.
     */
    private void setupShutdownHook() {
        shutdownHook = new Thread(() -> {
            logger.info("Shutdown hook triggered, stopping RADIUS server...");
            if (server != null && server.isRunning()) {
                server.stop();
            }
            logger.info("Shutdown hook completed");
        }, "RadiusServer-ShutdownHook");
        
        Runtime.getRuntime().addShutdownHook(shutdownHook);
        logger.debug("Shutdown hook registered");
    }
    
    /**
     * Main application entry point with lifecycle management.
     * 
     * @param args command line arguments
     */
    public static void main(String[] args) {
        RadiusServerLifecycle lifecycle = new RadiusServerLifecycle();
        
        try {
            if (args.length > 0) {
                // Production mode with config file
                lifecycle.startWithConfiguration(args[0]);
            } else {
                // Demo mode
                lifecycle.startDemoMode();
            }
            
            // Run main loop
            lifecycle.runMainLoop();
            
        } catch (Exception e) {
            logger.error("Failed to start RADIUS Gateway", e);
            System.exit(1);
        } finally {
            // Ensure cleanup
            lifecycle.stop();
        }
    }
}