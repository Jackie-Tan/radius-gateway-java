package com.radiusgateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Properties;

/**
 * Manages RADIUS server configuration including loading properties,
 * creating NAS registry, authentication backend, and handlers.
 */
public class ConfigurationManager {
    
    private static final Logger logger = LoggerFactory.getLogger(ConfigurationManager.class);
    
    private final Properties config;
    
    public ConfigurationManager(String configFile) throws IOException {
        this.config = loadConfiguration(configFile);
    }
    
    /**
     * Loads configuration from the specified file.
     * 
     * @param configFile path to configuration file
     * @return loaded properties
     * @throws IOException if configuration cannot be loaded
     */
    private Properties loadConfiguration(String configFile) throws IOException {
        Properties config = new Properties();
        
        try (FileInputStream fis = new FileInputStream(configFile)) {
            config.load(fis);
            logger.info("Configuration loaded from: {}", configFile);
        } catch (IOException e) {
            logger.warn("Could not load config file: {}. Using defaults.", configFile);
            // Load default configuration
            config.setProperty("radius.port", "1812");
            config.setProperty("radius.thread.pool.size", "10");
            config.setProperty("auth.otp.length", "6");
            config.setProperty("nas.vpngateway.ip", "192.168.203.1");
            config.setProperty("nas.vpngateway.secret", "YourStrongSecret123!");
            config.setProperty("nas.vpngateway.description", "VPN Gateway");
            throw e; // Re-throw to indicate configuration loading failed
        }
        
        return config;
    }
    
    /**
     * Creates and configures the NAS registry from configuration.
     * 
     * @return configured NAS registry
     * @throws Exception if NAS registry creation fails
     */
    public NasRegistry createNasRegistry() throws Exception {
        NasRegistry registry = new NasRegistry();
        
        // Register VPN Gateway
        String vpnGatewayIp = config.getProperty("nas.vpngateway.ip");
        String vpnGatewaySecret = config.getProperty("nas.vpngateway.secret");
        String vpnGatewayDesc = config.getProperty("nas.vpngateway.description", "VPN Gateway");
        
        if (vpnGatewayIp != null && vpnGatewaySecret != null) {
            InetAddress vpnGatewayAddr = InetAddress.getByName(vpnGatewayIp);
            registry.registerClient(vpnGatewayAddr, vpnGatewaySecret, vpnGatewayDesc);
            logger.info("Registered VPN Gateway: {} with shared secret", vpnGatewayIp);
        }
        
        // Register additional NAS clients
        for (String key : config.stringPropertyNames()) {
            if (key.startsWith("nas.") && key.endsWith(".ip") && !key.contains("vpngateway")) {
                String prefix = key.substring(0, key.lastIndexOf(".ip"));
                String ip = config.getProperty(key);
                String secret = config.getProperty(prefix + ".secret");
                String desc = config.getProperty(prefix + ".description", "NAS Client");
                
                if (ip != null && secret != null) {
                    InetAddress addr = InetAddress.getByName(ip);
                    registry.registerClient(addr, secret, desc);
                    logger.info("Registered NAS client: {} ({})", ip, desc);
                }
            }
        }
        
        logger.info("NAS Registry created with {} clients", registry.getClientCount());
        return registry;
    }
    
    /**
     * Creates the authentication backend from configuration.
     * 
     * @return configured authentication backend
     */
    public AuthBackend createAuthBackend() {
        logger.info("Creating configurable authentication backend");
        return new ConfigurableAuthBackend(config);
    }
    
    /**
     * Creates the appropriate RADIUS handler based on configuration.
     * 
     * @param authBackend the authentication backend to use
     * @return configured RADIUS handler
     */
    public RadiusHandler createRadiusHandler(AuthBackend authBackend) {
        String otpMode = getOtpMode();
        return HandlerFactory.createHandler(authBackend, otpMode, this);
    }
    
    /**
     * Gets the configured server port.
     * 
     * @return server port number
     */
    public int getServerPort() {
        return Integer.parseInt(config.getProperty("radius.port", "1812"));
    }
    
    /**
     * Gets the configured thread pool size.
     * 
     * @return thread pool size
     */
    public int getThreadPoolSize() {
        return Integer.parseInt(config.getProperty("radius.thread.pool.size", "10"));
    }
    
    /**
     * Gets the OTP mode from configuration.
     * 
     * @return OTP mode string
     */
    public String getOtpMode() {
        return config.getProperty("auth.otp.mode", "combined");
    }
    
    /**
     * Gets a property value from the configuration.
     * 
     * @param key the property key
     * @param defaultValue the default value if key is not found
     * @return property value or default
     */
    public String getProperty(String key, String defaultValue) {
        return config.getProperty(key, defaultValue);
    }
    
    /**
     * Gets a property value from the configuration.
     * 
     * @param key the property key
     * @return property value or null if not found
     */
    public String getProperty(String key) {
        return config.getProperty(key);
    }
    
    /**
     * Validates that all required configuration properties are present.
     * 
     * @throws IllegalStateException if required properties are missing
     */
    public void validateConfiguration() {
        // Check required properties
        String vpnGatewayIp = config.getProperty("nas.vpngateway.ip");
        String vpnGatewaySecret = config.getProperty("nas.vpngateway.secret");
        
        if (vpnGatewayIp == null || vpnGatewayIp.trim().isEmpty()) {
            throw new IllegalStateException("Missing required property: nas.vpngateway.ip");
        }
        
        if (vpnGatewaySecret == null || vpnGatewaySecret.trim().isEmpty()) {
            throw new IllegalStateException("Missing required property: nas.vpngateway.secret");
        }
        
        // Validate OTP mode
        String otpMode = getOtpMode();
        if (!HandlerFactory.isValidOtpMode(otpMode)) {
            throw new IllegalStateException("Invalid OTP mode: " + otpMode + 
                                          ". Supported modes: " + String.join(", ", HandlerFactory.getSupportedModes()));
        }
        
        // Validate numeric properties
        try {
            getServerPort();
            getThreadPoolSize();
        } catch (NumberFormatException e) {
            throw new IllegalStateException("Invalid numeric configuration property", e);
        }
        
        logger.info("Configuration validation passed");
    }
    
    
    /**
     * Logs the current configuration summary.
     */
    public void logConfigurationSummary() {
        logger.info("Configuration Summary:");
        logger.info("  - Port: {}", getServerPort());
        logger.info("  - Thread Pool Size: {}", getThreadPoolSize());
        logger.info("  - OTP Mode: {}", getOtpMode());
        
        int nasClientCount = 0;
        for (String key : config.stringPropertyNames()) {
            if (key.startsWith("nas.") && key.endsWith(".ip")) {
                nasClientCount++;
            }
        }
        logger.info("  - Configured NAS Clients: {}", nasClientCount);
    }
    
    /**
     * Configurable authentication backend for production use.
     * In real deployment, replace this with your actual authentication system.
     */
    private static class ConfigurableAuthBackend implements AuthBackend {
        private final Properties config;
        private final int configuredOtpLength;
        
        public ConfigurableAuthBackend(Properties config) {
            this.config = config;
            // Get configured OTP length, default to 6
            String otpLengthStr = config.getProperty("auth.otp.length", "6");
            try {
                this.configuredOtpLength = Integer.parseInt(otpLengthStr);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid OTP length configuration: " + otpLengthStr, e);
            }
        }
        
        @Override
        public AuthResult authenticate(String username, String password) {
            return authenticate(username, password, null);
        }
        
        @Override
        public AuthResult authenticate(String username, String password, String otp) {
            logger.debug("Authentication attempt for user: {} (password={}, otp={})", 
                        username, password != null ? "[provided]" : "[missing]", 
                        otp != null ? "[provided]" : "[missing]");
            
            // Demo authentication - replace with your actual backend
            String expectedPassword = config.getProperty("demo.user." + username);
            
            if (expectedPassword == null) {
                logger.warn("User '{}' not found in configuration", username);
                return AuthResult.failure("User not found", "Invalid credentials");
            }
            
            // Handle different authentication scenarios
            if (otp == null || otp.isEmpty()) {
                // Password-only authentication (Stage 1 of two-stage, or single-stage)
                if (expectedPassword.equals(password)) {
                    logger.debug("Password authentication successful for user: {}", username);
                    return AuthResult.success("Password validated");
                } else {
                    logger.warn("Password authentication failed for user: {}", username);
                    return AuthResult.failure("Invalid password", "Invalid credentials");
                }
            } else if (password == null || password.isEmpty()) {
                // OTP-only authentication (Stage 2 of two-stage, or OTP-only mode)
                String otpPattern = "\\d{" + configuredOtpLength + "}"; // Use configured OTP length
                if (otp.matches(otpPattern)) {
                    logger.debug("OTP-only authentication successful for user: {} (OTP length: {})", username, configuredOtpLength);
                    return AuthResult.success("Welcome " + username + "!");
                } else {
                    logger.warn("OTP-only authentication failed for user: {} (invalid format: '{}', expected {} digits)", 
                               username, otp, configuredOtpLength);
                    return AuthResult.failure("Invalid OTP format", "Invalid OTP code");
                }
            } else {
                // Combined password+OTP authentication (single-stage modes)
                String otpPattern = "\\d{" + configuredOtpLength + "}"; // Use configured OTP length
                if (expectedPassword.equals(password) && otp.matches(otpPattern)) {
                    logger.debug("Combined authentication successful for user: {} (OTP length: {})", username, configuredOtpLength);
                    return AuthResult.success("Welcome " + username + "!");
                } else {
                    logger.warn("Combined authentication failed for user: {} (expected OTP length: {})", username, configuredOtpLength);
                    return AuthResult.failure("Invalid credentials", "Authentication failed");
                }
            }
        }
    }
}