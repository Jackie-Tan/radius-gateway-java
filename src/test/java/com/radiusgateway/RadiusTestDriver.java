package com.radiusgateway;

import java.io.IOException;
import java.net.*;
import java.util.Arrays;

/**
 * Test driver to simulate RADIUS Access-Request packets for testing the RadiusServer.
 * This tool helps verify interoperability and basic functionality.
 */
public class RadiusTestDriver {
    
    private static final String DEFAULT_HOST = "localhost";
    private static final int DEFAULT_PORT = 1812;
    private static final String DEFAULT_SECRET = "secret";
    
    public static void main(String[] args) {
        if (args.length > 0 && (args[0].equals("--help") || args[0].equals("-h"))) {
            printUsage();
            return;
        }
        
        String host = DEFAULT_HOST;
        int port = DEFAULT_PORT;
        String secret = DEFAULT_SECRET;
        String username = "test";
        String password = "test123"; // password + 3-digit OTP
        String otp = null; // separate OTP for separate mode
        boolean separateOtp = false;
        
        // Parse command line arguments
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--host":
                    if (i + 1 < args.length) host = args[++i];
                    break;
                case "--port":
                    if (i + 1 < args.length) port = Integer.parseInt(args[++i]);
                    break;
                case "--secret":
                    if (i + 1 < args.length) secret = args[++i];
                    break;
                case "--username":
                    if (i + 1 < args.length) username = args[++i];
                    break;
                case "--password":
                    if (i + 1 < args.length) password = args[++i];
                    break;
                case "--otp":
                    if (i + 1 < args.length) {
                        otp = args[++i];
                        separateOtp = true;
                    }
                    break;
            }
        }
        
        System.out.println("RADIUS Test Driver");
        System.out.println("==================");
        System.out.println("Target: " + host + ":" + port);
        System.out.println("Username: " + username);
        System.out.println("Password: " + password);
        System.out.println("Shared Secret: " + secret);
        System.out.println();
        
        try {
            RadiusTestDriver driver = new RadiusTestDriver();
            RadiusResponse response;
            if (separateOtp) {
                response = driver.sendAccessRequestWithSeparateOtp(host, port, secret, username, password, otp);
                System.out.println("Mode: Separate Password and OTP");
                System.out.println("OTP: " + otp);
            } else {
                response = driver.sendAccessRequest(host, port, secret, username, password);
                System.out.println("Mode: Combined Password+OTP");
            }
            
            System.out.println("Response received:");
            System.out.println("  Code: " + response.getCodeName());
            if (response.getReplyMessage() != null) {
                System.out.println("  Reply-Message: " + response.getReplyMessage());
            }
            System.out.println("  Success: " + (response.getCode() == RadiusPacket.ACCESS_ACCEPT));
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static void printUsage() {
        System.out.println("RADIUS Test Driver - Simulates Access-Request packets");
        System.out.println();
        System.out.println("Usage: java RadiusTestDriver [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --host <host>       Target RADIUS server host (default: localhost)");
        System.out.println("  --port <port>       Target RADIUS server port (default: 1812)");
        System.out.println("  --secret <secret>   Shared secret (default: secret)");
        System.out.println("  --username <user>   Username for authentication (default: test)");
        System.out.println("  --password <pass>   Password+OTP for authentication (default: test123)");
        System.out.println("  --otp <otp>         Separate OTP (enables separate OTP mode)");
        System.out.println("  --help, -h          Show this help message");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java RadiusTestDriver");
        System.out.println("  java RadiusTestDriver --username alice --password mypass456789");
        System.out.println("  java RadiusTestDriver --username bob --password secretpass --otp 123456");
        System.out.println("  java RadiusTestDriver --host 192.168.1.100 --secret mysecret");
    }
    
    public RadiusResponse sendAccessRequest(String host, int port, String sharedSecret, 
                                          String username, String password) throws IOException, RadiusPacket.RadiusException {
        
        InetAddress serverAddress = InetAddress.getByName(host);
        
        // Generate request authenticator
        byte[] requestAuth = RadiusCodec.generateRequestAuthenticator();
        
        // Encrypt password
        byte[] encryptedPassword = RadiusCodec.encryptPassword(password, requestAuth, sharedSecret);
        
        // Create attributes
        RadiusPacket.RadiusAttribute[] attributes = {
            new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, username),
            new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, encryptedPassword)
        };
        
        // Create Access-Request packet
        int identifier = (int) (Math.random() * 256);
        RadiusPacket requestPacket = new RadiusPacket(
            RadiusPacket.ACCESS_REQUEST, 
            identifier, 
            requestAuth, 
            Arrays.asList(attributes)
        );
        
        // Send packet
        byte[] requestData = requestPacket.encode();
        
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(5000); // 5 second timeout
            
            DatagramPacket requestUdpPacket = new DatagramPacket(
                requestData, requestData.length, serverAddress, port);
            
            System.out.println("Sending Access-Request...");
            socket.send(requestUdpPacket);
            
            // Receive response
            byte[] responseBuffer = new byte[4096];
            DatagramPacket responseUdpPacket = new DatagramPacket(responseBuffer, responseBuffer.length);
            
            socket.receive(responseUdpPacket);
            
            // Parse response
            byte[] responseData = new byte[responseUdpPacket.getLength()];
            System.arraycopy(responseUdpPacket.getData(), responseUdpPacket.getOffset(), 
                           responseData, 0, responseUdpPacket.getLength());
            
            RadiusPacket responsePacket = RadiusPacket.decode(responseData);
            
            return new RadiusResponse(responsePacket);
        }
    }
    
    public RadiusResponse sendAccessRequestWithSeparateOtp(String host, int port, String sharedSecret, 
                                                         String username, String password, String otp) 
                                                         throws IOException, RadiusPacket.RadiusException {
        
        InetAddress serverAddress = InetAddress.getByName(host);
        
        // Generate request authenticator
        byte[] requestAuth = RadiusCodec.generateRequestAuthenticator();
        
        // Encrypt password
        byte[] encryptedPassword = RadiusCodec.encryptPassword(password, requestAuth, sharedSecret);
        
        // Create vendor-specific attribute for OTP (simplified format)
        // Format: Vendor-Id (4 bytes) + Vendor-Type (1 byte) + Vendor-Length (1 byte) + OTP data
        byte[] otpBytes = otp.getBytes();
        byte[] vendorSpecific = new byte[6 + otpBytes.length];
        
        // Vendor ID (using a test vendor ID)
        vendorSpecific[0] = 0x00; vendorSpecific[1] = 0x00; vendorSpecific[2] = 0x00; vendorSpecific[3] = 0x01;
        // Vendor Type (OTP)
        vendorSpecific[4] = 0x01;
        // Vendor Length
        vendorSpecific[5] = (byte) (2 + otpBytes.length);
        // OTP data
        System.arraycopy(otpBytes, 0, vendorSpecific, 6, otpBytes.length);
        
        // Create attributes with separate OTP
        RadiusPacket.RadiusAttribute[] attributes = {
            new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, username),
            new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, encryptedPassword),
            new RadiusPacket.RadiusAttribute(RadiusPacket.VENDOR_SPECIFIC, vendorSpecific)
        };
        
        // Create Access-Request packet
        int identifier = (int) (Math.random() * 256);
        RadiusPacket requestPacket = new RadiusPacket(
            RadiusPacket.ACCESS_REQUEST,
            identifier,
            requestAuth,
            Arrays.asList(attributes)
        );
        
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(5000); // 5 second timeout
            
            // Send request
            byte[] requestData = requestPacket.encode();
            DatagramPacket requestUdpPacket = new DatagramPacket(
                requestData, requestData.length, serverAddress, port);
            
            socket.send(requestUdpPacket);
            
            // Receive response
            byte[] responseBuffer = new byte[4096];
            DatagramPacket responseUdpPacket = new DatagramPacket(responseBuffer, responseBuffer.length);
            
            socket.receive(responseUdpPacket);
            
            // Parse response
            byte[] responseData = new byte[responseUdpPacket.getLength()];
            System.arraycopy(responseUdpPacket.getData(), responseUdpPacket.getOffset(), 
                           responseData, 0, responseUdpPacket.getLength());
            
            RadiusPacket responsePacket = RadiusPacket.decode(responseData);
            
            return new RadiusResponse(responsePacket);
        }
    }
    
    public static class RadiusResponse {
        private final RadiusPacket packet;
        
        public RadiusResponse(RadiusPacket packet) {
            this.packet = packet;
        }
        
        public int getCode() {
            return packet.getCode();
        }
        
        public String getCodeName() {
            switch (packet.getCode()) {
                case RadiusPacket.ACCESS_ACCEPT:
                    return "Access-Accept";
                case RadiusPacket.ACCESS_REJECT:
                    return "Access-Reject";
                case RadiusPacket.ACCESS_CHALLENGE:
                    return "Access-Challenge";
                default:
                    return "Unknown(" + packet.getCode() + ")";
            }
        }
        
        public String getReplyMessage() {
            return packet.getStringAttribute(RadiusPacket.REPLY_MESSAGE);
        }
        
        public RadiusPacket getPacket() {
            return packet;
        }
    }
}