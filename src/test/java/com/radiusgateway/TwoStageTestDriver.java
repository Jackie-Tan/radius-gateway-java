package com.radiusgateway;

import java.io.IOException;
import java.net.*;
import java.util.Arrays;
import java.util.Scanner;

/**
 * Enhanced test driver for testing two-stage RADIUS authentication.
 * Simulates the exact flow shown in VPN clients:
 * 1. Send username + password
 * 2. Receive Access-Challenge
 * 3. Send username + OTP + State
 * 4. Receive Access-Accept/Reject
 */
public class TwoStageTestDriver {
    
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
        String username = "alice";
        String password = "password123";
        boolean interactive = false;
        
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
                case "--interactive":
                    interactive = true;
                    break;
            }
        }
        
        System.out.println("RADIUS Two-Stage Authentication Test Driver");
        System.out.println("===========================================");
        System.out.println("Host: " + host);
        System.out.println("Port: " + port);
        System.out.println("Username: " + username);
        System.out.println("Password: " + password);
        System.out.println("Shared Secret: " + secret);
        System.out.println();
        
        try {
            TwoStageTestDriver driver = new TwoStageTestDriver();
            
            // Stage 1: Send username and password
            System.out.println("Stage 1: Sending username and password...");
            TwoStageResponse stage1Response = driver.sendPasswordAuthentication(
                host, port, secret, username, password);
            
            System.out.println("Stage 1 Response:");
            System.out.println("  Code: " + stage1Response.getCodeName());
            if (stage1Response.getReplyMessage() != null) {
                System.out.println("  Message: " + stage1Response.getReplyMessage());
            }
            
            if (stage1Response.getCode() != RadiusPacket.ACCESS_CHALLENGE) {
                System.out.println("  Result: " + 
                    (stage1Response.getCode() == RadiusPacket.ACCESS_ACCEPT ? "SUCCESS" : "FAILED"));
                System.out.println("Authentication completed in single stage.");
                return;
            }
            
            // Stage 2: Handle challenge - prompt for OTP
            System.out.println();
            String otp;
            if (interactive) {
                Scanner scanner = new Scanner(System.in);
                System.out.print("Stage 2: " + stage1Response.getReplyMessage() + ": ");
                otp = scanner.nextLine().trim();
            } else {
                otp = "123456"; // Default OTP for demo
                System.out.println("Stage 2: Using default OTP: " + otp);
            }
            
            byte[] challengeState = stage1Response.getState();
            if (challengeState == null) {
                System.err.println("Error: No State attribute in challenge response");
                return;
            }
            
            // Stage 2: Send OTP with challenge state
            System.out.println("Stage 2: Sending OTP with challenge state...");
            TwoStageResponse stage2Response = driver.sendOtpAuthentication(
                host, port, secret, username, otp, challengeState);
            
            System.out.println("Stage 2 Response:");
            System.out.println("  Code: " + stage2Response.getCodeName());
            if (stage2Response.getReplyMessage() != null) {
                System.out.println("  Message: " + stage2Response.getReplyMessage());
            }
            System.out.println("  Result: " + 
                (stage2Response.getCode() == RadiusPacket.ACCESS_ACCEPT ? "SUCCESS" : "FAILED"));
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static void printUsage() {
        System.out.println("RADIUS Two-Stage Test Driver");
        System.out.println();
        System.out.println("Usage: java TwoStageTestDriver [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --host <host>       Target RADIUS server host (default: localhost)");
        System.out.println("  --port <port>       Target RADIUS server port (default: 1812)");
        System.out.println("  --secret <secret>   Shared secret (default: secret)");
        System.out.println("  --username <user>   Username for authentication (default: alice)");
        System.out.println("  --password <pass>   Password for authentication (default: password123)");
        System.out.println("  --interactive       Prompt for OTP input (default: uses 123456)");
        System.out.println("  --help, -h          Show this help message");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java TwoStageTestDriver");
        System.out.println("  java TwoStageTestDriver --username bob --password secretpass");
        System.out.println("  java TwoStageTestDriver --interactive");
        System.out.println("  java TwoStageTestDriver --host 192.168.1.100 --secret mysecret");
    }
    
    /**
     * Stage 1: Send username and password authentication
     */
    public TwoStageResponse sendPasswordAuthentication(String host, int port, String sharedSecret, 
                                                     String username, String password) 
                                                     throws IOException, RadiusPacket.RadiusException {
        
        InetAddress serverAddress = InetAddress.getByName(host);
        
        // Generate request authenticator
        byte[] requestAuth = RadiusCodec.generateRequestAuthenticator();
        
        // Encrypt password
        byte[] encryptedPassword = RadiusCodec.encryptPassword(password, requestAuth, sharedSecret);
        
        // Create attributes for Stage 1 (no State attribute)
        RadiusPacket.RadiusAttribute[] attributes = {
            new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, username),
            new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, encryptedPassword)
        };
        
        return sendRequest(serverAddress, port, sharedSecret, requestAuth, attributes);
    }
    
    /**
     * Stage 2: Send OTP with challenge state
     */
    public TwoStageResponse sendOtpAuthentication(String host, int port, String sharedSecret, 
                                                String username, String otp, byte[] challengeState) 
                                                throws IOException, RadiusPacket.RadiusException {
        
        InetAddress serverAddress = InetAddress.getByName(host);
        
        // Generate request authenticator
        byte[] requestAuth = RadiusCodec.generateRequestAuthenticator();
        
        // Encrypt OTP (sent as password in Stage 2)
        byte[] encryptedOtp = RadiusCodec.encryptPassword(otp, requestAuth, sharedSecret);
        
        // Create attributes for Stage 2 (includes State attribute)
        RadiusPacket.RadiusAttribute[] attributes = {
            new RadiusPacket.RadiusAttribute(RadiusPacket.USER_NAME, username),
            new RadiusPacket.RadiusAttribute(RadiusPacket.USER_PASSWORD, encryptedOtp),
            new RadiusPacket.RadiusAttribute(RadiusPacket.STATE, challengeState)
        };
        
        return sendRequest(serverAddress, port, sharedSecret, requestAuth, attributes);
    }
    
    private TwoStageResponse sendRequest(InetAddress serverAddress, int port, String sharedSecret,
                                       byte[] requestAuth, RadiusPacket.RadiusAttribute[] attributes) 
                                       throws IOException, RadiusPacket.RadiusException {
        
        // Create Access-Request packet
        int identifier = (int) (Math.random() * 256);
        RadiusPacket requestPacket = new RadiusPacket(
            RadiusPacket.ACCESS_REQUEST,
            identifier,
            requestAuth,
            Arrays.asList(attributes)
        );
        
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(10000); // 10 second timeout
            
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
            
            return new TwoStageResponse(responsePacket);
        }
    }
    
    public static class TwoStageResponse {
        private final RadiusPacket packet;
        
        public TwoStageResponse(RadiusPacket packet) {
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
                    return "Unknown (" + packet.getCode() + ")";
            }
        }
        
        public String getReplyMessage() {
            RadiusPacket.RadiusAttribute attr = packet.getAttribute(RadiusPacket.REPLY_MESSAGE);
            return attr != null ? new String(attr.getValue()) : null;
        }
        
        public byte[] getState() {
            RadiusPacket.RadiusAttribute attr = packet.getAttribute(RadiusPacket.STATE);
            return attr != null ? attr.getValue() : null;
        }
    }
}