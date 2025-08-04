package com.radiusgateway;

import java.security.SecureRandom;
import java.util.regex.Pattern;

/**
 * Common utility methods for RADIUS protocol operations.
 * Consolidates duplicate functionality across the codebase.
 */
public final class RadiusUtils {
    
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9._@-]{1,253}$");
    private static final Pattern OTP_PATTERN = Pattern.compile("^\\d{4,8}$");
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    
    // Private constructor to prevent instantiation
    private RadiusUtils() {
        throw new AssertionError("Utility class should not be instantiated");
    }
    
    /**
     * Converts byte array to hexadecimal string representation.
     * 
     * @param bytes the byte array to convert
     * @return hexadecimal string representation
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    /**
     * Converts hexadecimal string to byte array.
     * 
     * @param hex the hexadecimal string to convert
     * @return byte array representation
     * @throws IllegalArgumentException if hex string is invalid
     */
    public static byte[] hexToBytes(String hex) {
        if (hex == null) {
            return null;
        }
        
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string length: " + hex.length());
        }
        
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
    
    /**
     * Generates a cryptographically secure random byte array.
     * 
     * @param length the length of the byte array to generate
     * @return secure random byte array
     */
    public static byte[] generateSecureRandomBytes(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("Length must be positive: " + length);
        }
        
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }
    
    /**
     * Validates RADIUS username format according to RFC standards.
     * 
     * @param username the username to validate
     * @return true if username is valid, false otherwise
     */
    public static boolean isValidUsername(String username) {
        return username != null && 
               !username.trim().isEmpty() && 
               USERNAME_PATTERN.matcher(username).matches();
    }
    
    /**
     * Validates OTP format (numeric, reasonable length).
     * 
     * @param otp the OTP to validate
     * @return true if OTP format is valid, false otherwise
     */
    public static boolean isValidOtpFormat(String otp) {
        return otp != null && 
               OTP_PATTERN.matcher(otp.trim()).matches();
    }
    
    /**
     * Validates OTP format with specific expected length and tolerance.
     * 
     * @param otp the OTP to validate
     * @param expectedLength the expected OTP length
     * @param tolerance acceptable deviation from expected length
     * @return true if OTP format is valid, false otherwise
     */
    public static boolean isValidOtpFormat(String otp, int expectedLength, int tolerance) {
        if (otp == null || expectedLength <= 0 || tolerance < 0) {
            return false;
        }
        
        String trimmed = otp.trim();
        if (!trimmed.matches("\\d+")) {
            return false;
        }
        
        int minLength = Math.max(1, expectedLength - tolerance);
        int maxLength = expectedLength + tolerance;
        
        return trimmed.length() >= minLength && trimmed.length() <= maxLength;
    }
    
    /**
     * Safely compares two strings for equality, handling null values.
     * 
     * @param a first string
     * @param b second string
     * @return true if strings are equal (including both null), false otherwise
     */
    public static boolean safeEquals(String a, String b) {
        if (a == null && b == null) {
            return true;
        }
        if (a == null || b == null) {
            return false;
        }
        return a.equals(b);
    }
    
    /**
     * Safely compares two byte arrays for equality, handling null values.
     * 
     * @param a first byte array
     * @param b second byte array
     * @return true if arrays are equal (including both null), false otherwise
     */
    public static boolean safeEquals(byte[] a, byte[] b) {
        if (a == null && b == null) {
            return true;
        }
        if (a == null || b == null) {
            return false;
        }
        if (a.length != b.length) {
            return false;
        }
        
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Creates a standardized error message for authentication failures.
     * 
     * @param username the username that failed authentication
     * @param reason the reason for failure
     * @return formatted error message
     */
    public static String formatAuthenticationError(String username, String reason) {
        return String.format("Authentication failed for user '%s': %s", 
                           username != null ? username : "[unknown]", 
                           reason != null ? reason : "Unknown error");
    }
    
    /**
     * Creates a standardized error message for validation failures.
     * 
     * @param field the field that failed validation
     * @param value the invalid value (will be masked if sensitive)
     * @param reason the reason for validation failure
     * @return formatted error message
     */
    public static String formatValidationError(String field, String value, String reason) {
        // Mask sensitive fields
        String displayValue = isSensitiveField(field) ? "[masked]" : value;
        return String.format("Validation failed for %s '%s': %s", 
                           field, displayValue, reason);
    }
    
    /**
     * Checks if a field name represents sensitive data that should be masked.
     * 
     * @param fieldName the field name to check
     * @return true if field is sensitive, false otherwise
     */
    private static boolean isSensitiveField(String fieldName) {
        if (fieldName == null) {
            return false;
        }
        
        String lower = fieldName.toLowerCase();
        return lower.contains("password") || 
               lower.contains("secret") || 
               lower.contains("otp") ||
               lower.contains("token");
    }
}