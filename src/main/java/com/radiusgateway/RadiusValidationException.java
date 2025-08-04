package com.radiusgateway;

/**
 * Exception thrown when RADIUS packet or request validation fails.
 * This includes format validation, bounds checking, and input validation errors.
 */
public class RadiusValidationException extends Exception {
    
    private final String fieldName;
    private final String invalidValue;
    
    /**
     * Creates a validation exception with a message.
     * 
     * @param message the error message
     */
    public RadiusValidationException(String message) {
        super(message);
        this.fieldName = null;
        this.invalidValue = null;
    }
    
    /**
     * Creates a validation exception with a message and cause.
     * 
     * @param message the error message
     * @param cause the underlying cause
     */
    public RadiusValidationException(String message, Throwable cause) {
        super(message, cause);
        this.fieldName = null;
        this.invalidValue = null;
    }
    
    /**
     * Creates a validation exception for a specific field.
     * 
     * @param fieldName the name of the field that failed validation
     * @param invalidValue the invalid value (will be masked if sensitive)
     * @param message the error message
     */
    public RadiusValidationException(String fieldName, String invalidValue, String message) {
        super(RadiusUtils.formatValidationError(fieldName, invalidValue, message));
        this.fieldName = fieldName;
        this.invalidValue = isSensitiveField(fieldName) ? "[masked]" : invalidValue;
    }
    
    /**
     * Creates a validation exception for a specific field with cause.
     * 
     * @param fieldName the name of the field that failed validation
     * @param invalidValue the invalid value (will be masked if sensitive)
     * @param message the error message
     * @param cause the underlying cause
     */
    public RadiusValidationException(String fieldName, String invalidValue, String message, Throwable cause) {
        super(RadiusUtils.formatValidationError(fieldName, invalidValue, message), cause);
        this.fieldName = fieldName;
        this.invalidValue = isSensitiveField(fieldName) ? "[masked]" : invalidValue;
    }
    
    /**
     * Gets the name of the field that failed validation.
     * 
     * @return field name, or null if not field-specific
     */
    public String getFieldName() {
        return fieldName;
    }
    
    /**
     * Gets the invalid value (masked if sensitive).
     * 
     * @return invalid value, or null if not field-specific
     */
    public String getInvalidValue() {
        return invalidValue;
    }
    
    /**
     * Checks if this validation error is related to a specific field.
     * 
     * @return true if field-specific, false otherwise
     */
    public boolean isFieldSpecific() {
        return fieldName != null;
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
               lower.contains("token") ||
               lower.contains("authenticator");
    }
    
    /**
     * Creates a validation exception for packet length bounds checking.
     * 
     * @param actualLength the actual packet length
     * @param expectedMin minimum expected length
     * @param expectedMax maximum expected length
     * @return validation exception
     */
    public static RadiusValidationException packetLengthError(int actualLength, int expectedMin, int expectedMax) {
        return new RadiusValidationException("packet-length", String.valueOf(actualLength),
            String.format("Length must be between %d and %d bytes", expectedMin, expectedMax));
    }
    
    /**
     * Creates a validation exception for attribute value bounds checking.
     * 
     * @param attributeType the RADIUS attribute type
     * @param actualLength the actual attribute length
     * @param maxLength maximum allowed length
     * @return validation exception
     */
    public static RadiusValidationException attributeLengthError(int attributeType, int actualLength, int maxLength) {
        return new RadiusValidationException("attribute-" + attributeType + "-length", String.valueOf(actualLength),
            String.format("Attribute %d length must not exceed %d bytes", attributeType, maxLength));
    }
    
    /**
     * Creates a validation exception for missing required fields.
     * 
     * @param fieldName the name of the missing field
     * @return validation exception
     */
    public static RadiusValidationException missingRequiredField(String fieldName) {
        return new RadiusValidationException(fieldName, null, "Required field is missing");
    }
    
    /**
     * Creates a validation exception for invalid format.
     * 
     * @param fieldName the name of the field with invalid format
     * @param value the invalid value
     * @param expectedFormat description of expected format
     * @return validation exception
     */
    public static RadiusValidationException invalidFormat(String fieldName, String value, String expectedFormat) {
        return new RadiusValidationException(fieldName, value, 
            "Invalid format, expected: " + expectedFormat);
    }
    
    /**
     * Creates a validation exception for missing required attributes.
     * 
     * @param attributeName the name of the missing attribute
     * @param packetType the type of packet requiring the attribute
     * @return validation exception
     */
    public static RadiusValidationException missingRequiredAttribute(String attributeName, String packetType) {
        return new RadiusValidationException(attributeName, null,
            String.format("Required attribute missing from %s packet", packetType));
    }
    
    /**
     * Creates a validation exception for conflicting attributes.
     * 
     * @param attribute1 the name of the first conflicting attribute
     * @param attribute2 the name of the second conflicting attribute
     * @param reason description of why they conflict
     * @return validation exception
     */
    public static RadiusValidationException conflictingAttributes(String attribute1, String attribute2, String reason) {
        return new RadiusValidationException(attribute1 + "/" + attribute2, null,
            String.format("Conflicting attributes: %s", reason));
    }
}