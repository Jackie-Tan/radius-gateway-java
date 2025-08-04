package com.radiusgateway;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RadiusPacket {
    
    public static final int ACCESS_REQUEST = 1;
    public static final int ACCESS_ACCEPT = 2;
    public static final int ACCESS_REJECT = 3;
    public static final int ACCOUNTING_REQUEST = 4;
    public static final int ACCOUNTING_RESPONSE = 5;
    public static final int ACCESS_CHALLENGE = 11;
    
    public static final int USER_NAME = 1;
    public static final int USER_PASSWORD = 2;
    public static final int CHAP_PASSWORD = 3;
    public static final int NAS_IP_ADDRESS = 4;
    public static final int NAS_PORT = 5;
    public static final int REPLY_MESSAGE = 18;
    public static final int STATE = 24;
    public static final int VENDOR_SPECIFIC = 26;
    public static final int MESSAGE_AUTHENTICATOR = 80;
    
    private final int code;
    private final int identifier;
    private final byte[] authenticator;
    private final List<RadiusAttribute> attributes;
    
    public RadiusPacket(int code, int identifier, byte[] authenticator, List<RadiusAttribute> attributes) {
        this.code = code;
        this.identifier = identifier;
        this.authenticator = authenticator.clone();
        this.attributes = new ArrayList<>(attributes);
    }
    
    public static RadiusPacket decode(byte[] data) throws RadiusException {
        if (data.length < 20) {
            throw new RadiusException("RADIUS packet too short: " + data.length);
        }
        
        ByteBuffer buffer = ByteBuffer.wrap(data);
        
        int code = buffer.get() & 0xFF;
        int identifier = buffer.get() & 0xFF;
        int length = buffer.getShort() & 0xFFFF;
        
        if (length != data.length) {
            throw new RadiusException("Length field mismatch: " + length + " vs " + data.length);
        }
        
        byte[] authenticator = new byte[16];
        buffer.get(authenticator);
        
        List<RadiusAttribute> attributes = new ArrayList<>();
        
        while (buffer.hasRemaining()) {
            if (buffer.remaining() < 2) {
                throw new RadiusException("Malformed attribute: insufficient data");
            }
            
            int type = buffer.get() & 0xFF;
            int attrLength = buffer.get() & 0xFF;
            
            if (attrLength < 2) {
                throw new RadiusException("Invalid attribute length: " + attrLength);
            }
            
            if (buffer.remaining() < attrLength - 2) {
                throw new RadiusException("Attribute data truncated");
            }
            
            byte[] value = new byte[attrLength - 2];
            buffer.get(value);
            
            attributes.add(new RadiusAttribute(type, value));
        }
        
        return new RadiusPacket(code, identifier, authenticator, attributes);
    }
    
    public byte[] encode() {
        int totalLength = 20; // Header
        for (RadiusAttribute attr : attributes) {
            totalLength += attr.getLength();
        }
        
        ByteBuffer buffer = ByteBuffer.allocate(totalLength);
        
        buffer.put((byte) code);
        buffer.put((byte) identifier);
        buffer.putShort((short) totalLength);
        buffer.put(authenticator);
        
        for (RadiusAttribute attr : attributes) {
            buffer.put((byte) attr.getType());
            buffer.put((byte) attr.getLength());
            buffer.put(attr.getValue());
        }
        
        return buffer.array();
    }
    
    public int getCode() {
        return code;
    }
    
    public int getIdentifier() {
        return identifier;
    }
    
    public byte[] getAuthenticator() {
        return authenticator.clone();
    }
    
    public List<RadiusAttribute> getAttributes() {
        return new ArrayList<>(attributes);
    }
    
    public RadiusAttribute getAttribute(int type) {
        for (RadiusAttribute attr : attributes) {
            if (attr.getType() == type) {
                return attr;
            }
        }
        return null;
    }
    
    public List<RadiusAttribute> getAttributes(int type) {
        List<RadiusAttribute> result = new ArrayList<>();
        for (RadiusAttribute attr : attributes) {
            if (attr.getType() == type) {
                result.add(attr);
            }
        }
        return result;
    }
    
    public String getStringAttribute(int type) {
        RadiusAttribute attr = getAttribute(type);
        return attr != null ? attr.getStringValue() : null;
    }
    
    public byte[] getBinaryAttribute(int type) {
        RadiusAttribute attr = getAttribute(type);
        return attr != null ? attr.getValue() : null;
    }
    
    public static class RadiusAttribute {
        private final int type;
        private final byte[] value;
        
        public RadiusAttribute(int type, byte[] value) {
            this.type = type;
            this.value = value.clone();
        }
        
        public RadiusAttribute(int type, String value) {
            this.type = type;
            this.value = value.getBytes();
        }
        
        public int getType() {
            return type;
        }
        
        public byte[] getValue() {
            return value.clone();
        }
        
        public String getStringValue() {
            return new String(value);
        }
        
        public int getLength() {
            return value.length + 2; // Type + Length + Value
        }
    }
    
    public static class RadiusException extends Exception {
        public RadiusException(String message) {
            super(message);
        }
        
        public RadiusException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}