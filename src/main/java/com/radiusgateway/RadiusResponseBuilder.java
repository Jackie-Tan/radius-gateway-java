package com.radiusgateway;

import java.util.ArrayList;
import java.util.List;

public class RadiusResponseBuilder {
    
    private final int code;
    private final int identifier;
    private final List<RadiusPacket.RadiusAttribute> attributes;
    
    private RadiusResponseBuilder(int code, int identifier) {
        this.code = code;
        this.identifier = identifier;
        this.attributes = new ArrayList<>();
    }
    
    public static RadiusResponseBuilder createAccept(int identifier) {
        return new RadiusResponseBuilder(RadiusPacket.ACCESS_ACCEPT, identifier);
    }
    
    public static RadiusResponseBuilder createReject(int identifier) {
        return new RadiusResponseBuilder(RadiusPacket.ACCESS_REJECT, identifier);
    }
    
    public static RadiusResponseBuilder createChallenge(int identifier) {
        return new RadiusResponseBuilder(RadiusPacket.ACCESS_CHALLENGE, identifier);
    }
    
    public RadiusResponseBuilder addReplyMessage(String message) {
        if (message != null && !message.isEmpty()) {
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.REPLY_MESSAGE, message));
        }
        return this;
    }
    
    public RadiusResponseBuilder addState(byte[] state) {
        if (state != null && state.length > 0) {
            attributes.add(new RadiusPacket.RadiusAttribute(RadiusPacket.STATE, state));
        }
        return this;
    }
    
    public RadiusResponseBuilder addAttribute(int type, String value) {
        if (value != null) {
            attributes.add(new RadiusPacket.RadiusAttribute(type, value));
        }
        return this;
    }
    
    public RadiusResponseBuilder addAttribute(int type, byte[] value) {
        if (value != null) {
            attributes.add(new RadiusPacket.RadiusAttribute(type, value));
        }
        return this;
    }
    
    public RadiusResponseBuilder addAttribute(RadiusPacket.RadiusAttribute attribute) {
        if (attribute != null) {
            attributes.add(attribute);
        }
        return this;
    }
    
    public RadiusPacket build(byte[] requestAuthenticator, String sharedSecret) throws RadiusPacket.RadiusException {
        // Create initial packet with zero authenticator
        byte[] zeroAuthenticator = new byte[16];
        RadiusPacket tempPacket = new RadiusPacket(code, identifier, zeroAuthenticator, attributes);
        
        // Compute response authenticator
        byte[] responseAuthenticator = RadiusCodec.computeResponseAuthenticator(
            tempPacket, requestAuthenticator, sharedSecret);
        
        // Create final packet with computed authenticator
        return new RadiusPacket(code, identifier, responseAuthenticator, attributes);
    }
    
    public static RadiusPacket buildFromResponse(RadiusHandler.RadiusResponse response, 
                                               int identifier,
                                               byte[] requestAuthenticator, 
                                               String sharedSecret) throws RadiusPacket.RadiusException {
        RadiusResponseBuilder builder;
        
        switch (response.getCode()) {
            case RadiusPacket.ACCESS_ACCEPT:
                builder = createAccept(identifier);
                break;
            case RadiusPacket.ACCESS_REJECT:
                builder = createReject(identifier);
                break;
            case RadiusPacket.ACCESS_CHALLENGE:
                builder = createChallenge(identifier);
                break;
            default:
                throw new RadiusPacket.RadiusException("Unsupported response code: " + response.getCode());
        }
        
        if (response.getReplyMessage() != null) {
            builder.addReplyMessage(response.getReplyMessage());
        }
        
        if (response.getState() != null) {
            builder.addState(response.getState());
        }
        
        return builder.build(requestAuthenticator, sharedSecret);
    }
}