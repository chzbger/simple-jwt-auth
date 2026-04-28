package com.simplejwtauth.auth.adapter.out.hazelcast;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.map.IMap;
import com.simplejwtauth.auth.application.port.out.OAuthCodeStore;

import java.security.SecureRandom;
import java.util.Base64;

public class HazelcastOAuthCodeStore implements OAuthCodeStore {

    static final String MAP_NAME = "simple-jwt-auth:oauth-code";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final IMap<String, String> codeToToken;

    public HazelcastOAuthCodeStore(HazelcastInstance hazelcastInstance) {
        this.codeToToken = hazelcastInstance.getMap(MAP_NAME);
    }

    @Override
    public String issue(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) return null;
        String code = newCode();
        codeToToken.set(code, accessToken);
        return code;
    }

    @Override
    public String consume(String code) {
        if (code == null || code.isBlank()) return null;
        return codeToToken.remove(code);
    }

    private static String newCode() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
