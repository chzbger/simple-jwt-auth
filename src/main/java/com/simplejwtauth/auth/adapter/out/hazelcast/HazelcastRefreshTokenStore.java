package com.simplejwtauth.auth.adapter.out.hazelcast;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.map.IMap;
import com.simplejwtauth.auth.application.port.out.RefreshTokenStore;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;

public class HazelcastRefreshTokenStore implements RefreshTokenStore {

    static final String TOKEN_USER_MAP_NAME = "simple-jwt-auth:rt-token-user";
    static final String USER_TOKEN_MAP_NAME = "simple-jwt-auth:rt-user-token";

    /** hash(token) -> userId */
    private final IMap<String, String> tokenToUser;
    /** userId -> {hash, sessionStartedAtEpochSec} (1:1) */
    private final IMap<String, RefreshEntry> userToToken;
    private final Duration sessionMaxLifetime;

    public HazelcastRefreshTokenStore(HazelcastInstance hazelcastInstance, Duration sessionMaxLifetime) {
        this.tokenToUser = hazelcastInstance.getMap(TOKEN_USER_MAP_NAME);
        this.userToToken = hazelcastInstance.getMap(USER_TOKEN_MAP_NAME);
        this.sessionMaxLifetime = sessionMaxLifetime;
    }

    @Override
    public void issueToken(String plainToken, String userId) {
        String newHash = sha256(plainToken);
        long sessionStartedAtEpochSec = Instant.now().getEpochSecond();
        RefreshEntry oldEntry = userToToken.put(userId, new RefreshEntry(newHash, sessionStartedAtEpochSec));
        if (oldEntry != null) {
            tokenToUser.delete(oldEntry.hash());
        }
        tokenToUser.set(newHash, userId);
    }

    @Override
    public String rotate(String plainOldToken, String plainNewToken) {
        String oldHash = sha256(plainOldToken);
        String userId = tokenToUser.remove(oldHash);
        if (userId == null) return null; // 이미 회전됐거나 만료됨 — 호출자가 401

        RefreshEntry oldEntry = userToToken.remove(userId);
        if (oldEntry == null) return null;

        // 로그인 최대시간 지나면 로그아웃
        long diffSec = Instant.now().getEpochSecond() - oldEntry.sessionStartedAtEpochSec();
        if (diffSec > sessionMaxLifetime.toSeconds()) {
            return null;
        }

        String newHash = sha256(plainNewToken);
        tokenToUser.set(newHash, userId);
        userToToken.set(userId, new RefreshEntry(newHash, oldEntry.sessionStartedAtEpochSec()));
        return userId;
    }

    @Override
    public void invalidate(String plainToken) {
        if (plainToken == null || plainToken.isBlank()) return;
        String hash = sha256(plainToken);
        String userId = tokenToUser.remove(hash);
        if (userId != null) {
            RefreshEntry current = userToToken.get(userId);
            if (current != null && current.hash().equals(hash)) { // 사이에 새로 로그인 했을경우는 pass
                userToToken.remove(userId, current);
            }
        }
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 알고리즘 사용 불가", e);
        }
    }

    public record RefreshEntry(String hash, long sessionStartedAtEpochSec) implements Serializable {}
}
