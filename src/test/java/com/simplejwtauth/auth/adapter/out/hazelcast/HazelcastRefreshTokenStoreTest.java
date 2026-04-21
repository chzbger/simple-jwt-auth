package com.simplejwtauth.auth.adapter.out.hazelcast;

import com.hazelcast.config.Config;
import com.hazelcast.config.MapConfig;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.map.IMap;
import com.simplejwtauth.auth.application.port.out.RefreshTokenStore.RotateResult;
import com.simplejwtauth.auth.application.port.out.RefreshTokenStore.RotateResult.Invalid;
import com.simplejwtauth.auth.application.port.out.RefreshTokenStore.RotateResult.SessionExpired;
import com.simplejwtauth.auth.application.port.out.RefreshTokenStore.RotateResult.Success;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class HazelcastRefreshTokenStoreTest {

    private HazelcastInstance hz;
    private HazelcastRefreshTokenStore store;

    @BeforeEach
    void setup() {
        Config config = new Config();
        config.setInstanceName("sja-test-" + UUID.randomUUID());
        config.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
        config.getNetworkConfig().getJoin().getTcpIpConfig().setEnabled(false);
        config.addMapConfig(new MapConfig(HazelcastRefreshTokenStore.TOKEN_USER_MAP_NAME).setTimeToLiveSeconds(60));
        config.addMapConfig(new MapConfig(HazelcastRefreshTokenStore.USER_TOKEN_MAP_NAME).setTimeToLiveSeconds(60));

        hz = Hazelcast.newHazelcastInstance(config);
        store = new HazelcastRefreshTokenStore(hz, Duration.ofDays(2));
    }

    @AfterEach
    void teardown() {
        hz.shutdown();
    }

    @Test
    @DisplayName("issueToken: findUserId로 userId 확인")
    void issueToken() {
        store.issueToken("token-A", "user-1");

        assertThat(store.findUserId("token-A")).isEqualTo("user-1");
    }

    @Test
    @DisplayName("같은 userId 로 재발급 시 직전 토큰은 무효화")
    void issueToken_2() {
        store.issueToken("token-A", "user-1");
        store.issueToken("token-B", "user-1");

        assertThat(store.findUserId("token-A")).isNull();
        assertThat(store.findUserId("token-B")).isEqualTo("user-1");
    }

    @Test
    @DisplayName("userToToken 1:1 확인")
    void issueToken_3() {
        IMap<String, HazelcastRefreshTokenStore.RefreshEntry> userToToken =
                hz.getMap(HazelcastRefreshTokenStore.USER_TOKEN_MAP_NAME);

        store.issueToken("token-A", "user-1");
        store.issueToken("token-B", "user-1");
        store.issueToken("token-C", "user-1");

        assertThat(userToToken.size()).isEqualTo(1);
    }

    @Test
    @DisplayName("rotate")
    void rotate() {
        store.issueToken("token-old", "user-1");

        RotateResult result = store.rotate("token-old", "token-new");

        assertThat(result).isInstanceOf(Success.class);
        assertThat(((Success) result).userId()).isEqualTo("user-1");
        assertThat(store.findUserId("token-old")).isNull();
        assertThat(store.findUserId("token-new")).isEqualTo("user-1");
    }

    @Test
    @DisplayName("rotate 없는건 Invalid")
    void rotate_2() {
        RotateResult result = store.rotate("does-not-exist", "token-new");

        assertThat(result).isInstanceOf(Invalid.class);
    }

    @Test
    @DisplayName("rotate 이미 지난건 Invalid")
    void rotate_3() {
        store.issueToken("token-old", "user-1");
        store.rotate("token-old", "token-new");

        RotateResult secondTry = store.rotate("token-old", "token-newer");

        assertThat(secondTry).isInstanceOf(Invalid.class);
    }

    @Test
    @DisplayName("rotate sessionStartedAt(최초 로그인 시간 확인)")
    void rotate_4() {
        IMap<String, HazelcastRefreshTokenStore.RefreshEntry> userToToken =
                hz.getMap(HazelcastRefreshTokenStore.USER_TOKEN_MAP_NAME);

        store.issueToken("token-1", "user-1");
        long originalStart = userToToken.get("user-1").sessionStartedAtEpochSec();

        store.rotate("token-1", "token-2");
        store.rotate("token-2", "token-3");
        store.rotate("token-3", "token-4");

        long afterRotations = userToToken.get("user-1").sessionStartedAtEpochSec();
        assertThat(afterRotations).isEqualTo(originalStart);
    }

    @Test
    @DisplayName("rotate 최대 시간 지나면 만료 확인")
    void rotate_5() throws InterruptedException {
        // 1초 lifetime, 약간 넉넉히 sleep 해서 만료 보장
        store = new HazelcastRefreshTokenStore(hz, Duration.ofSeconds(1));

        store.issueToken("token-old", "user-1");
        Thread.sleep(2_000);

        RotateResult result = store.rotate("token-old", "token-new");

        assertThat(result).isInstanceOf(SessionExpired.class);
    }

    @Test
    @DisplayName("invalidate(로그아웃)")
    void invalidate() {
        store.issueToken("token-A", "user-1");

        store.invalidate("token-A");

        assertThat(store.findUserId("token-A")).isNull();
    }

    @Test
    @DisplayName("findUserId")
    void findUserId() {
        assertThat(store.findUserId("does-not-exist")).isNull();
        assertThat(store.findUserId(null)).isNull();
        assertThat(store.findUserId("")).isNull();
        assertThat(store.findUserId("   ")).isNull();
    }
}
