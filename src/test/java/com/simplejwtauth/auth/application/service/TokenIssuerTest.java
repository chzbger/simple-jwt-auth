package com.simplejwtauth.auth.application.service;

import com.simplejwtauth.auth.application.config.JwtSettings;
import com.simplejwtauth.auth.application.port.out.RefreshTokenStore;
import com.simplejwtauth.auth.application.port.out.RefreshTokenStore.RotateResult;
import com.simplejwtauth.auth.domain.AuthToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TokenIssuerTest {

    private JwtEncoder jwtEncoder;
    private RefreshTokenStore refreshTokenStore;
    private TokenIssuer tokenIssuer;

    @BeforeEach
    void setup() {
        jwtEncoder = mock(JwtEncoder.class);
        refreshTokenStore = mock(RefreshTokenStore.class);
        JwtSettings settings = new JwtSettings(
                "0123456789abcdef0123456789abcdef",
                Duration.ofMinutes(15),
                Duration.ofHours(2),
                Duration.ofDays(2),
                Duration.ofSeconds(30)
        );
        tokenIssuer = new TokenIssuer(jwtEncoder, settings, refreshTokenStore);

        Jwt fakeJwt = new Jwt(
                "fake-access-token",
                Instant.now(),
                Instant.now().plusSeconds(900),
                Map.of("alg", "HS256"),
                Map.of("sub", "user-1")
        );
        when(jwtEncoder.encode(any(JwtEncoderParameters.class))).thenReturn(fakeJwt);
    }

    @Test
    @DisplayName("issueTokens")
    void issueTokens() {
        AuthToken token = tokenIssuer.issueTokens("user-1");

        assertThat(token.accessToken()).isEqualTo("fake-access-token");
        assertThat(token.refreshToken()).isNotBlank();
        verify(refreshTokenStore).issueToken(token.refreshToken(), "user-1");
    }

    @Test
    @DisplayName("issueTokens: 매번 새 refresh token 생성")
    void issueTokens_2() {
        AuthToken first = tokenIssuer.issueTokens("user-1");
        AuthToken second = tokenIssuer.issueTokens("user-1");

        assertThat(first.refreshToken()).isNotEqualTo(second.refreshToken());
    }

    @Test
    @DisplayName("rotateTokens")
    void rotateTokens() {
        when(refreshTokenStore.rotate(any(), any())).thenReturn(new RotateResult.Success("user-1"));

        AuthToken result = tokenIssuer.rotateTokens("old-token");

        assertThat(result.accessToken()).isEqualTo("fake-access-token");
        assertThat(result.refreshToken()).isNotBlank();
    }

    @Test
    @DisplayName("rotateTokens: IllegalArgumentException")
    void rotateTokens_2() {
        when(refreshTokenStore.rotate(any(), any())).thenReturn(new RotateResult.Invalid());

        assertThatThrownBy(() -> tokenIssuer.rotateTokens("old-token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("유효하지 않은");
    }

    @Test
    @DisplayName("rotateTokens: IllegalStateException")
    void rotateTokens_3() {
        when(refreshTokenStore.rotate(any(), any())).thenReturn(new RotateResult.SessionExpired());

        assertThatThrownBy(() -> tokenIssuer.rotateTokens("old-token"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("최대 시간 초과");
    }
}
