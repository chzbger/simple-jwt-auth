package com.simplejwtauth.auth.adapter.in.web;

import com.simplejwtauth.auth.application.config.JwtSettings;
import com.simplejwtauth.auth.application.config.WebSettings;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class CookieHelperTest {

    private CookieHelper cookieHelper;
    private HttpServletResponse response;

    @BeforeEach
    void setup() {
        WebSettings web = new WebSettings("/api/auth", "sja_rt", true, "Strict", "/", "/?sja_error=");
        JwtSettings jwt = new JwtSettings(
                "0123456789abcdef0123456789abcdef",
                Duration.ofMinutes(15),
                Duration.ofHours(2),
                Duration.ofDays(2),
                Duration.ofSeconds(30)
        );
        cookieHelper = new CookieHelper(web, jwt);
        response = mock(HttpServletResponse.class);
    }

    @Test
    @DisplayName("setRefreshCookie")
    void setRefreshCookie() {
        cookieHelper.setRefreshCookie(response, "my-refresh-token");

        String header = captureSetCookieHeader();
        assertThat(header).contains("sja_rt=my-refresh-token");
        assertThat(header).contains("HttpOnly");
        assertThat(header).contains("Secure");
        assertThat(header).contains("SameSite=Strict");
        assertThat(header).contains("Path=/api/auth");
        assertThat(header).contains("Max-Age=7200");   // 2h = 7200s
    }

    @Test
    @DisplayName("clearRefreshCookie")
    void clearRefreshCookie_1() {
        cookieHelper.clearRefreshCookie(response);

        String header = captureSetCookieHeader();
        assertThat(header).startsWith("sja_rt=;");
        assertThat(header).contains("Max-Age=0");
        assertThat(header).contains("Path=/api/auth");
    }

    private String captureSetCookieHeader() {
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(response).addHeader(org.mockito.ArgumentMatchers.eq("Set-Cookie"), captor.capture());
        return captor.getValue();
    }
}
