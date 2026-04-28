package com.simplejwtauth.common.security;

import com.simplejwtauth.auth.application.config.WebSettings;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * OAuth 로그인 실패 시 설정된 post-login error URL 로 error 코드와 함께 redirect.
 */
@RequiredArgsConstructor
public class OAuth2LoginFailureHandler implements AuthenticationFailureHandler {

    private final WebSettings webSettings;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        String errorCode = exception instanceof OAuth2AuthenticationException oae
                ? oae.getError().getErrorCode()
                : "oauth_failed";
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.sendRedirect(webSettings.postLoginErrorRedirect()
                + URLEncoder.encode(errorCode, StandardCharsets.UTF_8));
    }
}
