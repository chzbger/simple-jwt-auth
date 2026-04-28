package com.simplejwtauth.common.security;

import com.simplejwtauth.auth.adapter.in.web.CookieHelper;
import com.simplejwtauth.auth.application.config.WebSettings;
import com.simplejwtauth.auth.application.port.in.LogoutUseCase;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.util.WebUtils;

/**
 * Spring Security LogoutFilter 에 연결되는 logout 단계 — refresh token 무효화 + cookie 제거
 * cookie 에서 refresh 읽는 이유: access token 유효성과 무관하게 동작 + 멱등성
 */
@RequiredArgsConstructor
public class RefreshTokenLogoutHandler implements LogoutHandler {

    private final LogoutUseCase logoutUseCase;
    private final CookieHelper cookieHelper;
    private final WebSettings webSettings;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Cookie cookie = WebUtils.getCookie(request, webSettings.cookieName());
        if (cookie != null && cookie.getValue() != null && !cookie.getValue().isBlank()) {
            logoutUseCase.logout(cookie.getValue());
        }
        cookieHelper.clearRefreshCookie(response);
    }
}
