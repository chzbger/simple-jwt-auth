package com.simplejwtauth.auth.adapter.in.web;

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
 * 로그아웃 handler
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
