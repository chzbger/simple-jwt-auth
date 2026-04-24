package com.simplejwtauth.auth.adapter.in.web;

import com.simplejwtauth.auth.adapter.in.web.dto.TokenResponse;
import com.simplejwtauth.auth.application.port.in.LogoutUseCase;
import com.simplejwtauth.auth.application.port.in.RefreshUseCase;
import com.simplejwtauth.auth.adapter.in.web.annotation.Auth;
import com.simplejwtauth.auth.domain.AuthToken;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Auth(isAuth = false)
@RestController
@RequiredArgsConstructor
@RequestMapping("${simple-jwt-auth.web.base-path:/api/auth}")
public class SessionController {

    private final RefreshUseCase refreshUseCase;
    private final LogoutUseCase logoutUseCase;
    private final CookieHelper cookieHelper;

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            @CookieValue(name = "${simple-jwt-auth.web.cookie-name:sja_rt}", required = false) String refreshToken,
            HttpServletResponse response) {
        if (refreshToken == null || refreshToken.isBlank()) {
            return ResponseEntity.status(401).build();
        }
        AuthToken token = refreshUseCase.refresh(refreshToken);
        cookieHelper.setRefreshCookie(response, token.refreshToken());
        return ResponseEntity.ok(new TokenResponse(token.accessToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @CookieValue(name = "${simple-jwt-auth.web.cookie-name:sja_rt}", required = false) String refreshToken,
            HttpServletResponse response) {
        if (refreshToken != null) {
            logoutUseCase.logout(refreshToken);
        }
        cookieHelper.clearRefreshCookie(response);
        return ResponseEntity.ok().build();
    }
}
