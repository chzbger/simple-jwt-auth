package com.simplejwtauth.adapter.in.web;

import com.simplejwtauth.adapter.in.web.dto.TokenResponse;
import com.simplejwtauth.application.port.in.LogoutUseCase;
import com.simplejwtauth.application.port.in.RefreshUseCase;
import com.simplejwtauth.config.Auth;
import com.simplejwtauth.domain.model.AuthToken;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Auth(isAuth = false)
@RestController
@RequestMapping("${simple-jwt-auth.web.base-path:/api/auth}")
public class SessionController {

    private final RefreshUseCase refreshUseCase;
    private final LogoutUseCase logoutUseCase;
    private final CookieHelper cookieHelper;

    public SessionController(RefreshUseCase refreshUseCase,
                             LogoutUseCase logoutUseCase,
                             CookieHelper cookieHelper) {
        this.refreshUseCase = refreshUseCase;
        this.logoutUseCase = logoutUseCase;
        this.cookieHelper = cookieHelper;
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            @CookieValue("${simple-jwt-auth.web.cookie-name:sja_rt}") String refreshToken,
            HttpServletResponse response) {
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
