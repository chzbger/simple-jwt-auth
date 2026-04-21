package com.simplejwtauth.auth.adapter.in.web;

import com.simplejwtauth.auth.adapter.in.web.dto.TokenResponse;
import com.simplejwtauth.auth.application.port.in.CheckSessionUseCase;
import com.simplejwtauth.auth.application.port.in.RefreshUseCase;
import com.simplejwtauth.auth.domain.AuthToken;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("${simple-jwt-auth.web.base-path:/api/auth}")
public class SessionController {

    private final RefreshUseCase refreshUseCase;
    private final CheckSessionUseCase checkSessionUseCase;
    private final CookieHelper cookieHelper;

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            @CookieValue(name = "${simple-jwt-auth.web.cookie-name:sja_rt}", required = false) String refreshToken,
            HttpServletResponse response) {
        if (refreshToken == null || refreshToken.isBlank()) {
            return unauthorized(response);
        }
        try {
            AuthToken token = refreshUseCase.refresh(refreshToken);
            cookieHelper.setRefreshCookie(response, token.refreshToken());
            return ResponseEntity.ok()
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .body(new TokenResponse(token.accessToken()));
        } catch (IllegalArgumentException | IllegalStateException ex) {
            return unauthorized(response);
        }
    }

    @GetMapping("/me")
    public ResponseEntity<Map<String, String>> me(
            @CookieValue(name = "${simple-jwt-auth.web.cookie-name:sja_rt}", required = false) String refreshToken) {
        String userId = checkSessionUseCase.currentUserId(refreshToken);
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .build();
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(Map.of("userId", userId));
    }

    private ResponseEntity<TokenResponse> unauthorized(HttpServletResponse response) {
        cookieHelper.clearRefreshCookie(response);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .build();
    }
}
