package com.simplejwtauth.auth.adapter.in.web;

import com.simplejwtauth.auth.adapter.in.web.dto.LoginRequest;
import com.simplejwtauth.auth.adapter.in.web.dto.TokenResponse;
import com.simplejwtauth.auth.application.port.in.LoginUseCase;
import com.simplejwtauth.auth.adapter.in.web.annotation.Auth;
import com.simplejwtauth.auth.domain.AuthToken;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Auth(isAuth = false)
@RestController
@RequiredArgsConstructor
@RequestMapping("${simple-jwt-auth.web.base-path:/api/auth}")
public class LoginController {

    private final LoginUseCase loginUseCase;
    private final CookieHelper cookieHelper;

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest request,
                                               HttpServletResponse response) {
        AuthToken token = loginUseCase.login(request.username(), request.password());
        cookieHelper.setRefreshCookie(response, token.refreshToken());
        return ResponseEntity.ok(new TokenResponse(token.accessToken()));
    }
}
