package com.simplejwtauth.auth.domain;

import com.simplejwtauth.common.AuthInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Optional;

/**
 * 인증된 사용자의 id 를 요청 컨텍스트에서 읽어오기 위한 헬퍼.
 *
 * <p>{@link AuthInterceptor} 가 {@code @Auth} 로 보호된 엔드포인트에서 검증에 성공하면
 * userId 를 현재 request attribute 에 바인딩한다. 소비자 컨트롤러는
 * {@link #getUserId()} 또는 {@link #getOptionalUserId()} 로 읽는다.</p>
 */
public final class AuthContext {

    static final String ATTR_KEY = "AUTH_USER_ID";

    private AuthContext() {}

    /** {@link AuthInterceptor} 내부용. 현재 요청에 인증된 userId 를 바인딩한다. */
    public static void set(HttpServletRequest request, String userId) {
        request.setAttribute(ATTR_KEY, userId);
    }

    /**
     * @throws IllegalStateException 요청 스레드가 아니거나, 현재 요청이 {@code @Auth} 로 보호돼 있지 않아
     *                               인증된 userId 가 바인딩돼 있지 않을 때.
     */
    public static String getUserId() {
        return getOptionalUserId().orElseThrow(() -> new IllegalStateException(
                "No authenticated user in request context. Ensure the endpoint is annotated with @Auth."));
    }

    public static Optional<String> getOptionalUserId() {
        var attrs = RequestContextHolder.getRequestAttributes();
        if (!(attrs instanceof ServletRequestAttributes sra)) return Optional.empty();
        Object value = sra.getRequest().getAttribute(ATTR_KEY);
        return value instanceof String userId ? Optional.of(userId) : Optional.empty();
    }
}
