package com.simplejwtauth.config;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 인증 정책을 지정하는 어노테이션.
 *
 * <p>메서드/클래스에 모두 적용 가능하며, 메서드 레벨이 클래스 레벨보다 우선한다.</p>
 *
 * <ul>
 *   <li>{@code @Auth} (기본) — 인증 필요.</li>
 *   <li>{@code @Auth(isAuth = false)} — 인증 불필요. 클래스 레벨 {@code @Auth}의 예외로 메서드에 붙이거나,
 *       default-policy가 {@code deny}인 환경에서 공개 API를 명시적으로 허용할 때 사용.</li>
 * </ul>
 *
 * <p>어떤 어노테이션도 없으면 {@code simple-jwt-auth.security.default-policy} 설정을 따른다 (기본 {@code allow}).</p>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface Auth {

    /** {@code false}면 해당 엔드포인트는 인증을 요구하지 않는다. */
    boolean isAuth() default true;
}
