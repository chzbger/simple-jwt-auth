package com.simplejwtauth.adapter.in.web;

import com.simplejwtauth.application.config.SecuritySettings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 기동 시 모든 등록된 엔드포인트를 PROTECTED/PUBLIC로 분류해 로그에 남긴다.
 * 요약은 INFO, 상세 목록은 DEBUG.
 */
public class AuthPolicyAuditor {

    private static final Logger log = LoggerFactory.getLogger("simple-jwt-auth");

    private final RequestMappingHandlerMapping handlerMapping;
    private final AuthInterceptor authInterceptor;
    private final SecuritySettings security;

    public AuthPolicyAuditor(RequestMappingHandlerMapping handlerMapping,
                             AuthInterceptor authInterceptor,
                             SecuritySettings security) {
        this.handlerMapping = handlerMapping;
        this.authInterceptor = authInterceptor;
        this.security = security;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void audit() {
        int protectedCount = 0;
        int publicCount = 0;
        List<String> lines = new ArrayList<>();

        for (Map.Entry<RequestMappingInfo, HandlerMethod> entry : handlerMapping.getHandlerMethods().entrySet()) {
            RequestMappingInfo info = entry.getKey();
            HandlerMethod method = entry.getValue();

            List<String> paths = new ArrayList<>(info.getPatternValues());
            paths.sort(Comparator.naturalOrder());
            String methods = renderMethods(info.getMethodsCondition().getMethods());
            String firstPath = paths.isEmpty() ? "" : paths.get(0);

            boolean requiresAuth = authInterceptor.authRequired(method, firstPath);
            if (requiresAuth) protectedCount++;
            else publicCount++;

            if (log.isDebugEnabled()) {
                lines.add(String.format(
                        "  [%-9s] %-6s %-40s -> %s.%s",
                        requiresAuth ? "PROTECTED" : "PUBLIC",
                        methods,
                        String.join(",", paths),
                        method.getBeanType().getSimpleName(),
                        method.getMethod().getName()
                ));
            }
        }

        log.info("[simple-jwt-auth] policy={} publicPaths={} protected={} public={}",
                security.defaultPolicy(),
                security.publicPaths(),
                protectedCount,
                publicCount);

        if (log.isDebugEnabled() && !lines.isEmpty()) {
            lines.sort(Comparator.naturalOrder());
            log.debug("[simple-jwt-auth] endpoint policy map:\n{}", String.join("\n", lines));
        }
    }

    private static String renderMethods(Set<RequestMethod> methods) {
        if (methods == null || methods.isEmpty()) return "ANY";
        List<String> names = new ArrayList<>();
        for (RequestMethod m : methods) names.add(m.name());
        names.sort(Comparator.naturalOrder());
        return String.join(",", names);
    }
}
