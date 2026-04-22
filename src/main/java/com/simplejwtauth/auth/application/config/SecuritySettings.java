package com.simplejwtauth.auth.application.config;

import java.util.List;

public record SecuritySettings(Policy defaultPolicy, List<String> publicPaths) {

    public SecuritySettings {
        if (defaultPolicy == null) defaultPolicy = Policy.ALLOW;
        publicPaths = publicPaths == null ? List.of() : List.copyOf(publicPaths);
    }

    public enum Policy { ALLOW, DENY }
}
