package com.simplejwtauth.auth.domain;

import java.io.Serializable;

public record TokenFamily(Long userId, String familyId) implements Serializable {}
