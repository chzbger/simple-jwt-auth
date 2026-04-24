package com.simplejwtauth.auth.domain;

import java.io.Serializable;

public record TokenFamily(String userId, String familyId) implements Serializable {}
