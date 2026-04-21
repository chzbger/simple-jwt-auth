package com.simplejwtauth.domain.model;

import java.io.Serializable;

public record TokenFamily(Long userId, String familyId) implements Serializable {}
