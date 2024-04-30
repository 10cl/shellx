package com.toscl.shellx.utils;

import java.security.SecureRandom;
import java.util.UUID;

public class UniqueIdentifierGenerator {

    private static final String ALLOWED_CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    public static String generateUniqueIdentifier() {
        String uuid = UUID.randomUUID().toString();
        String randomString = generateRandomString(12);
        return uuid.substring(0, 8) + randomString + uuid.substring(24);
    }

    private static String generateRandomString(final int length) {
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(ALLOWED_CHARACTERS.charAt(random.nextInt(ALLOWED_CHARACTERS.length())));
        }
        return sb.toString();
    }
}
