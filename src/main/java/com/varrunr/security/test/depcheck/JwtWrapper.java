package com.varrunr.security.test.depcheck;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang3.RandomStringUtils;

import java.util.HashMap;
import java.util.Map;

public class JwtWrapper {
    public static JWTClaimsSet generateJwtClaims(Map<String, String> customClaims) {
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder();
        customClaims.entrySet().stream().forEach(entry -> claimsSetBuilder.claim(entry.getKey(), entry.getValue()));
        return claimsSetBuilder.build();
    }

    public static void main(String[] args) {
        Map<String, String> customClaims = new HashMap<>();
        // RandomStringUtils is vulnerable to a CVE in commons-lang3
        customClaims.put("testKey", RandomStringUtils.random(20));
        generateJwtClaims(customClaims);
    }
}
