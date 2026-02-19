package com.spring.lica.oauth2.service;

import com.spring.lica.domain.entity.User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.*;

@Service
public class OidcClaimService {

    private static final Map<String, List<String>> SCOPE_CLAIMS = Map.of(
        "profile", List.of("name", "given_name", "family_name", "nickname", "picture",
            "profile", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"),
        "email", List.of("email", "email_verified"),
        "phone", List.of("phone_number", "phone_number_verified"),
        "address", List.of("address")
    );

    public boolean isOidcRequest(String scope) {
        if (!StringUtils.hasText(scope)) {
            return false;
        }
        return Arrays.asList(scope.split("\\s+")).contains("openid");
    }

    public Map<String, Object> resolveClaims(User user, String scope) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", user.getUsername());

        if (!StringUtils.hasText(scope)) {
            return claims;
        }

        Set<String> scopes = new HashSet<>(Arrays.asList(scope.split("\\s+")));

        if (scopes.contains("profile")) {
            String name = buildName(user);
            if (name != null) claims.put("name", name);
            if (user.getGivenName() != null) claims.put("given_name", user.getGivenName());
            if (user.getFamilyName() != null) claims.put("family_name", user.getFamilyName());
            if (user.getNickname() != null) claims.put("nickname", user.getNickname());
            if (user.getPicture() != null) claims.put("picture", user.getPicture());
            if (user.getProfile() != null) claims.put("profile", user.getProfile());
            if (user.getWebsite() != null) claims.put("website", user.getWebsite());
            if (user.getGender() != null) claims.put("gender", user.getGender());
            if (user.getBirthdate() != null) claims.put("birthdate", user.getBirthdate());
            if (user.getZoneinfo() != null) claims.put("zoneinfo", user.getZoneinfo());
            if (user.getLocale() != null) claims.put("locale", user.getLocale());
            if (user.getUpdatedAt() != null) claims.put("updated_at", user.getUpdatedAt().getEpochSecond());
        }

        if (scopes.contains("email")) {
            if (user.getEmail() != null) claims.put("email", user.getEmail());
            claims.put("email_verified", user.isEmailVerified());
        }

        if (scopes.contains("phone")) {
            if (user.getPhoneNumber() != null) claims.put("phone_number", user.getPhoneNumber());
            claims.put("phone_number_verified", user.isPhoneNumberVerified());
        }

        if (scopes.contains("address")) {
            if (user.getAddress() != null) claims.put("address", user.getAddress());
        }

        return claims;
    }

    private String buildName(User user) {
        if (StringUtils.hasText(user.getGivenName()) || StringUtils.hasText(user.getFamilyName())) {
            String given = user.getGivenName() != null ? user.getGivenName() : "";
            String family = user.getFamilyName() != null ? user.getFamilyName() : "";
            return (given + " " + family).trim();
        }
        return user.getUsername();
    }
}
