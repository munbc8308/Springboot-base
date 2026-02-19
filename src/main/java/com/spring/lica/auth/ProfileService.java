package com.spring.lica.auth;

import com.spring.lica.domain.entity.User;
import com.spring.lica.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class ProfileService {

    private final UserRepository userRepository;

    @Transactional(readOnly = true)
    public Map<String, Object> getProfile(Long userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new ProfileException("User not found"));

        Map<String, Object> profile = new LinkedHashMap<>();
        profile.put("id", user.getId());
        profile.put("username", user.getUsername());
        profile.put("email", user.getEmail());
        profile.put("email_verified", user.isEmailVerified());
        profile.put("mfa_enabled", user.isMfaEnabled());
        profile.put("given_name", user.getGivenName());
        profile.put("family_name", user.getFamilyName());
        profile.put("nickname", user.getNickname());
        profile.put("picture", user.getPicture());
        profile.put("phone_number", user.getPhoneNumber());
        profile.put("phone_number_verified", user.isPhoneNumberVerified());
        profile.put("created_at", user.getCreatedAt());
        profile.put("updated_at", user.getUpdatedAt());
        return profile;
    }

    @Transactional
    public void updateProfile(Long userId, Map<String, String> updates) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new ProfileException("User not found"));

        if (updates.containsKey("given_name")) user.setGivenName(updates.get("given_name"));
        if (updates.containsKey("family_name")) user.setFamilyName(updates.get("family_name"));
        if (updates.containsKey("nickname")) user.setNickname(updates.get("nickname"));
        if (updates.containsKey("picture")) user.setPicture(updates.get("picture"));
        if (updates.containsKey("phone_number")) user.setPhoneNumber(updates.get("phone_number"));
        if (updates.containsKey("gender")) user.setGender(updates.get("gender"));
        if (updates.containsKey("birthdate")) user.setBirthdate(updates.get("birthdate"));
        if (updates.containsKey("zoneinfo")) user.setZoneinfo(updates.get("zoneinfo"));
        if (updates.containsKey("locale")) user.setLocale(updates.get("locale"));
        if (updates.containsKey("website")) user.setWebsite(updates.get("website"));
        if (updates.containsKey("address")) user.setAddress(updates.get("address"));

        userRepository.save(user);
        log.info("Profile updated for user {}", user.getUsername());
    }

    @Transactional
    public void deactivateAccount(Long userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new ProfileException("User not found"));

        user.setEnabled(false);
        userRepository.save(user);
        log.info("Account deactivated for user {}", user.getUsername());
    }

    public static class ProfileException extends RuntimeException {
        public ProfileException(String message) {
            super(message);
        }
    }
}
