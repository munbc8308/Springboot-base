package com.spring.lica.auth;

import com.spring.lica.sso.SsoProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.util.Locale;

@Slf4j
@Service
public class EmailService {

    private final SsoProperties ssoProperties;
    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    public EmailService(SsoProperties ssoProperties,
                        @Autowired(required = false) JavaMailSender mailSender,
                        TemplateEngine templateEngine) {
        this.ssoProperties = ssoProperties;
        this.mailSender = mailSender;
        this.templateEngine = templateEngine;
    }

    public void sendVerificationEmail(String to, String token) {
        sendVerificationEmail(to, token, Locale.KOREAN);
    }

    public void sendVerificationEmail(String to, String token, Locale locale) {
        String link = ssoProperties.issuer() + "/api/auth/verify-email?token=" + token;

        Context context = new Context(locale);
        context.setVariable("verificationLink", link);

        String body = templateEngine.process("email/verification", context);
        sendHtmlEmail(to, "[Lica SSO] Email Verification", body);
    }

    public void sendPasswordResetEmail(String to, String token) {
        sendPasswordResetEmail(to, token, Locale.KOREAN);
    }

    public void sendPasswordResetEmail(String to, String token, Locale locale) {
        String link = ssoProperties.issuer() + "/api/auth/reset-password?token=" + token;

        Context context = new Context(locale);
        context.setVariable("resetLink", link);

        String body = templateEngine.process("email/password-reset", context);
        sendHtmlEmail(to, "[Lica SSO] Password Reset", body);
    }

    public void sendPasswordChangedNotification(String to) {
        sendPasswordChangedNotification(to, Locale.KOREAN);
    }

    public void sendPasswordChangedNotification(String to, Locale locale) {
        Context context = new Context(locale);
        String body = templateEngine.process("email/password-changed", context);
        sendHtmlEmail(to, "[Lica SSO] Password Changed", body);
    }

    public void sendAccountLockedNotification(String to) {
        sendAccountLockedNotification(to, Locale.KOREAN);
    }

    public void sendAccountLockedNotification(String to, Locale locale) {
        Context context = new Context(locale);
        String body = templateEngine.process("email/account-locked", context);
        sendHtmlEmail(to, "[Lica SSO] Account Locked", body);
    }

    private void sendHtmlEmail(String to, String subject, String body) {
        if (mailSender == null) {
            log.info("[MAIL STUB] To: {}, Subject: {}", to, subject);
            log.debug("[MAIL STUB] Body: {}", body);
            return;
        }

        try {
            var message = mailSender.createMimeMessage();
            var helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(body, true);
            mailSender.send(message);
            log.info("Email sent to {}: {}", to, subject);
        } catch (Exception e) {
            log.warn("Failed to send email to {}: {}", to, e.getMessage());
            log.info("[MAIL FALLBACK] To: {}, Subject: {}", to, subject);
        }
    }
}
