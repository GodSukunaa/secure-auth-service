package com.substring.auth.auth_app.security;

import com.substring.auth.auth_app.enitites.Provider;
import com.substring.auth.auth_app.enitites.RefreshToken;
import com.substring.auth.auth_app.enitites.User;
import com.substring.auth.auth_app.repository.RefreshTokenRepository;
import com.substring.auth.auth_app.repository.UserRepository;
import com.substring.auth.auth_app.services.CookieService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

@Component
@AllArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private RefreshTokenRepository refreshTokenRepository;
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        logger.info("Successfully authentication");
        logger.info(authentication.toString());
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        //Identify User
        String registrationId = "unknown";
        if (authentication instanceof OAuth2AuthenticationToken token){
            registrationId = token.getAuthorizedClientRegistrationId();
        }

        logger.info("RegistrationId:"+registrationId);
        logger.info("user:"+oAuth2User.getAttributes().toString());

        User user;
        switch (registrationId){
            case "google" -> {
                String googleId = oAuth2User.getAttributes().getOrDefault("sub", "").toString();
                String email = oAuth2User.getAttributes().getOrDefault("email", "").toString();
                String name = oAuth2User.getAttributes().getOrDefault("name", "").toString();
                String picture = oAuth2User.getAttributes().getOrDefault("picture", "").toString();
                user = User.builder()
                        .email(email)
                        .name(name)
                        .enable(true)
                        .image(picture)
                        .provider(Provider.GOOGLE)
                        .build();
                userRepository.findByEmail(email).ifPresentOrElse(user1 -> {
                    logger.info("user is in their database");
                    logger.info(user1.toString());
                }, () -> {
                    userRepository.save(user);
                });
            }
            default -> {
                throw new RuntimeException("Invalid Registration ID ");
            }
        }

        //Username, userEmail, new UserCreate
        String jti = UUID.randomUUID().toString();
         RefreshToken refreshTokenOb = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .revoked(false)
                .createdAt(Instant.now())
                .expiredAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .build();
         refreshTokenRepository.save(refreshTokenOb);
         String accessToken = jwtService.generateTokenAccess(user);
         String refreshToken= jwtService.generateRefreshToken(user,refreshTokenOb.getJti());
         cookieService.attachRefreshCookie(response,refreshToken,(int) jwtService.getRefreshTtlSeconds());

         response.getWriter().write("Login Successful");
    }
}
