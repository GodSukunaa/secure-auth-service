package com.substring.auth.auth_app.security;

import com.substring.auth.auth_app.enitites.Provider;
import com.substring.auth.auth_app.enitites.RefreshToken;
import com.substring.auth.auth_app.enitites.User;
import com.substring.auth.auth_app.repository.RefreshTokenRepository;
import com.substring.auth.auth_app.repository.UserRepository;
import com.substring.auth.auth_app.services.CookieService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final CookieService cookieService;
    private RefreshTokenRepository refreshTokenRepository;

    @Value("${app.auth.frontend.success-redirect}")
    private String frontendSuccessUrl;

    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
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
               User user1 = User.builder()
                        .email(email)
                        .name(name)
                        .enable(true)
                        .image(picture)
                        .provider(Provider.GOOGLE)
                       .providerId(googleId)
                        .build();
                user = userRepository.findByEmail(email).orElseGet(() -> userRepository.save(user1));
            }
            case "github" ->{
                String name = oAuth2User.getAttributes().getOrDefault("login", "").toString();
                String githubId = oAuth2User.getAttributes().getOrDefault("id", "").toString();
                String picture = oAuth2User.getAttributes().getOrDefault("avatar_url", "").toString();
                String email =(String) oAuth2User.getAttributes().get("email");

                if (email == null) email = name + "@github.com";

                User user1 = User.builder()
                        .email(email)
                        .name(name)
                        .enable(true)
                        .image(picture)
                        .provider(Provider.GITHUB)
                        .providerId(githubId)
                        .build();
                user = userRepository.findByEmail(email).orElseGet(() -> userRepository.save(user1));


            }
            default -> {
                throw new RuntimeException("Invalid Registration ID ");
            }
        }

        //Refresh
        //User --> Revoke the refresh token, HOW?

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

//         response.getWriter().write("Login Successful");
        response.sendRedirect(frontendSuccessUrl);
    }
}
