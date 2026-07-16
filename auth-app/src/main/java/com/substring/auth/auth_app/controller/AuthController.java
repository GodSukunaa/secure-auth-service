package com.substring.auth.auth_app.controller;

import com.substring.auth.auth_app.dtos.LoginRequest;
import com.substring.auth.auth_app.dtos.RefreshTokenRequest;
import com.substring.auth.auth_app.dtos.TokenResponse;
import com.substring.auth.auth_app.dtos.UserDto;
import com.substring.auth.auth_app.enitites.RefreshToken;
import com.substring.auth.auth_app.enitites.User;
import com.substring.auth.auth_app.repository.RefreshTokenRepository;
import com.substring.auth.auth_app.repository.UserRepository;
import com.substring.auth.auth_app.security.JwtService;
import com.substring.auth.auth_app.services.AuthService;
import com.substring.auth.auth_app.services.CookieService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final RefreshTokenRepository refreshTokenRepository;

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final ModelMapper modelMapper;

    private final CookieService cookieService;

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest loginRequest, HttpServletResponse response){
        //Authenticate
        Authentication authenticate = authenticate(loginRequest);//The real check of Username nd password
        User user = userRepository.findByEmail(loginRequest.email()).orElseThrow(()->new BadCredentialsException("Invalid User Email!"));//Load user Entity, After authentication,you fetch the complete user Object
        if (!user.isEnable()){ //Check User Status
            throw new DisabledException("User is Disabled");
        }

        //Generate Refresh Token
        String jti = UUID.randomUUID().toString();
        var refreshTokenOb = RefreshToken.builder()
                .jti(jti)
                .user(user)
                .createdAt(Instant.now())
                .expiredAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();

        //Save the info of refreshToken here id is saving
        refreshTokenRepository.save(refreshTokenOb);


        //Generate Access Token
        String tokenAccess = jwtService.generateTokenAccess(user);
        String refreshToken = jwtService.generateRefreshToken(user,refreshTokenOb.getJti());

        //Use Cookie Services to attach refresh token in cookie
        cookieService.attachRefreshCookie(response,refreshToken,(int)jwtService.getRefreshTtlSeconds());

        cookieService.addNoStoreHeaders(response);
        TokenResponse tokenResponse  = TokenResponse.of(tokenAccess,refreshToken,jwtService.getAccessTtlSeconds(),modelMapper.map(user,UserDto.class));
        return ResponseEntity.ok(tokenResponse);
    }

    //Creating the Api for Renew Access and Refresh token
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refreshToken(
            @RequestBody (required = false)RefreshTokenRequest body,
            HttpServletResponse response,//in cookie to add response
            HttpServletRequest request//We can read from cookies
            ){

        String refreshToken = readRefreshTokenFromRequest(body,request).orElseThrow(() -> new BadCredentialsException("Refresh Token is Missing"));

        //This checks the refresh Token or access token
        if (!jwtService.isRefreshToken(refreshToken)){
            throw new BadCredentialsException("Invalid Refresh Token Type");
        }

        String jti = jwtService.getJti(refreshToken);
        UUID userId = jwtService.getUserId(refreshToken);

        //Create method in RefreshTokenRepository
        RefreshToken storeRefreshToken = refreshTokenRepository.findByJti(jti).orElseThrow(() -> new BadCredentialsException("Refresh Token Not Reccognized"));

        if (storeRefreshToken.isRevoked()){
            throw new BadCredentialsException("Refresh Token expired or Revoked");
        }

        if (storeRefreshToken.getExpiredAt().isBefore(Instant.now())){
            throw new BadCredentialsException("Refresh Token Expired");
        }

        //If this id not match means someone else try to access through this token
        if (!storeRefreshToken.getUser().getId().equals(userId)){
            throw new BadCredentialsException("Refresh Token not Belong to this User");
        }

        //Refresh Token Rotation
        storeRefreshToken.setRevoked(true);
        String newJti = UUID.randomUUID().toString();
        storeRefreshToken.setReplacedByToken(newJti);
        refreshTokenRepository.save(storeRefreshToken);

        //Generate new Access And Refresh Token
        User user = storeRefreshToken.getUser();
        var newRefreshTokenObj = RefreshToken.builder()
                .jti(newJti)
                .user(user)
                .createdAt(Instant.now())
                .expiredAt(Instant.now().plusSeconds(jwtService.getRefreshTtlSeconds()))
                .revoked(false)
                .build();
        refreshTokenRepository.save(newRefreshTokenObj);

        String newAccessToken = jwtService.generateTokenAccess(user);
        String newRefreshToken = jwtService.generateRefreshToken(user,newRefreshTokenObj.getJti());

        cookieService.attachRefreshCookie(response,newRefreshToken,(int) jwtService.getRefreshTtlSeconds());
        cookieService.addNoStoreHeaders(response);

        return ResponseEntity.ok(TokenResponse.of(newAccessToken,newRefreshToken,jwtService.getAccessTtlSeconds(),modelMapper.map(user,UserDto.class)));

    }


    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response,HttpServletRequest request){
        readRefreshTokenFromRequest(null,request).ifPresent(token ->{
            try{
                if (jwtService.isRefreshToken(token)){
                    String jti = jwtService.getJti(token);
                    refreshTokenRepository.findByJti(jti).ifPresent(rt->{
                        rt.setRevoked(true);
                        refreshTokenRepository.save(rt);
                    });
                }
            }catch (JwtException ignored){
            }
        });

        //Use CookieUtil (Same behaviour)
        cookieService.clearRefreshCookie(response);
        cookieService.addNoStoreHeaders(response);
        SecurityContextHolder.clearContext();
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    //This method will read refresh token from request Header or body
    private Optional<String> readRefreshTokenFromRequest(RefreshTokenRequest body, HttpServletRequest request) {
        //1.Prefer Reading, refresh token from cookie
        //This Only run when Browser carries any cookies
        if (request.getCookies() != null){
            Optional<String> fromCookie = Arrays.stream(request.getCookies())
                    .filter(c->cookieService.getRefreshTokenCookieName().equals(c.getName()))//Keeps only the refresh token cookie.
                    .map(Cookie::getValue)
                    .filter(v->!v.isBlank())
                    .findFirst();

            // If the browser sent cookies, try to find the refresh token cookie.
            if (fromCookie.isPresent()){
                return fromCookie;
            }
        }


        //2 : Body if it sent on body
        if (body != null && body.refreshToken() != null && !body.refreshToken().isBlank()){
            return Optional.of(body.refreshToken());
        }

        //3. Custom header
        String refreshHeader = request.getHeader("X-Refresh-Token");
        if (refreshHeader != null && !refreshHeader.isBlank()){
            return Optional.of(refreshHeader.trim());
        }

        //Authorization = Bearer <token>
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.regionMatches(true,0,"Bearer ",0,7)){
            String candidate = authHeader.substring(7).trim();
            if (!candidate.isEmpty()){
                try {
                    if (jwtService.isRefreshToken(candidate)){
                        return Optional.of(candidate);
                    }
                } catch (Exception ignored){

                }
            }
        }
        return Optional.empty();
    }

    private Authentication authenticate(LoginRequest loginRequest){
        try{
           return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.email(),loginRequest.password()));
        }catch (Exception e){
            // if the password wrong sends Credential exception because this pass this exception and move to the ManagerProvider
            throw new BadCredentialsException("Invalid User or Password!!");
        }
    }

    @PostMapping("/register")
    public ResponseEntity<UserDto> registerUser(@RequestBody UserDto userDto){
       return ResponseEntity.status(HttpStatus.CREATED).body(authService.registerUser(userDto));
    }
}
