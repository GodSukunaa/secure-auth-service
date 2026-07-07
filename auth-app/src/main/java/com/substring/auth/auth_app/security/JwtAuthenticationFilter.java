package com.substring.auth.auth_app.security;

import com.substring.auth.auth_app.helpers.UserHelper;
import com.substring.auth.auth_app.repository.UserRepository;
import io.jsonwebtoken.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private  final JwtService jwtService;
    private final UserRepository userRepository;
    private Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);



    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //This is set as Authorization Header
        String header = request.getHeader("Authorization");//Reads the Authorization header from the incoming HTTP request.

        logger.info("Authorization Header :{} ",header);//Logs the header value for debugging.


        if (header!=null && header.startsWith("Bearer ")){

            //token extract and validate then authentication create and then set into security context
            String token = header.substring(7);//because the token start from 7th char before it bearer have the token

            try {
            //Checks if token isAccessed or not
            if (!jwtService.isAccessToken(token)){
                filterChain.doFilter(request,response);
                return;
            }
                Jws<Claims> parse = jwtService.parse(token);
                Claims payloads = parse.getPayload();
                String userId = payloads.getSubject();
                UUID userUuid = UserHelper.parseUUID(userId);

                userRepository.findById(userUuid)
                        .ifPresent( user ->{
                            //Check user enabled
                            if (user.isEnable()){
                                // If user took from database
                                List<GrantedAuthority> authorities = user.getAuthorities() == null ? List.of() :
                                        user.getRoles().stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList());

                                //To set the authentication to security
                                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                        user.getEmail(),
                                        null,
                                        authorities
                                );

                                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                                if (SecurityContextHolder.getContext().getAuthentication() ==null)
                                    SecurityContextHolder.getContext().setAuthentication(authentication);

                            }
                        });

            }catch (ExpiredJwtException e){
                request.setAttribute("error","Token Expired");
//                e.printStackTrace();
            }
            catch (Exception e){
                request.setAttribute("error","Invalid Token");
            }
        }
        filterChain.doFilter(request,response);
    }

    //Why used ?
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getRequestURI().startsWith("/api/v1/auth");
    }
}
