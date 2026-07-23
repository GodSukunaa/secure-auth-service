package com.substring.auth.auth_app.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.substring.auth.auth_app.dtos.ApiError;
import com.substring.auth.auth_app.security.JwtAuthenticationFilter;
import jakarta.annotation.Nonnull;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class  SecurityConfig {


    private JwtAuthenticationFilter jwtAuthenticationFilter;
    private AuthenticationSuccessHandler successHandler;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter, AuthenticationSuccessHandler successHandler) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.successHandler = successHandler;
    }

    //Secure Interaction with api
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())//cross-origin resource sharing is enforced by browser to handle the response from being read if cors not allowed
                .sessionManagement(sm->sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                //these are the routes configuration
                .authorizeHttpRequests( authorizedHttpRequest ->
                authorizedHttpRequest.requestMatchers("/api/v1/auth/register").permitAll()
                .requestMatchers("/api/v1/auth/login").permitAll()
                        .requestMatchers("/api/v1/auth/refresh").permitAll()
                        .requestMatchers("/api/v1/auth/logout").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth ->
                                oauth.successHandler(successHandler)
                                        .failureHandler(null)
                )
                .logout(AbstractHttpConfigurer::disable)
                //this handle the non-authorized to secure api
                .exceptionHandling(ex->ex.authenticationEntryPoint((request,response,e)->{
                    //error msg send to client
//                    e.printStackTrace();
                    response.setStatus(401);
                    response.setContentType("application/json");

                    String message = e.getMessage();
                    String error =  (String) request.getAttribute("error");

                    //To set if actual error occurred then sent on msg
                    if (error != null){
                        message = error;
                    }
                    //This below is point to display the error MSG on client server like postman
//                    Map<String,Object> errorMap = Map.of("message",message,"status",401);
                    var apiError = ApiError.of(HttpStatus.UNAUTHORIZED.value(), "Unauthorized Access",message,request.getRequestURI(),true);
                    var objectMapper = new ObjectMapper();

                    response.getWriter().write(objectMapper.writeValueAsString(apiError));
                }))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);//jwtAuthenticationFilter runs earlier in the filter chain than UsernamePasswordAuthenticationFilter.
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(@Nonnull AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();

    }

//    @Bean
//    public UserDetailsService users() {
//        //These are the default users that allow to get data using api
//        User.UserBuilder userBuilder = User.withDefaultPasswordEncoder();
//        UserDetails user1 = userBuilder.username("pavan").password("abc").roles("Admin").build();
//        UserDetails user2 = userBuilder.username("neha").password("ok").build();
//        UserDetails user3 = userBuilder.username("rohan").password("").build();
//        return new InMemoryUserDetailsManager(user1,user2,user3);
//    }
}
