package com.substring.auth.auth_app.services;

import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

@Service
@Getter
public class CookieService {
    private final String refreshTokenCookieName ;
    private final boolean cookieHttpOnly;
    private final boolean cookieSecure;
    private final String cookieDomain;
    private final String cookieSameSite;


    public CookieService(
            @Value("${security.jwt.refresh-token-cookie-name}") String refreshTokenCookieName,
            @Value("${security.jwt.cookie-http-only}") boolean cookieHttpOnly,
            @Value("${security.jwt.cookie-secure}")boolean cookieSecure,
            @Value("${security.jwt.cookie-domain}")String cookieDomain,
            @Value("${security.jwt.cookie-same-site}")String cookieSameSite) {
        this.refreshTokenCookieName = refreshTokenCookieName;
        this.cookieHttpOnly = cookieHttpOnly;//Used to prevents JavaScripts from reading the cookies
        this.cookieSecure = cookieSecure;
        this.cookieDomain = cookieDomain;
        this.cookieSameSite = cookieSameSite;
    }

    //Create Methods to attach cookie to response
    public void attachRefreshCookie(HttpServletResponse response,String value,int maxAge){
        var responseCookieBuilder = ResponseCookie.from(refreshTokenCookieName,value) //To create an http response cookie
                .httpOnly(cookieHttpOnly)//Browser can't expose the cookie to JS
                .secure(cookieSecure)//Only Https
                .path("/")//without this cookie may work only for one endpoint
                .maxAge(maxAge)//Cookie expiry
                .sameSite(cookieSameSite);

        //Only add if the user Configured the domain
        if (cookieDomain != null && !cookieDomain.isBlank()){
            responseCookieBuilder.domain(cookieDomain);
        }

        ResponseCookie responseCookie = responseCookieBuilder.build();//Builder becomes the actual cookie
        response.addHeader(HttpHeaders.SET_COOKIE,responseCookie.toString());
    }

    //Clear Refresh Cookies
    public void clearRefreshCookie(HttpServletResponse response){
        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from(refreshTokenCookieName,"")
                .maxAge(0)//delete Immediately
                .httpOnly(cookieHttpOnly)
                .path("/")
                .sameSite(cookieSameSite)
                .secure(cookieSecure);

        if (cookieDomain != null && !cookieDomain.isBlank()){
            builder.domain(cookieDomain);
        }
        ResponseCookie responseCookie = builder.build();
        response.addHeader(HttpHeaders.SET_COOKIE,responseCookie.toString());

    }

    public void addNoStoreHeaders(HttpServletResponse response) {
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader("Pragma", "no-cache");
    }
}

