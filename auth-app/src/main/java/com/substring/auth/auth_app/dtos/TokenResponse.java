package com.substring.auth.auth_app.dtos;

public record TokenResponse(
        String accessToken,
        String refreshToken,
        long expiresIn,
        String tokenType,
        UserDto userDto) {
    public static TokenResponse of(String accessToken, String refreshToken, long expiresIn,UserDto userDto){
        return new TokenResponse(accessToken, refreshToken, expiresIn, "Bearer", userDto);
    }

}
