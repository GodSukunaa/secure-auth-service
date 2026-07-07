package com.substring.auth.auth_app.helpers;

import java.util.UUID;

public class UserHelper {
    public static UUID parseUUID(String userId){
        return UUID.fromString(userId);
    }
}
