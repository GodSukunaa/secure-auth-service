package com.substring.auth.auth_app.dtos;

import com.substring.auth.auth_app.enitites.Provider;
import com.substring.auth.auth_app.enitites.Role;
import lombok.*;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserDto {
    private UUID id;//It's type of class that represent unique id
    private String email;
    private String name;
    private String password;
    private String image;
    private boolean enable=true;
    private Instant createdAt = Instant.now();//For time
    private Instant updateAt = Instant.now();
    private Provider provider = Provider.LOCAL; //To know the user logging from which provider like via facebook,Instagram,email,phone
    private Set<RoleDto> roles = new HashSet<>();

}
