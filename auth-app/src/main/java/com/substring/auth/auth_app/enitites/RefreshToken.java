package com.substring.auth.auth_app.enitites;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "refresh_token",indexes = {
        @Index(name = "refresh_tokens_jti_idx",columnList = "jti",unique = true),
        @Index(name = "refresh_tokens_user_id_idx",columnList = "user_id")
})
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "jti",unique = true,nullable = false,updatable = false)
    private String jti;

    //One User can generate many tokens
    @ManyToOne(optional = false,fetch = FetchType.LAZY)
    //@ManyToOne → many token records can belong to one user.
    //optional = false → the token must be associated with a user (user_id cannot be null).
    //fetch = FetchType.LAZY → when you load a token, Hibernate does not immediately load the user. The user is fetched only when token.getUser() is accessed.
    @JoinColumn(name = "user_id",nullable = false,updatable = false)
    private User user;

    @Column(updatable = false,nullable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant expiredAt;

    @Column(nullable = false)
    private boolean revoked;//when the password changes
    private String replacedByToken;
}
