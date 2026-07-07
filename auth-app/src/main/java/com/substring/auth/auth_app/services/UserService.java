package com.substring.auth.auth_app.services;

import com.substring.auth.auth_app.dtos.UserDto;

public interface UserService {
    //Create User
    UserDto createUser(UserDto userDto);

    //get user by email
    UserDto getUserByEmail(String userEmail);

    //Update User
    UserDto updateUser(UserDto userDto, String userId);
    //Delete user
    void deleteUser(String userId);

    //get user by id
    UserDto getUserById(String userId);

    //get all User
    Iterable<UserDto> getAllUsers();

}
