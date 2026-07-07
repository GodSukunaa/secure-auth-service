package com.substring.auth.auth_app.services;

import com.substring.auth.auth_app.enitites.Provider;
import com.substring.auth.auth_app.enitites.User;
import com.substring.auth.auth_app.exceptions.ResourceNotFoundException;
import com.substring.auth.auth_app.helpers.UserHelper;
import com.substring.auth.auth_app.repository.UserRepository;

import com.substring.auth.auth_app.dtos.UserDto;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor

public class UserServiceImpl implements UserService{
    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    @Override
    @Transactional //To Follows the transactional Properties
    public UserDto createUser(UserDto userDto) {

        //To check whether Add email of user
        if(userDto.getEmail() == null || userDto.getEmail().isBlank()){
           throw new IllegalArgumentException("Email is Required!");
        }

        //To check whether the email present
        if (userRepository.existsByEmail(userDto.getEmail())){
            throw new IllegalArgumentException("Email already exist");
        }

        // if you have extra checks __put here...
        User user = modelMapper.map(userDto,User.class);
        user.setProvider(userDto.getProvider() != null ? userDto.getProvider() : Provider.LOCAL);
        //Role assign here

        return modelMapper.map(userRepository.save(user),UserDto.class);
    }

    @Override
    public UserDto getUserByEmail(String email) {

        User s = userRepository.findByEmail(email).orElseThrow(() -> new ResourceNotFoundException("User Not Found with given email id !"));
        return modelMapper.map(s,UserDto.class);
    }

    @Override
    public UserDto updateUser(UserDto userDto, String userId) {
        UUID uId = UserHelper.parseUUID(userId);

        User existingUser = userRepository.findById(uId).orElseThrow(() -> new ResourceNotFoundException("User Not Found"));
        if (userDto.getName() != null) existingUser.setName(userDto.getName());
        if (userDto.getImage() != null) existingUser.setImage(userDto.getImage());
        if (userDto.getProvider() != null) existingUser.setProvider(userDto.getProvider());
        //TODO: change password updation logic...
        if (userDto.getPassword() != null) existingUser.setPassword(userDto.getPassword());
        existingUser.setEnable(userDto.isEnable());

        existingUser.setUpdatedAt(Instant.now());

        User updatedUser = userRepository.save(existingUser);
        return modelMapper.map(updatedUser,UserDto.class);
    }

    @Override
    public void deleteUser(String userId) {
        UUID uId = UserHelper.parseUUID(userId);
        User user = userRepository.findById(uId).orElseThrow(() -> new ResourceNotFoundException("User Not Found with given Id "));
        userRepository.delete(user);
    }

    @Override
    public UserDto getUserById(String userId) {
        User user = userRepository.findById(UserHelper.parseUUID(userId)).orElseThrow(() -> new ResourceNotFoundException("From the ID the user not found."));
        return modelMapper.map(user,UserDto.class);
    }

    @Override
    @Transactional
    public Iterable<UserDto> getAllUsers() {
        return userRepository.findAll().stream().map(user -> modelMapper.map(user,UserDto.class)).toList();
    }
}
