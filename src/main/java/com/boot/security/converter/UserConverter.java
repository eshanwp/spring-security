package com.boot.security.converter;

import com.boot.security.dto.UserDto;
import com.boot.security.entity.User;
import org.springframework.stereotype.Component;

@Component
public class UserConverter {

    public static User dtoToEntity(UserDto userDto){

        User user = new User();
        user.setFirstName(userDto.getFirstName());
        user.setLastName(userDto.getLastName());
        user.setEmail(userDto.getEmail());
        user.setPassword(userDto.getPassword());
//        user.setUsing2FA(userDto.getUsing2FA());

        return user;
    }

    public static UserDto entityToDto(User user){

        UserDto userDto = new UserDto();
        userDto.setFirstName(user.getFirstName());
        userDto.setLastName(user.getLastName());
        userDto.setEmail(user.getEmail());
        userDto.setPassword(user.getPassword());
//        userDto.setUsing2FA(user.getUsing2FA());
        return userDto;
    }
}
