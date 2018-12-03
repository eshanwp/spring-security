package com.boot.security.service.implementation;

import com.boot.security.dto.UserDto;
import com.boot.security.entity.PasswordResetToken;
import com.boot.security.entity.User;
import com.boot.security.entity.VerificationToken;
import com.boot.security.error.auth.EmailExistsException;

import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.Optional;

public interface IUserService {

    User registerNewUserAccount(UserDto userDto)
            throws EmailExistsException;

    User getUser(String verificationToken);

    void saveRegisteredUser(User user);

    void deleteUser(User user);

    void createVerificationToken(User user, String token);

    VerificationToken getVerificationToken(String VerificationToken);

    void createVerificationTokenForUser(User user, String token);

    User findUserByEmail(String userEmail);

    PasswordResetToken getPasswordResetToken(String token);

    void createPasswordResetTokenForUser(User user, String token);

    VerificationToken generateNewVerificationToken(String existingVerificationToken);

    void changeUserPassword(User user, String newPassword);

    boolean checkIfValidOldPassword(User user, String oldPassword);

    User getUserByPasswordResetToken(String token);

    Optional<User> getUserByID(long id);

    String validateVerificationToken(String token);

    String generateQRUrl(User user) throws UnsupportedEncodingException;

    User updateUser2FA(boolean use2FA);

    List<String> getUsersFromSessionRegistry();
}
