package pt.isep.desofs.enderchest.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import pt.isep.desofs.enderchest.exception.resource.UserNotFoundException;
import pt.isep.desofs.enderchest.service.UserService;
import pt.isep.desofs.enderchest.service.dto.UserProfileResponse;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("UserController Unit Tests")
class UserControllerTest {

    private static final String USER_ID = "123e4567-e89b-12d3-a456-426614174000";
    private static final UUID USER_UUID = UUID.fromString(USER_ID);

    @Mock
    private UserService userService;

    @InjectMocks
    private UserController controller;

    @Test
    @DisplayName("getCurrentUserProfile: existing user returns 200")
    void getCurrentUserProfile_success_returnsOk() {
        UserProfileResponse profile = new UserProfileResponse(
                USER_UUID,
                "john.doe",
                "john.doe@example.com",
                "John Doe",
                10L,
                3L,
                7L
        );
        when(userService.getUserProfile(USER_UUID)).thenReturn(profile);

        ResponseEntity<UserProfileResponse> response = controller.getCurrentUserProfile(USER_ID);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertSame(profile, response.getBody());
        assertEquals("john.doe", response.getBody().getUsername());
    }

    @Test
    @DisplayName("getCurrentUserProfile: invalid user id returns 400")
    void getCurrentUserProfile_invalidUserId_returnsBadRequest() {
        ResponseEntity<UserProfileResponse> response = controller.getCurrentUserProfile("not-a-uuid");

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNull(response.getBody());
        verifyNoInteractions(userService);
    }

    @Test
    @DisplayName("getCurrentUserProfile: missing user returns 404")
    void getCurrentUserProfile_missingUser_returnsNotFound() {
        when(userService.getUserProfile(USER_UUID)).thenThrow(new UserNotFoundException(USER_UUID));

        ResponseEntity<UserProfileResponse> response = controller.getCurrentUserProfile(USER_ID);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNull(response.getBody());
    }

    @Test
    @DisplayName("checkUserExists: existing user returns 200")
    void checkUserExists_existing_returnsOk() {
        when(userService.checkUserExists(USER_UUID)).thenReturn(true);

        ResponseEntity<Void> response = controller.checkUserExists(USER_ID);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNull(response.getBody());
    }

    @Test
    @DisplayName("checkUserExists: missing user returns 404")
    void checkUserExists_missing_returnsNotFound() {
        when(userService.checkUserExists(USER_UUID)).thenReturn(false);

        ResponseEntity<Void> response = controller.checkUserExists(USER_ID);

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNull(response.getBody());
    }

    @Test
    @DisplayName("checkUserExists: invalid user id returns 404")
    void checkUserExists_invalidUserId_returnsNotFound() {
        ResponseEntity<Void> response = controller.checkUserExists("not-a-uuid");

        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertNull(response.getBody());
        verifyNoInteractions(userService);
    }
}
