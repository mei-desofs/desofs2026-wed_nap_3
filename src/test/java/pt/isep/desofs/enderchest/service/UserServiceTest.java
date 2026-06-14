package pt.isep.desofs.enderchest.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import pt.isep.desofs.enderchest.entity.User;
import pt.isep.desofs.enderchest.exception.resource.UserNotFoundException;
import pt.isep.desofs.enderchest.repository.FileRepository;
import pt.isep.desofs.enderchest.repository.UserRepository;
import pt.isep.desofs.enderchest.service.dto.UserProfileResponse;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("UserService Unit Tests")
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private FileRepository fileRepository;

    @InjectMocks
    private UserService userService;

    // ── getUserProfile ────────────────────────────────────────────────────────

    @Test
    @DisplayName("getUserProfile: existing user returns profile with storage data")
    void getUserProfile_existing_returnsProfile() throws UserNotFoundException {
        UUID userId = UUID.randomUUID();
        User user = new User("john", "john@example.com", "hash", "John", "Doe");
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(fileRepository.calculateUserStorageUsage(userId)).thenReturn(1024L);

        UserProfileResponse response = userService.getUserProfile(userId);

        assertNotNull(response);
        assertEquals("john@example.com", response.getEmail());
        assertEquals(1024L, response.getUsedStorage());
        assertEquals("John Doe", response.getFullName());
        assertTrue(response.getAvailableStorage() > 0);
    }

    @Test
    @DisplayName("getUserProfile: missing user throws UserNotFoundException")
    void getUserProfile_missing_throws() {
        UUID userId = UUID.randomUUID();
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> userService.getUserProfile(userId));
    }

    @Test
    @DisplayName("getUserProfile: availableStorage = storageQuota - usedStorage")
    void getUserProfile_storageCalculation_isCorrect() throws UserNotFoundException {
        UUID userId = UUID.randomUUID();
        User user = new User("alice", "alice@example.com", "hash", "Alice", "Smith");
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(fileRepository.calculateUserStorageUsage(userId)).thenReturn(500L);

        UserProfileResponse response = userService.getUserProfile(userId);

        assertEquals(response.getStorageQuota() - 500L, response.getAvailableStorage());
    }

    // ── getUserProfileByEmail ─────────────────────────────────────────────────

    @Test
    @DisplayName("getUserProfileByEmail: existing email returns profile")
    void getUserProfileByEmail_existing_returnsProfile() throws UserNotFoundException {
        String email = "jane@example.com";
        User user = new User("jane", email, "hash", "Jane", "Smith");
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(fileRepository.calculateUserStorageUsage(any())).thenReturn(0L);

        UserProfileResponse response = userService.getUserProfileByEmail(email);

        assertEquals(email, response.getEmail());
        assertEquals(0L, response.getUsedStorage());
    }

    @Test
    @DisplayName("getUserProfileByEmail: unknown email throws UserNotFoundException")
    void getUserProfileByEmail_missing_throws() {
        String email = "unknown@test.com";
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class,
                () -> userService.getUserProfileByEmail(email));
    }

    // ── checkUserExists ───────────────────────────────────────────────────────

    @Test
    @DisplayName("checkUserExists: returns true for existing user")
    void checkUserExists_existing_returnsTrue() {
        UUID userId = UUID.randomUUID();
        when(userRepository.existsById(userId)).thenReturn(true);

        assertTrue(userService.checkUserExists(userId));
    }

    @Test
    @DisplayName("checkUserExists: returns false for missing user")
    void checkUserExists_missing_returnsFalse() {
        UUID userId = UUID.randomUUID();
        when(userRepository.existsById(userId)).thenReturn(false);

        assertFalse(userService.checkUserExists(userId));
    }

    // ── calculateUsedStorage ──────────────────────────────────────────────────

    @Test
    @DisplayName("calculateUsedStorage: null from repository returns 0")
    void calculateUsedStorage_nullFromRepo_returnsZero() {
        UUID userId = UUID.randomUUID();
        when(fileRepository.calculateUserStorageUsage(userId)).thenReturn(null);

        long result = userService.calculateUsedStorage(userId);

        assertEquals(0L, result);
    }

    @Test
    @DisplayName("calculateUsedStorage: positive value from repository is returned as-is")
    void calculateUsedStorage_positiveValue_returned() {
        UUID userId = UUID.randomUUID();
        when(fileRepository.calculateUserStorageUsage(userId)).thenReturn(2048L);

        long result = userService.calculateUsedStorage(userId);

        assertEquals(2048L, result);
    }
}
