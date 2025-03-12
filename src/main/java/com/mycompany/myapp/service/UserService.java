package com.mycompany.myapp.service;

import com.mycompany.myapp.config.Constants;
import com.mycompany.myapp.domain.Authority;
import com.mycompany.myapp.domain.User;
import com.mycompany.myapp.repository.AuthorityRepository;
import com.mycompany.myapp.repository.UserRepository;
import com.mycompany.myapp.security.AuthoritiesConstants;
import com.mycompany.myapp.security.SecurityUtils;
import com.mycompany.myapp.service.dto.AdminUserDTO;
import com.mycompany.myapp.service.dto.UserDTO;
import com.mycompany.myapp.service.event.UserEvent;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.CacheManager;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.jhipster.security.RandomUtil;

import javax.validation.constraints.NotNull;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Service class for managing users.
 */
@Service
@Transactional
public class UserService {

    private final Logger log = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final AuthorityRepository authorityRepository;

    private final CacheManager cacheManager;

    private final ApplicationEventPublisher eventPublisher;

    // Cache for failed login attempts to prevent brute force attacks
    private final Map<String, AtomicInteger> failedLoginAttempts = new ConcurrentHashMap<>();

    // Maximum number of failed attempts before account lockout
    private static final int MAX_FAILED_ATTEMPTS = 5;

    // Lockout duration in minutes
    private static final int ACCOUNT_LOCKOUT_TIME = 30;

    // Map to track locked accounts and their lockout expiration time
    private final Map<String, Instant> lockedAccounts = new ConcurrentHashMap<>();

    public UserService(
        UserRepository userRepository,
        PasswordEncoder passwordEncoder,
        AuthorityRepository authorityRepository,
        CacheManager cacheManager,
        ApplicationEventPublisher eventPublisher
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authorityRepository = authorityRepository;
        this.cacheManager = cacheManager;
        this.eventPublisher = eventPublisher;
    }

    /**
     * Activates a user account using the provided activation key.
     *
     * @param key the activation key
     * @return an Optional containing the activated User if found, empty otherwise
     */
    public Optional<User> activateRegistration(String key) {
        log.debug("Activating user for activation key {}", key);
        return userRepository
            .findOneByActivationKey(key)
            .map(user -> {
                // activate given user for the registration key.
                user.setActivated(true);
                user.setActivationKey(null);
                this.clearUserCaches(user);
                log.debug("Activated user: {}", user);
                eventPublisher.publishEvent(new UserEvent(UserEvent.Type.ACTIVATED, user));
                return user;
            });
    }

    /**
     * Completes the password reset process using the provided reset key.
     *
     * @param newPassword the new password to set
     * @param key the reset key
     * @return an Optional containing the User if found and reset operation was successful, empty otherwise
     */
    public Optional<User> completePasswordReset(String newPassword, String key) {
        log.debug("Reset user password for reset key {}", key);

        // Validate password strength
        if (!isPasswordStrong(newPassword)) {
            throw new WeakPasswordException("Password does not meet security requirements");
        }

        return userRepository
            .findOneByResetKey(key)
            .filter(user -> user.getResetDate().isAfter(Instant.now().minus(1, ChronoUnit.DAYS)))
            .map(user -> {
                user.setPassword(passwordEncoder.encode(newPassword));
                user.setResetKey(null);
                user.setResetDate(null);
                // Reset failed login attempts when password is reset
                failedLoginAttempts.remove(user.getLogin().toLowerCase());
                lockedAccounts.remove(user.getLogin().toLowerCase());
                this.clearUserCaches(user);
                eventPublisher.publishEvent(new UserEvent(UserEvent.Type.PASSWORD_RESET, user));
                return user;
            });
    }

    /**
     * Validates that a password meets the strength requirements.
     *
     * @param password the password to validate
     * @return true if the password is strong enough, false otherwise
     */
    private boolean isPasswordStrong(String password) {
        // Password must be at least 8 characters long
        if (password.length() < 8) {
            return false;
        }

        // Password must contain at least one uppercase letter
        if (!password.matches(".*[A-Z].*")) {
            return false;
        }

        // Password must contain at least one lowercase letter
        if (!password.matches(".*[a-z].*")) {
            return false;
        }

        // Password must contain at least one digit
        if (!password.matches(".*\\d.*")) {
            return false;
        }

        // Password must contain at least one special character
        if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*")) {
            return false;
        }

        return true;
    }

    /**
     * Initiates the password reset process for a user with the given email.
     *
     * @param mail the email address of the user
     * @return an Optional containing the User if found and activated, empty otherwise
     */
    public Optional<User> requestPasswordReset(String mail) {
        return userRepository
            .findOneByEmailIgnoreCase(mail)
            .filter(User::isActivated)
            .map(user -> {
                user.setResetKey(RandomUtil.generateResetKey());
                user.setResetDate(Instant.now());
                this.clearUserCaches(user);
                eventPublisher.publishEvent(new UserEvent(UserEvent.Type.PASSWORD_RESET_REQUESTED, user));
                return user;
            });
    }

    /**
     * Registers a new user in the system.
     *
     * @param userDTO the user data
     * @param password the user password
     * @return the created User entity
     */
    public User registerUser(AdminUserDTO userDTO, String password) {
        // Validate password strength
        if (!isPasswordStrong(password)) {
            throw new WeakPasswordException("Password does not meet security requirements");
        }

        userRepository
            .findOneByLogin(userDTO.getLogin().toLowerCase())
            .ifPresent(existingUser -> {
                boolean removed = removeNonActivatedUser(existingUser);
                if (!removed) {
                    throw new UsernameAlreadyUsedException();
                }
            });
        userRepository
            .findOneByEmailIgnoreCase(userDTO.getEmail())
            .ifPresent(existingUser -> {
                boolean removed = removeNonActivatedUser(existingUser);
                if (!removed) {
                    throw new EmailAlreadyUsedException();
                }
            });
        User newUser = new User();
        String encryptedPassword = passwordEncoder.encode(password);
        newUser.setLogin(userDTO.getLogin().toLowerCase());
        // new user gets initially a generated password
        newUser.setPassword(encryptedPassword);
        newUser.setFirstName(userDTO.getFirstName());
        newUser.setLastName(userDTO.getLastName());
        if (userDTO.getEmail() != null) {
            newUser.setEmail(userDTO.getEmail().toLowerCase());
        }
        newUser.setImageUrl(userDTO.getImageUrl());
        newUser.setLangKey(userDTO.getLangKey());
        // new user is not active
        newUser.setActivated(false);
        // new user gets registration key
        newUser.setActivationKey(RandomUtil.generateActivationKey());
        Set<Authority> authorities = new HashSet<>();
        authorityRepository.findById(AuthoritiesConstants.USER).ifPresent(authorities::add);
        newUser.setAuthorities(authorities);
        userRepository.save(newUser);
        this.clearUserCaches(newUser);
        log.debug("Created Information for User: {}", newUser);
        eventPublisher.publishEvent(new UserEvent(UserEvent.Type.REGISTERED, newUser));
        return newUser;
    }

    private boolean removeNonActivatedUser(User existingUser) {
        if (existingUser.isActivated()) {
            return false;
        }
        userRepository.delete(existingUser);
        userRepository.flush();
        this.clearUserCaches(existingUser);
        return true;
    }

    /**
     * Creates a new user in the system.
     *
     * @param userDTO the user data
     * @return the created User entity
     */
    public User createUser(AdminUserDTO userDTO) {
        User user = new User();
        user.setLogin(userDTO.getLogin().toLowerCase());
        user.setFirstName(userDTO.getFirstName());
        user.setLastName(userDTO.getLastName());
        if (userDTO.getEmail() != null) {
            user.setEmail(userDTO.getEmail().toLowerCase());
        }
        user.setImageUrl(userDTO.getImageUrl());
        if (userDTO.getLangKey() == null) {
            user.setLangKey(Constants.DEFAULT_LANGUAGE); // default language
        } else {
            user.setLangKey(userDTO.getLangKey());
        }

        // Generate a strong password
        String randomPassword = RandomUtil.generatePassword();
        while (!isPasswordStrong(randomPassword)) {
            randomPassword = RandomUtil.generatePassword();
        }

        String encryptedPassword = passwordEncoder.encode(randomPassword);
        user.setPassword(encryptedPassword);
        user.setResetKey(RandomUtil.generateResetKey());
        user.setResetDate(Instant.now());
        user.setActivated(true);
        if (userDTO.getAuthorities() != null) {
            Set<Authority> authorities = userDTO
                .getAuthorities()
                .stream()
                .map(authorityRepository::findById)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(Collectors.toSet());
            user.setAuthorities(authorities);
        }
        userRepository.save(user);
        this.clearUserCaches(user);
        log.debug("Created Information for User: {}", user);
        eventPublisher.publishEvent(new UserEvent(UserEvent.Type.CREATED, user));
        return user;
    }

    /**
     * Update all information for a specific user, and return the modified user.
     *
     * @param userDTO user to update.
     * @return updated user.
     */
    public Optional<AdminUserDTO> updateUser(AdminUserDTO userDTO) {
        return Optional
            .of(userRepository.findById(userDTO.getId()))
            .filter(Optional::isPresent)
            .map(Optional::get)
            .map(user -> {
                this.clearUserCaches(user);
                user.setLogin(userDTO.getLogin().toLowerCase());
                user.setFirstName(userDTO.getFirstName());
                user.setLastName(userDTO.getLastName());
                if (userDTO.getEmail() != null) {
                    user.setEmail(userDTO.getEmail().toLowerCase());
                }
                user.setImageUrl(userDTO.getImageUrl());
                user.setActivated(userDTO.isActivated());
                user.setLangKey(userDTO.getLangKey());
                Set<Authority> managedAuthorities = user.getAuthorities();
                managedAuthorities.clear();
                userDTO
                    .getAuthorities()
                    .stream()
                    .map(authorityRepository::findById)
                    .filter(Optional::isPresent)
                    .map(Optional::get)
                    .forEach(managedAuthorities::add);
                this.clearUserCaches(user);
                log.debug("Changed Information for User: {}", user);
                eventPublisher.publishEvent(new UserEvent(UserEvent.Type.UPDATED, user));
                return user;
            })
            .map(AdminUserDTO::new);
    }

    /**
     * Deletes a user from the system.
     *
     * @param login the login of the user to delete
     */
    public void deleteUser(String login) {
        userRepository
            .findOneByLogin(login)
            .ifPresent(user -> {
                userRepository.delete(user);
                this.clearUserCaches(user);
                failedLoginAttempts.remove(login.toLowerCase());
                lockedAccounts.remove(login.toLowerCase());
                log.debug("Deleted User: {}", user);
                eventPublisher.publishEvent(new UserEvent(UserEvent.Type.DELETED, user));
            });
    }

    /**
     * Update basic information (first name, last name, email, language) for the current user.
     *
     * @param firstName first name of user.
     * @param lastName  last name of user.
     * @param email     email id of user.
     * @param langKey   language key.
     * @param imageUrl  image URL of user.
     */
    public void updateUser(String firstName, String lastName, String email, String langKey, String imageUrl) {
        SecurityUtils
            .getCurrentUserLogin()
            .flatMap(userRepository::findOneByLogin)
            .ifPresent(user -> {
                user.setFirstName(firstName);
                user.setLastName(lastName);
                if (email != null) {
                    user.setEmail(email.toLowerCase());
                }
                user.setLangKey(langKey);
                user.setImageUrl(imageUrl);
                this.clearUserCaches(user);
                log.debug("Changed Information for User: {}", user);
                eventPublisher.publishEvent(new UserEvent(UserEvent.Type.UPDATED, user));
            });
    }

    /**
     * Changes the current user's password.
     *
     * @param currentClearTextPassword the current password
     * @param newPassword the new password
     */
    @Transactional
    public void changePassword(String currentClearTextPassword, String newPassword) {
        // Validate password strength
        if (!isPasswordStrong(newPassword)) {
            throw new WeakPasswordException("Password does not meet security requirements");
        }

        SecurityUtils
            .getCurrentUserLogin()
            .flatMap(userRepository::findOneByLogin)
            .ifPresent(user -> {
                String currentEncryptedPassword = user.getPassword();
                if (!passwordEncoder.matches(currentClearTextPassword, currentEncryptedPassword)) {
                    throw new InvalidPasswordException();
                }
                String encryptedPassword = passwordEncoder.encode(newPassword);
                user.setPassword(encryptedPassword);
                // Reset failed login attempts when password is changed
                failedLoginAttempts.remove(user.getLogin().toLowerCase());
                lockedAccounts.remove(user.getLogin().toLowerCase());
                this.clearUserCaches(user);
                log.debug("Changed password for User: {}", user);
                eventPublisher.publishEvent(new UserEvent(UserEvent.Type.PASSWORD_CHANGED, user));
            });
    }

    /**
     * Gets all managed users.
     *
     * @param pageable the pagination information
     * @return a page of AdminUserDTO
     */
    @Transactional(readOnly = true)
    public Page<AdminUserDTO> getAllManagedUsers(Pageable pageable) {
        return userRepository.findAll(pageable).map(AdminUserDTO::new);
    }

    /**
     * Gets all public users.
     *
     * @param pageable the pagination information
     * @return a page of UserDTO
     */
    @Transactional(readOnly = true)
    public Page<UserDTO> getAllPublicUsers(Pageable pageable) {
        return userRepository.findAllByIdNotNullAndActivatedIsTrue(pageable).map(UserDTO::new);
    }

    /**
     * Gets a user with authorities by login.
     *
     * @param login the login of the user
     * @return an Optional containing the User if found, empty otherwise
     */
    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthoritiesByLogin(String login) {
        return userRepository.findOneWithAuthoritiesByLogin(login);
    }

    /**
     * Gets the currently authenticated user.
     *
     * @return an Optional containing the User if found, empty otherwise
     */
    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities() {
        return SecurityUtils.getCurrentUserLogin().flatMap(userRepository::findOneWithAuthoritiesByLogin);
    }

    /**
     * Not activated users should be automatically deleted after 3 days.
     * <p>
     * This is scheduled to get fired everyday, at 01:00 (am).
     */
    @Scheduled(cron = "0 0 1 * * ?")
    public void removeNotActivatedUsers() {
        userRepository
            .findAllByActivatedIsFalseAndActivationKeyIsNotNullAndCreatedDateBefore(Instant.now().minus(3, ChronoUnit.DAYS))
            .forEach(user -> {
                log.debug("Deleting not activated user {}", user.getLogin());
                userRepository.delete(user);
                this.clearUserCaches(user);
            });
    }

    /**
     * Gets a list of all the authorities.
     * @return a list of all the authorities.
     */
    @Transactional(readOnly = true)
    public List<String> getAuthorities() {
        return authorityRepository.findAll().stream().map(Authority::getName).collect(Collectors.toList());
    }

    /**
     * Records a failed login attempt for the given username.
     * If too many failed attempts are recorded, the account will be locked.
     *
     * @param login the user login
     * @return true if the account is now locked, false otherwise
     */
    public boolean recordFailedLoginAttempt(String login) {
        if (login == null) {
            return false;
        }

        String lowercaseLogin = login.toLowerCase();

        // Check if account is already locked
        if (isAccountLocked(lowercaseLogin)) {
            return true;
        }

        // Increment the failed login attempt counter
        AtomicInteger attempts = failedLoginAttempts.computeIfAbsent(lowercaseLogin, k -> new AtomicInteger(0));
        int currentAttempts = attempts.incrementAndGet();

        // If we've reached the maximum number of attempts, lock the account
        if (currentAttempts >= MAX_FAILED_ATTEMPTS) {
            lockAccount(lowercaseLogin);
            log.warn("Account {} locked due to too many failed login attempts", lowercaseLogin);
            return true;
        }

        return false;
    }

    /**
     * Checks if an account is currently locked.
     *
     * @param login the user login
     * @return true if the account is locked, false otherwise
     */
    public boolean isAccountLocked(String login) {
        if (login == null) {
            return false;
        }

        String lowercaseLogin = login.toLowerCase();
        Instant lockTime = lockedAccounts.get(lowercaseLogin);

        if (lockTime == null) {
            return false;
        }

        // If the lock time has passed, unlock the account
        if (Instant.now().isAfter(lockTime)) {
            unlockAccount(lowercaseLogin);
            return false;
        }

        return true;
    }

    /**
     * Locks an account for a specified duration.
     *
     * @param login the user login to lock
     */
    private void lockAccount(String login) {
        lockedAccounts.put(login, Instant.now().plus(ACCOUNT_LOCKOUT_TIME, ChronoUnit.MINUTES));
    }

    /**
     * Unlocks an account.
     *
     * @param login the user login to unlock
     */
    public void unlockAccount(String login) {
        if (login == null) {
            return;
        }

        String lowercaseLogin = login.toLowerCase();
        lockedAccounts.remove(lowercaseLogin);
        failedLoginAttempts.remove(lowercaseLogin);

        log.debug("Account {} has been unlocked", lowercaseLogin);
    }

    /**
     * Resets the failed login attempts for a user after a successful login.
     *
     * @param login the user login
     */
    public void resetFailedLoginAttempts(String login) {
        if (login == null) {
            return;
        }

        String lowercaseLogin = login.toLowerCase();
        failedLoginAttempts.remove(lowercaseLogin);
    }

    /**
     * Finds users by their first name or last name containing the given search term.
     *
     * @param searchTerm the search term
     * @param pageable the pagination information
     * @return a page of UserDTO
     */
    @Transactional(readOnly = true)
    public Page<UserDTO> searchUsersByName(String searchTerm, Pageable pageable) {
        return userRepository.findByFirstNameContainingIgnoreCaseOrLastNameContainingIgnoreCase(
            searchTerm, searchTerm, pageable).map(UserDTO::new);
    }

    /**
     * Scheduled job that runs every hour to clean up expired account lockouts.
     */
    @Scheduled(fixedRate = 1, timeUnit = TimeUnit.HOURS)
    public void cleanupExpiredLockouts() {
        Instant now = Instant.now();
        lockedAccounts.entrySet().removeIf(entry -> entry.getValue().isBefore(now));
    }

    /**
     * Sends a welcome email to a newly registered user.
     *
     * @param user the user to send the welcome email to
     */
    public void sendWelcomeEmail(@NotNull User user) {
        // Implementation would involve an email service
        log.debug("Sending welcome email to user: {}", user.getEmail());
        // emailService.sendWelcomeEmail(user);
    }

    /**
     * Suspends a user account.
     *
     * @param login the login of the user to suspend
     * @return true if the user was suspended, false if the user was not found
     */
    public boolean suspendUser(String login) {
        return userRepository
            .findOneByLogin(login)
            .map(user -> {
                user.setActivated(false);
                this.clearUserCaches(user);
                log.debug("Suspended User: {}", user);
                eventPublisher.publishEvent(new UserEvent(UserEvent.Type.SUSPENDED, user));
                return true;
            })
            .orElse(false);
    }

    private void clearUserCaches(User user) {
        Objects.requireNonNull(cacheManager.getCache(UserRepository.USERS_BY_LOGIN_CACHE)).evict(user.getLogin());
        if (user.getEmail() != null) {
            Objects.requireNonNull(cacheManager.getCache(UserRepository.USERS_BY_EMAIL_CACHE)).evict(user.getEmail());
        }
    }
}
