package com.spring.lica.security.auth;

import com.spring.lica.domain.entity.Role;
import com.spring.lica.domain.entity.User;
import com.spring.lica.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service("ssoUserDetailsService")
@RequiredArgsConstructor
public class SsoUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findWithRolesAndGroupsByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        Set<Role> allRoles = new HashSet<>(user.getRoles());
        user.getGroups().forEach(group -> allRoles.addAll(group.getRoles()));

        var authorities = allRoles.stream()
            .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName().toUpperCase()))
            .collect(Collectors.toSet());

        return new SsoUserPrincipal(user, authorities);
    }
}
