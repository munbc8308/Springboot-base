package com.spring.lica.domain.repository;

import com.spring.lica.domain.entity.Role;
import com.spring.lica.domain.entity.RoleType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByNameAndType(String name, RoleType type);

    List<Role> findByType(RoleType type);

    boolean existsByNameAndType(String name, RoleType type);
}
