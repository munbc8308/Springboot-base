package com.spring.lica.domain.repository;

import com.spring.lica.domain.entity.Group;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface GroupRepository extends JpaRepository<Group, Long> {

    Optional<Group> findByNameAndParentIsNull(String name);

    List<Group> findByParentIsNull();

    List<Group> findByParentId(Long parentId);
}
