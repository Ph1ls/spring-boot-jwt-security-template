package de.phil.jwt.mongodb.repository;

import de.phil.jwt.mongodb.models.ERole;
import de.phil.jwt.mongodb.models.Role;
import java.util.List;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface RoleRepository extends MongoRepository<Role, String> {
  Optional<Role> findByName(ERole name);

  List<Role> findAllByName(List<ERole> roles);
}
