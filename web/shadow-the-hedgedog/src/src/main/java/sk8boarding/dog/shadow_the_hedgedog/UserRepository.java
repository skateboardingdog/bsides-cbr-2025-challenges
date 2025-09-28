package sk8boarding.dog.shadow_the_hedgedog;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<UserAccount, Long> {
    List<UserAccount> findByUsername(String username);
}
