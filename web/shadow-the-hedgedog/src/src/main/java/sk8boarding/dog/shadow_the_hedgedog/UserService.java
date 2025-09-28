package sk8boarding.dog.shadow_the_hedgedog;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService {
    @Autowired UserRepository users;

	@Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<UserAccount> user = users.findByUsername(username);
        if (user.isEmpty()) {
             throw new UsernameNotFoundException("User not found");
        }
        return user.get(0);
    }

    public void saveUser(UserAccount user) {
        users.save(user);
    }

    // 30 minutes
    @Scheduled(fixedRate = 30 * 60 * 1000)
    public void cleanup() {
        users.deleteAll();
    }

}
