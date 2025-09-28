package sk8boarding.dog.shadow_the_hedgedog;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class UserAccount implements UserDetails {
  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  protected String username;
  protected String password;
  protected String role;

  protected UserAccount() {}

  public UserAccount(String username, String password, String role) {
    this.username = username;
    this.password = password;
    this.role = role;
  }

  public Collection<? extends GrantedAuthority> getAuthorities() {
    return List.of(new SimpleGrantedAuthority(this.role));
  }

  @Override
  public String getPassword() {
    return this.password;
  }

  @Override
  public String getUsername() {
    return this.username;
  }

  public String getRole() {
    return this.role;
  }

  public String toString() {
    return String.format("User(id = %s, username = %s, password = %s, role = %s)", this.id, this.username, this.password, this.role);
  }

  public void setUsername(String newUsername) {
    this.username = newUsername;
  }

}
