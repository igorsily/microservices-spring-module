package dev.igorsily.auth.security;

import dev.igorsily.core.models.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;

public class UserSecurity  implements UserDetails  {

    private String username;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;


    public UserSecurity(User user) {

        this.username = user.getUsername();
        this.password = user.getPassword();
        authorities = user.getRoles().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return  authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
