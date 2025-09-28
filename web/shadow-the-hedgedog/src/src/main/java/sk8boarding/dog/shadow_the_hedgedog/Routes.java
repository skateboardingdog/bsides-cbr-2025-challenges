package sk8boarding.dog.shadow_the_hedgedog;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Controller
public class Routes {
    @Autowired private JwtUtil jwtUtil;
    @Autowired private UserService userService;
    @Autowired private PasswordEncoder passwordEncoder;

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    protected void setJwtCookie(HttpServletResponse response, String username, String role) {
        String token = jwtUtil.generateToken(username, role);
        Cookie cookie = new Cookie("shadow", token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);
    }

    protected void unsetJwtCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("shadow", "");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(0);
        cookie.setPath("/");
        response.addCookie(cookie);
    }

    @PostMapping("/login")
    public String doLogin(@RequestParam String username,
                          @RequestParam String password,
                          HttpServletResponse response,
                          Model model
    ) {
        try {
            UserAccount user = (UserAccount) userService.loadUserByUsername(username);
            if (passwordEncoder.matches(password, user.getPassword())) {
                setJwtCookie(response, username, user.getRole());
                return "redirect:/home";
            }
        } catch (UsernameNotFoundException e) {
        }

        model.addAttribute("error", "Invalid username/password");
        return "login";
    }

    @GetMapping("/signup")
    public String signup() {
        return "signup";
    }

    @PostMapping("/signup")
    public String doSignup(@RequestParam String username,
                           @RequestParam String password,
                           Model model
    ) {
        try {
            userService.loadUserByUsername(username);
            model.addAttribute("error", "Username taken");
            return "signup";
        } catch (UsernameNotFoundException e) {

        }

        if (password.length() < 8 || !password.chars().anyMatch(Character::isDigit)) {
            model.addAttribute("error", "Password must be at least 8 characters and contain a digit");
            return "signup";
        }

        String encoded = passwordEncoder.encode(password);
        UserAccount user = new UserAccount(username, encoded, "ROLE_USER");
        userService.saveUser(user);

        return "redirect:/login";
    }

    @PostMapping("/create-admin")
    @PreAuthorize("hasRole('ADMIN') || hasRole('USER')")
    public String createAdmin(RedirectAttributes redirectAttrs) {
        String username = UUID.randomUUID().toString();
        String password = UUID.randomUUID().toString();

        try {
            userService.loadUserByUsername(username);
            redirectAttrs.addAttribute("error", "Username taken");
            return "redirect:/";
        } catch (UsernameNotFoundException e) {
        }

        String encoded = passwordEncoder.encode(password);
        UserAccount admin = new UserAccount(username, encoded, "ROLE_ADMIN");
        userService.saveUser(admin);
        redirectAttrs.addFlashAttribute("message", String.format("Admin '%s' created", username));
        return "redirect:/home";
    }

    @GetMapping(path = "/home")
    @PreAuthorize("hasRole('ADMIN') || hasRole('USER')")
    public String home(Model model) {
        UserAccount user = (UserAccount) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        model.addAttribute("username", user.getUsername());
        model.addAttribute("isAdmin", user.getAuthorities().stream()
                           .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN")));
        return "home";
    }

    @PostMapping(path = "/change-username")
    @PreAuthorize("hasRole('ADMIN') || hasRole('USER')")
    public String changeUsername(@RequestParam String newUsername,
                                 RedirectAttributes redirectAttrs,
                                 HttpServletResponse response
    ) {
        UserAccount user = (UserAccount) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        user.setUsername(newUsername);
        userService.saveUser(user);
        redirectAttrs.addFlashAttribute("message", "Username successfully changed. Please log in again.");
        unsetJwtCookie(response);
        return "redirect:/login";
    }

    @GetMapping(path = "/flag")
    @PreAuthorize("hasRole('ADMIN')")
    public String flag(Model model) {
        String flag = System.getenv("FLAG");
        model.addAttribute("flag", flag);
        return "flag";
    }

    @GetMapping("/error")
    public String handleError(HttpServletRequest request, Model model) {
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        Object message = request.getAttribute(RequestDispatcher.ERROR_MESSAGE);
        model.addAttribute("status", status);
        model.addAttribute("message", message);
        return "error";
    }
}
