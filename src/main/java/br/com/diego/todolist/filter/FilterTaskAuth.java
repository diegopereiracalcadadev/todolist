package br.com.diego.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.diego.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        var servletPath = request.getServletPath();
        if (servletPath.equals("/tasks/")) {

            // Recover Authorization Info
            var authorization = request.getHeader("Authorization");
            System.out.println("Authorization");
            System.out.println(authorization);

            // Decoding and splitting credentials
            var encodedAuth = authorization.substring("Basic".length()).trim();
            System.out.println("encodedAuth");
            System.out.println(encodedAuth);
            byte[] decodedAuth = Base64.getDecoder().decode(encodedAuth);
            System.out.println("decodedAuth");
            System.out.println(decodedAuth);

            var authString = new String(decodedAuth);
            System.out.println("authString");
            System.out.println(authString);

            String[] credentials = authString.split(":");

            String username = credentials[0];
            System.out.println("username");
            System.out.println(username);

            String password = credentials[1];
            System.out.println("password");
            System.out.println(password);

            // Validating
            var user = this.userRepository.findByUsername(username);
            if (user == null) {
                response.sendError(401);
            } else {
                var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                if (passwordVerify.verified) {
                    request.setAttribute("userId", user.getId());
                    filterChain.doFilter(request, response);
                } else {
                    response.sendError(401);
                }
            }
        } else {
            filterChain.doFilter(request, response);

        }

    }

}
