package de.phil.jwt.mongodb.security.jwt;

import de.phil.jwt.mongodb.security.services.UserDetailsServiceImpl;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

public class AuthTokenFilter extends OncePerRequestFilter {

  private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);
  @Autowired
  private JwtUtils jwtUtils;
  @Autowired
  private UserDetailsServiceImpl userDetailsService;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
    throws ServletException, IOException {
    String token = parseJwtTokenFromRequest(request);
    if (jwtUtils.isJwtTokenValid(token)) {
      UserDetails userDetails = getUser(token);
      setSecurityContext(request, userDetails);
    }

    filterChain.doFilter(request, response);
  }

  private void setSecurityContext(final HttpServletRequest request, final UserDetails userDetails) {
    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null,
      userDetails.getAuthorities());
    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

    SecurityContextHolder.getContext().setAuthentication(authentication);
  }

  private UserDetails getUser(final String jwt) {
    String username = jwtUtils.getUserNameFromJwtToken(jwt);

    return userDetailsService.loadUserByUsername(username);
  }

  private String parseJwtTokenFromRequest(HttpServletRequest request) {
    String headerAuth = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
      // TODO da die laenge des tokens bekannt ist sollte das hier auch als limit stehen + ggf das format checken
      return headerAuth.substring(7, headerAuth.length());
    }

    return null;
  }
}
