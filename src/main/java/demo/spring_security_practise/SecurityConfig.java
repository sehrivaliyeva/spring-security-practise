package demo.spring_security_practise;

import demo.spring_security_practise.jwt.AuthEntryPointJwt;
import demo.spring_security_practise.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
//metod seviyyeleri huquqlari aktivlesdirmek ucun elave etdim
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Autowired
    DataSource dataSource;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeRequests ->
                authorizeRequests.requestMatchers("/h2-console/**").permitAll()
                        .requestMatchers("/signin").permitAll()
                        .anyRequest().authenticated());
        http.sessionManagement(
                session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS)
        );
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));
        //http.httpBasic(withDefaults());
        http.headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions
                        .sameOrigin()
                )
        );
        http.csrf(csrf -> csrf.disable());
        http.addFilterBefore(authenticationJwtTokenFilter(),
                UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService) {
        return args -> {
            JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
            UserDetails user1 = User.withUsername("user1")
                    .password(passwordEncoder().encode("password1"))
                    .roles("USER")
                    .build();
            UserDetails admin = User.withUsername("admin")
                    //.password(passwordEncoder().encode("adminPass"))
                    .password(passwordEncoder().encode("adminPass"))
                    .roles("ADMIN")
                    .build();

            JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
            userDetailsManager.createUser(user1);
            userDetailsManager.createUser(admin);
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }
}

    /*
Tabii, her iki satırı Türkçe veya Azerbaycan dilinde açıklayalım:

1. http.csrf(csrf -> csrf.disable());
Bu satır CSRF (Cross-Site Request Forgery) korumasını devre dışı bırakır.

CSRF nedir?
CSRF, kötü niyetli bir sitenin bir kullanıcının tarayıcısını, kullanıcının haberi olmadan başka bir siteye istenmeyen istekler göndermesi için kandırdığı bir saldırıdır. Örneğin, bir bankacılık sitesinde oturum açmışsanız, başka bir kötü niyetli site sizin adınıza yetkilendirilmiş istekler yapabilir.

Neden devre dışı bırakılır?
Bazı durumlarda (örneğin H2 konsoluna erişirken ya da durumsuz REST API'leri geliştirirken) CSRF korumasına gerek yoktur:

H2 konsolu için, CSRF koruması gereksizdir çünkü konsola tarayıcı üzerinden erişim sağlanır ve genellikle bu tür durumlarda oturum yönetimi yapılmaz.
Stateless (durumsuz) REST API'lerde, her istek kimlik doğrulaması içerdiği için CSRF korumasına ihtiyaç duyulmaz.*/



