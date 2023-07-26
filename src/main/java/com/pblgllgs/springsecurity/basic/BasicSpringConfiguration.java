package com.pblgllgs.springsecurity.basic;

//@Configuration
public class BasicSpringConfiguration {

//    @Bean
//    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests(auth -> {
//            auth.anyRequest().authenticated();
//        });
//        http.httpBasic(withDefaults());
//        http.csrf().disable();
//        http.headers().frameOptions().sameOrigin();
//        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//        return http.build();
//    }
//
//    @Bean
//    public DataSource dataSource() {
//        return new EmbeddedDatabaseBuilder()
//                .setType(EmbeddedDatabaseType.H2)
//                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
//                .build();
//    }
//
//    @Bean
//    public UserDetailsService userDetailsService(DataSource dataSource) {
//
//        var user = User.withUsername("username")
//                .password("password")
//                .passwordEncoder(pass -> passwordEncoder().encode(pass))
//                .roles("USER")
//                .build();
//        var admin = User.withUsername("admin")
//                .password("password")
//                .passwordEncoder(pass -> passwordEncoder().encode(pass))
//                .roles("USER", "ADMIN")
//                .build();
//
//        var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
//
//        jdbcUserDetailsManager.createUser(user);
//        jdbcUserDetailsManager.createUser(admin);
//
//        return jdbcUserDetailsManager;
//    }
//
//    @Bean
//    public BCryptPasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }

}
