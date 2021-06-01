package com.ecw.rcm.configure;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;

@Configuration
public class DBConfigure {

    @Autowired
    Environment env;

    @Bean
    public DataSource customDataSource() {

        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName(env.getProperty("database1.datasource.driverClassName"));
        dataSource.setUrl(env.getProperty("database1.datasource.url"));
        dataSource.setUsername(env.getProperty("database1.datasource.username"));
        dataSource.setPassword(env.getProperty("database1.datasource.password"));

        return dataSource;

    }


}
