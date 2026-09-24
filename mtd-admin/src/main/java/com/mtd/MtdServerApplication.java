package com.mtd;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

/**
 * MTD 应用启动入口。
 */
@SpringBootApplication(exclude = { DataSourceAutoConfiguration.class })
public class MtdServerApplication
{
    public static void main(String[] args)
    {
        SpringApplication.run(MtdServerApplication.class, args);
        System.out.println("MTD 挖矿流量检测管理系统启动成功");
    }
}
