package com.hersystem;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

/**
 * 第三方子系统（模拟）
 *
 * 职责：
 *  1. 注册到门户侧 Eureka（8761），供服务发现
 *  2. 接收门户 SSO 跳转（URL 携带 ?ticket=xxx）
 *  3. 用「共享 JWT 密钥」本地验签 ticket（方式A，不回调门户）
 *  4. 验签通过后签发本系统自己的会话 token，页面展示用户信息
 *  5. 提供独立账号登录（模拟未走 SSO 时直接登录本系统）
 */
@SpringBootApplication
@EnableDiscoveryClient
public class HerSubsystemApplication {
    public static void main(String[] args) {
        SpringApplication.run(HerSubsystemApplication.class, args);
    }
}
