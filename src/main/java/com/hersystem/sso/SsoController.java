package com.hersystem.sso;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * 子系统自己的 SSO 验证逻辑（方式A：共享密钥本地验签，不回调门户）
 *
 * 流程：
 *  门户跳转 http://<ip>:8003/?ticket=xxx
 *   → 页面 JS 调 POST /api/sso/login?ticket=xxx
 *   → 本后端用「门户共享密钥」验签 JWT ticket：
 *       - 签名是否有效（共享密钥）
 *       - ticketType == "SSO"
 *       - targetApp == 本系统应用编码（防止 A 的票被 B 使用）
 *       - 是否在有效期内（JWT exp 自动校验）
 *   → 验签通过：签发本系统自己的会话 token 返回给页面
 */
@Slf4j
@RestController
@RequestMapping("/api")
public class SsoController {

    /** 门户(consumer-service)共享出来的 JWT 签名密钥 —— 与门户 application.yml 的 jwt.secret 完全一致 */
    @Value("${sso.portal-secret}")
    private String portalSecret;

    /** 本系统在门户登记的应用编码，须与门户 portal.subsystems[].code 一致 */
    @Value("${sso.app-code}")
    private String appCode;

    /** 本系统自己的会话密钥（与门户无关，仅本系统使用） */
    @Value("${sso.session-secret}")
    private String sessionSecret;

    /** 本系统会话有效期（毫秒），默认 2 小时 */
    @Value("${sso.session-expire:7200000}")
    private long sessionExpire;

    /** 门户地址（退出后跳回） */
    @Value("${sso.portal-url}")
    private String portalUrl;

    private volatile JWTVerifier portalVerifier;

    /** 惰性构建门户票据验签器 */
    private JWTVerifier portalVerifier() {
        if (portalVerifier == null) {
            synchronized (this) {
                if (portalVerifier == null) {
                    portalVerifier = JWT.require(Algorithm.HMAC256(portalSecret)).build();
                }
            }
        }
        return portalVerifier;
    }

    /**
     * SSO 登录：用门户跳转带来的 ticket 换取本系统会话
     * 页面地址栏 ?ticket=xxx → JS 调用本接口
     */
    @PostMapping("/sso/login")
    public Map<String, Object> ssoLogin(@RequestParam("ticket") String ticket) {
        Map<String, Object> resp = new HashMap<>();
        try {
            // 1. 共享密钥本地验签（含有效期校验）
            DecodedJWT jwt = portalVerifier().verify(ticket);

            // 2. 票据类型校验：必须是 SSO 票据，防止拿登录 token 冒充
            if (!"SSO".equals(jwt.getClaim("ticketType").asString())) {
                return fail("票据类型错误：不是 SSO 票据");
            }

            // 3. 目标应用校验：ticket 必须是签给本系统的，防止 A 系统的票被 B 系统使用
            String targetApp = jwt.getClaim("targetApp").asString();
            if (!appCode.equals(targetApp)) {
                return fail("票据目标应用不匹配：ticket 签发给 [" + targetApp + "]，本系统为 [" + appCode + "]");
            }

            // 4. 取出门户带来的用户信息
            Long userId = jwt.getClaim("userId").asLong();
            String username = jwt.getClaim("username").asString();
            String realName = jwt.getClaim("realName").isNull() ? username : jwt.getClaim("realName").asString();

            // 5. 签发本系统自己的会话 token
            String token = JWT.create()
                    .withClaim("authType", "SSO")
                    .withClaim("userId", userId)
                    .withClaim("username", username)
                    .withClaim("realName", realName)
                    .withIssuedAt(new Date())
                    .withExpiresAt(new Date(System.currentTimeMillis() + sessionExpire))
                    .sign(Algorithm.HMAC256(sessionSecret));

            log.info("[SSO] 门户用户 {}({}) 通过 SSO 票据登录本系统", username, userId);

            resp.put("code", 200);
            resp.put("message", "SSO 登录成功");
            Map<String, Object> data = new HashMap<>();
            data.put("token", token);
            data.put("userId", userId);
            data.put("username", username);
            data.put("realName", realName);
            data.put("authType", "SSO");
            data.put("loginTime", new Date().toString());
            resp.put("result", data);
            return resp;
        } catch (com.auth0.jwt.exceptions.TokenExpiredException e) {
            log.warn("[SSO] 票据已过期");
            return fail("SSO 票据已过期，请从门户重新进入");
        } catch (Exception e) {
            log.warn("[SSO] 票据验签失败: {}", e.getMessage());
            return fail("SSO 票据无效（验签失败）");
        }
    }

    /**
     * 本系统独立登录（模拟不走 SSO 时直接登录）
     * 模拟账号：heradmin / 123456
     */
    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");
        if (!"heradmin".equals(username) || !"123456".equals(password)) {
            return fail("用户名或密码错误（模拟账号：heradmin / 123456）");
        }
        String token = JWT.create()
                .withClaim("authType", "LOCAL")
                .withClaim("userId", 90001L)
                .withClaim("username", username)
                .withClaim("realName", "子系统本地账号")
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + sessionExpire))
                .sign(Algorithm.HMAC256(sessionSecret));

        Map<String, Object> resp = new HashMap<>();
        resp.put("code", 200);
        resp.put("message", "登录成功");
        Map<String, Object> data = new HashMap<>();
        data.put("token", token);
        data.put("userId", 90001L);
        data.put("username", username);
        data.put("realName", "子系统本地账号");
        data.put("authType", "LOCAL");
        data.put("loginTime", new Date().toString());
        resp.put("result", data);
        return resp;
    }

    /**
     * 当前会话信息（页面加载时校验本地 token 是否有效）
     */
    @GetMapping("/me")
    public Map<String, Object> me(@RequestHeader(value = "Authorization", required = false) String auth) {
        try {
            if (auth == null || !auth.startsWith("Bearer ")) {
                return fail("未登录");
            }
            DecodedJWT jwt = JWT.require(Algorithm.HMAC256(sessionSecret)).build().verify(auth.substring(7));
            Map<String, Object> resp = new HashMap<>();
            resp.put("code", 200);
            Map<String, Object> data = new HashMap<>();
            data.put("userId", jwt.getClaim("userId").asLong());
            data.put("username", jwt.getClaim("username").asString());
            data.put("realName", jwt.getClaim("realName").asString());
            data.put("authType", jwt.getClaim("authType").asString());
            resp.put("result", data);
            return resp;
        } catch (Exception e) {
            return fail("会话无效或已过期");
        }
    }

    /**
     * 退出登录（清本系统会话），由前端调用后再跳回门户
     */
    @PostMapping("/sso/logout")
    public Map<String, Object> ssoLogout() {
        Map<String, Object> resp = new HashMap<>();
        resp.put("code", 200);
        resp.put("message", "已退出本系统会话");
        Map<String, Object> data = new HashMap<>();
        data.put("portalUrl", portalUrl);   // 告诉前端退出后跳回哪里
        resp.put("result", data);
        return resp;
    }

    private Map<String, Object> fail(String msg) {
        Map<String, Object> resp = new HashMap<>();
        resp.put("code", 500);
        resp.put("message", msg);
        return resp;
    }
}
