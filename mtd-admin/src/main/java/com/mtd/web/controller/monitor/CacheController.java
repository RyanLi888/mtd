package com.mtd.web.controller.monitor;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeSet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.mtd.common.constant.CacheConstants;
import com.mtd.common.core.domain.AjaxResult;
import com.mtd.common.core.redis.RedisCache;
import com.mtd.system.domain.SysCache;

/** 缓存监控。桌面客户端显示内置缓存，服务器部署显示 Redis 缓存。 */
@RestController
@RequestMapping("/monitor/cache")
public class CacheController
{
    @Autowired
    private RedisCache redisCache;

    private final List<SysCache> caches = new ArrayList<>();
    {
        caches.add(new SysCache(CacheConstants.LOGIN_TOKEN_KEY, "用户信息"));
        caches.add(new SysCache(CacheConstants.SYS_CONFIG_KEY, "配置信息"));
        caches.add(new SysCache(CacheConstants.SYS_DICT_KEY, "数据字典"));
        caches.add(new SysCache(CacheConstants.CAPTCHA_CODE_KEY, "验证码"));
        caches.add(new SysCache(CacheConstants.REPEAT_SUBMIT_KEY, "防重提交"));
        caches.add(new SysCache(CacheConstants.RATE_LIMIT_KEY, "限流处理"));
        caches.add(new SysCache(CacheConstants.PWD_ERR_CNT_KEY, "密码错误次数"));
    }

    @PreAuthorize("@ss.hasPermi('monitor:cache:list')")
    @GetMapping()
    public AjaxResult getInfo()
    {
        Properties info = new Properties();
        info.setProperty("redis_version", redisCache.isLocalCache() ? "桌面内置缓存" : "Redis");
        info.setProperty("redis_mode", redisCache.isLocalCache() ? "local" : "standalone");
        info.setProperty("used_memory_human", "由 Java 运行时管理");

        Map<String, Object> result = new HashMap<>(3);
        result.put("info", info);
        result.put("dbSize", redisCache.size());
        result.put("commandStats", new ArrayList<>());
        return AjaxResult.success(result);
    }

    @PreAuthorize("@ss.hasPermi('monitor:cache:list')")
    @GetMapping("/getNames")
    public AjaxResult cache()
    {
        return AjaxResult.success(caches);
    }

    @PreAuthorize("@ss.hasPermi('monitor:cache:list')")
    @GetMapping("/getKeys/{cacheName}")
    public AjaxResult getCacheKeys(@PathVariable String cacheName)
    {
        return AjaxResult.success(new TreeSet<>(redisCache.keys(cacheName + "*")));
    }

    @PreAuthorize("@ss.hasPermi('monitor:cache:list')")
    @GetMapping("/getValue/{cacheName}/{cacheKey}")
    public AjaxResult getCacheValue(@PathVariable String cacheName, @PathVariable String cacheKey)
    {
        Object value = redisCache.getCacheObject(cacheKey);
        return AjaxResult.success(new SysCache(cacheName, cacheKey, String.valueOf(value)));
    }

    @PreAuthorize("@ss.hasPermi('monitor:cache:list')")
    @DeleteMapping("/clearCacheName/{cacheName}")
    public AjaxResult clearCacheName(@PathVariable String cacheName)
    {
        redisCache.deleteObject(redisCache.keys(cacheName + "*"));
        return AjaxResult.success();
    }

    @PreAuthorize("@ss.hasPermi('monitor:cache:list')")
    @DeleteMapping("/clearCacheKey/{cacheKey}")
    public AjaxResult clearCacheKey(@PathVariable String cacheKey)
    {
        redisCache.deleteObject(cacheKey);
        return AjaxResult.success();
    }

    @PreAuthorize("@ss.hasPermi('monitor:cache:list')")
    @DeleteMapping("/clearCacheAll")
    public AjaxResult clearCacheAll()
    {
        Collection<String> keys = redisCache.keys("*");
        redisCache.deleteObject(keys);
        return AjaxResult.success();
    }
}
