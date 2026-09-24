package com.mtd.framework.aspectj;

import java.lang.reflect.Method;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.mtd.common.annotation.RateLimiter;
import com.mtd.common.core.redis.RedisCache;
import com.mtd.common.enums.LimitType;
import com.mtd.common.exception.ServiceException;
import com.mtd.common.utils.ip.IpUtils;

/** 限流处理，桌面模式和服务器模式共用统一缓存入口。 */
@Aspect
@Component
public class RateLimiterAspect
{
    private static final Logger log = LoggerFactory.getLogger(RateLimiterAspect.class);

    @Autowired
    private RedisCache redisCache;

    @Before("@annotation(rateLimiter)")
    public void doBefore(JoinPoint point, RateLimiter rateLimiter)
    {
        String combineKey = getCombineKey(rateLimiter, point);
        long number = redisCache.increment(combineKey, rateLimiter.time());
        if (number > rateLimiter.count())
        {
            throw new ServiceException("访问过于频繁，请稍候再试");
        }
        log.info("限制请求'{}',当前请求'{}',缓存key'{}'", rateLimiter.count(), number, combineKey);
    }

    public String getCombineKey(RateLimiter rateLimiter, JoinPoint point)
    {
        StringBuilder key = new StringBuilder(rateLimiter.key());
        if (rateLimiter.limitType() == LimitType.IP) key.append(IpUtils.getIpAddr()).append("-");
        Method method = ((MethodSignature) point.getSignature()).getMethod();
        return key.append(method.getDeclaringClass().getName()).append("-").append(method.getName()).toString();
    }
}
