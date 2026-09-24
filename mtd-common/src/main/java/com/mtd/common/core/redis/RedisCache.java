package com.mtd.common.core.redis;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.BoundSetOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

/**
 * 统一缓存入口。服务器部署使用 Redis，Windows 客户端使用进程内缓存。
 */
@SuppressWarnings(value = { "unchecked", "rawtypes" })
@Component
public class RedisCache
{
    @Autowired(required = false)
    private RedisTemplate redisTemplate;

    @Value("${mtd.local-cache:false}")
    private boolean localCache;

    private final Map<String, LocalValue> values = new ConcurrentHashMap<>();

    public <T> void setCacheObject(final String key, final T value)
    {
        if (localCache)
        {
            values.put(key, new LocalValue(value, 0));
            return;
        }
        template().opsForValue().set(key, value);
    }

    public <T> void setCacheObject(final String key, final T value, final Integer timeout, final TimeUnit timeUnit)
    {
        if (localCache)
        {
            values.put(key, new LocalValue(value, expiresAt(timeout, timeUnit)));
            return;
        }
        template().opsForValue().set(key, value, timeout, timeUnit);
    }

    public boolean expire(final String key, final long timeout)
    {
        return expire(key, timeout, TimeUnit.SECONDS);
    }

    public boolean expire(final String key, final long timeout, final TimeUnit unit)
    {
        if (localCache)
        {
            LocalValue current = liveValue(key);
            if (current == null) return false;
            values.put(key, new LocalValue(current.value, expiresAt(timeout, unit)));
            return true;
        }
        return Boolean.TRUE.equals(template().expire(key, timeout, unit));
    }

    public long getExpire(final String key)
    {
        if (localCache)
        {
            LocalValue current = liveValue(key);
            if (current == null) return -2;
            if (current.expiresAt == 0) return -1;
            return Math.max(0, TimeUnit.MILLISECONDS.toSeconds(current.expiresAt - System.currentTimeMillis()));
        }
        Long seconds = template().getExpire(key);
        return seconds == null ? -2 : seconds;
    }

    public Boolean hasKey(String key)
    {
        return localCache ? liveValue(key) != null : template().hasKey(key);
    }

    public <T> T getCacheObject(final String key)
    {
        if (localCache)
        {
            LocalValue current = liveValue(key);
            return current == null ? null : (T) current.value;
        }
        return (T) template().opsForValue().get(key);
    }

    public boolean deleteObject(final String key)
    {
        return localCache ? values.remove(key) != null : Boolean.TRUE.equals(template().delete(key));
    }

    public boolean deleteObject(final Collection collection)
    {
        if (localCache)
        {
            boolean removed = false;
            for (Object key : collection) removed |= values.remove(String.valueOf(key)) != null;
            return removed;
        }
        Long count = template().delete(collection);
        return count != null && count > 0;
    }

    public <T> long setCacheList(final String key, final List<T> dataList)
    {
        if (localCache)
        {
            values.put(key, new LocalValue(new ArrayList<>(dataList), 0));
            return dataList.size();
        }
        Long count = template().opsForList().rightPushAll(key, dataList);
        return count == null ? 0 : count;
    }

    public <T> List<T> getCacheList(final String key)
    {
        if (localCache)
        {
            List<T> list = getCacheObject(key);
            return list == null ? Collections.emptyList() : list;
        }
        return template().opsForList().range(key, 0, -1);
    }

    public <T> BoundSetOperations<String, T> setCacheSet(final String key, final Set<T> dataSet)
    {
        if (localCache)
        {
            values.put(key, new LocalValue(new HashSet<>(dataSet), 0));
            return null;
        }
        BoundSetOperations<String, T> operation = template().boundSetOps(key);
        dataSet.forEach(operation::add);
        return operation;
    }

    public <T> Set<T> getCacheSet(final String key)
    {
        if (localCache)
        {
            Set<T> set = getCacheObject(key);
            return set == null ? Collections.emptySet() : set;
        }
        return template().opsForSet().members(key);
    }

    public <T> void setCacheMap(final String key, final Map<String, T> dataMap)
    {
        if (dataMap == null) return;
        if (localCache)
        {
            values.put(key, new LocalValue(new ConcurrentHashMap<>(dataMap), 0));
            return;
        }
        template().opsForHash().putAll(key, dataMap);
    }

    public <T> Map<String, T> getCacheMap(final String key)
    {
        if (localCache)
        {
            Map<String, T> map = getCacheObject(key);
            return map == null ? Collections.emptyMap() : map;
        }
        return template().opsForHash().entries(key);
    }

    public <T> void setCacheMapValue(final String key, final String hKey, final T value)
    {
        if (localCache)
        {
            Map<String, T> map = new ConcurrentHashMap<>(getCacheMap(key));
            map.put(hKey, value);
            values.put(key, new LocalValue(map, 0));
            return;
        }
        template().opsForHash().put(key, hKey, value);
    }

    public <T> T getCacheMapValue(final String key, final String hKey)
    {
        if (localCache)
        {
            Map<String, T> map = getCacheMap(key);
            return map.get(hKey);
        }
        return (T) template().opsForHash().get(key, hKey);
    }

    public <T> List<T> getMultiCacheMapValue(final String key, final Collection<Object> hKeys)
    {
        if (!localCache) return template().opsForHash().multiGet(key, hKeys);
        Map<String, T> map = getCacheMap(key);
        return hKeys.stream().map(item -> map.get(String.valueOf(item))).collect(Collectors.toList());
    }

    public boolean deleteCacheMapValue(final String key, final String hKey)
    {
        if (!localCache) return template().opsForHash().delete(key, hKey) > 0;
        Map<String, Object> map = new LinkedHashMap<>(getCacheMap(key));
        boolean removed = map.remove(hKey) != null;
        values.put(key, new LocalValue(map, 0));
        return removed;
    }

    public Collection<String> keys(final String pattern)
    {
        if (!localCache) return template().keys(pattern);
        cleanupExpired();
        if ("*".equals(pattern)) return new HashSet<>(values.keySet());
        if (pattern.endsWith("*"))
        {
            String prefix = pattern.substring(0, pattern.length() - 1);
            return values.keySet().stream().filter(key -> key.startsWith(prefix)).collect(Collectors.toSet());
        }
        return values.containsKey(pattern) ? Collections.singleton(pattern) : Collections.emptySet();
    }

    public long increment(final String key, final int timeoutSeconds)
    {
        if (!localCache)
        {
            Long value = template().opsForValue().increment(key);
            if (value != null && value == 1) template().expire(key, timeoutSeconds, TimeUnit.SECONDS);
            return value == null ? 0 : value;
        }
        synchronized (values)
        {
            LocalValue current = liveValue(key);
            long number = current == null ? 1 : ((Number) current.value).longValue() + 1;
            long expires = current == null ? expiresAt(timeoutSeconds, TimeUnit.SECONDS) : current.expiresAt;
            values.put(key, new LocalValue(new AtomicLong(number).longValue(), expires));
            return number;
        }
    }

    public boolean isLocalCache()
    {
        return localCache;
    }

    public long size()
    {
        return keys("*").size();
    }

    private RedisTemplate template()
    {
        if (redisTemplate == null) throw new IllegalStateException("RedisTemplate 未配置");
        return redisTemplate;
    }

    private LocalValue liveValue(String key)
    {
        LocalValue value = values.get(key);
        if (value != null && value.expiresAt > 0 && value.expiresAt <= System.currentTimeMillis())
        {
            values.remove(key, value);
            return null;
        }
        return value;
    }

    private void cleanupExpired()
    {
        new ArrayList<>(values.keySet()).forEach(this::liveValue);
    }

    private long expiresAt(long timeout, TimeUnit unit)
    {
        return System.currentTimeMillis() + unit.toMillis(timeout);
    }

    private static final class LocalValue
    {
        private final Object value;
        private final long expiresAt;

        private LocalValue(Object value, long expiresAt)
        {
            this.value = value;
            this.expiresAt = expiresAt;
        }
    }
}
