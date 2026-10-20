<?php
declare(strict_types=1);

namespace think\facade;

/**
 * Cache 门面桩 — 基于内存数组
 *
 * 说明：wise-oauth 的 `HttpClient` 在启用断路器时会执行 `Cache::store('redis')`，
 * 缺少本桩时会抛 `ClassNotFoundException: class not exists: cache`。
 * 这里用内存实现替代 Redis，测试无需外部依赖。
 */
class Cache
{
    /** @var array<string, MemoryStore> */
    private static array $stores = [];

    /**
     * 获取（或创建）指定命名空间的内存驱动
     */
    public static function store(?string $name = null): MemoryStore
    {
        $name = $name ?? 'default';

        return self::$stores[$name] ??= new MemoryStore();
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        return self::store()->get($key, $default);
    }

    public static function set(string $key, mixed $value, mixed $ttl = null): bool
    {
        return self::store()->set($key, $value, $ttl);
    }

    public static function has(string $key): bool
    {
        return self::store()->has($key);
    }

    public static function delete(string $key): bool
    {
        return self::store()->delete($key);
    }

    public static function inc(string $key, int $step = 1): int
    {
        return self::store()->inc($key, $step);
    }

    /**
     * 清空全部命名空间（测试隔离用）
     */
    public static function clear(): void
    {
        self::$stores = [];
    }
}

/**
 * 内存缓存驱动替身（支持 CircuitBreaker 所需的 get/set/has/delete/inc）
 */
class MemoryStore
{
    /** @var array<string, mixed> */
    private array $store = [];

    /** @var array<string, int> */
    private array $expires = [];

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->has($key) ? $this->store[$key] : $default;
    }

    public function set(string $key, mixed $value, mixed $ttl = null): bool
    {
        $this->store[$key] = $value;

        if ($ttl !== null && (int) $ttl > 0) {
            $this->expires[$key] = time() + (int) $ttl;
        } else {
            unset($this->expires[$key]);
        }

        return true;
    }

    public function has(string $key): bool
    {
        if (!array_key_exists($key, $this->store)) {
            return false;
        }

        if (isset($this->expires[$key]) && time() > $this->expires[$key]) {
            unset($this->store[$key], $this->expires[$key]);
            return false;
        }

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->store[$key], $this->expires[$key]);

        return true;
    }

    public function inc(string $key, int $step = 1): int
    {
        $value = (int) $this->get($key, 0) + $step;
        $this->store[$key] = $value;

        return $value;
    }

    public function clear(): void
    {
        $this->store = [];
        $this->expires = [];
    }
}
