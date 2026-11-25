<?php
declare(strict_types=1);

namespace think\facade;

/**
 * Config 门面桩 — 基于内存数组，支持点号取值
 *
 * 说明：wise-oauth 的测试不引导 ThinkPHP 应用，而 AbstractDriver 会调用
 * `Config::get('wise-oauth.circuit', [])`。缺少本桩时会抛
 * `ClassNotFoundException: class not exists: config`。
 */
class Config
{
    /** @var array<string, mixed> */
    private static array $items = [];

    public static function get(string $key = '', mixed $default = null): mixed
    {
        if ($key === '') {
            return self::$items;
        }

        $value = self::$items;
        foreach (explode('.', $key) as $segment) {
            if (!is_array($value) || !array_key_exists($segment, $value)) {
                return $default;
            }
            $value = $value[$segment];
        }

        return $value;
    }

    public static function has(string $key): bool
    {
        return self::get($key, '__wise_missing__') !== '__wise_missing__';
    }

    public static function set(string $key, mixed $value = null): void
    {
        $segments = explode('.', $key);

        $ref = &self::$items;
        foreach ($segments as $segment) {
            if (!isset($ref[$segment]) || !is_array($ref[$segment])) {
                $ref[$segment] = [];
            }
            $ref = &$ref[$segment];
        }
        $ref = $value;
    }

    /**
     * 清空配置（测试隔离用）
     */
    public static function reset(): void
    {
        self::$items = [];
    }
}
