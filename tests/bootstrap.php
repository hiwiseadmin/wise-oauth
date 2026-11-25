<?php
/**
 * PHPUnit 引导文件
 *
 * 加载项目 Composer autoload，并注册测试命名空间的 PSR-4 兜底映射。
 *
 * 注意两点：
 *  1. 项目 autoload 位于 `<项目根>/src/vendor/autoload.php`，
 *     即从本文件向上 4 级（tests → wise-oauth → wiseadmin → packages → src）；
 *  2. 包的 `autoload-dev` 不会随 path 仓库进入项目 vendor/autoload，
 *     因此 `wise\oauth\tests\*` 必须在此显式注册，否则会报
 *     "Class wise\oauth\tests\TestCase not found"。
 */

require_once __DIR__ . '/stubs/think/facade/Config.php';
require_once __DIR__ . '/stubs/think/facade/Cache.php';

$autoloadPath = dirname(__DIR__, 4) . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'autoload.php';
if (file_exists($autoloadPath)) {
    require_once $autoloadPath;
}

spl_autoload_register(static function (string $class): void {
    $prefix = 'wise\\oauth\\tests\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $file = __DIR__ . DIRECTORY_SEPARATOR
        . str_replace('\\', DIRECTORY_SEPARATOR, substr($class, strlen($prefix))) . '.php';

    if (file_exists($file)) {
        require_once $file;
    }
});

if (!function_exists('config')) {
    /**
     * ThinkPHP config() 助手桩（支持点号取值）
     */
    function config(string $key = '', mixed $default = null): mixed
    {
        $missing = '__wise_config_missing__';
        $items   = $GLOBALS['__think_config'] ?? [];

        if ($key === '') {
            return $items !== [] ? $items : \think\facade\Config::get();
        }

        $value = $items;
        foreach (explode('.', $key) as $segment) {
            if (!is_array($value) || !array_key_exists($segment, $value)) {
                $value = $missing;
                break;
            }
            $value = $value[$segment];
        }

        return $value === $missing
            ? \think\facade\Config::get($key, $default)
            : $value;
    }
}
