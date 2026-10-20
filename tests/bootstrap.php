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

// 1. 先加载门面桩：必须在 Composer autoload 之前 require，
//    类一旦定义，Composer 便不会再加载 vendor 中的真实门面，
//    从而避免测试依赖 ThinkPHP 应用容器。
require_once __DIR__ . '/stubs/think/facade/Config.php';
require_once __DIR__ . '/stubs/think/facade/Cache.php';

// 2. 加载项目 Composer autoload（提供 wise\oauth\* 与 wise\support\* 等类）
$autoloadPath = dirname(__DIR__, 4) . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'autoload.php';
if (file_exists($autoloadPath)) {
    require_once $autoloadPath;
}

// 测试命名空间 PSR-4 兜底：wise\oauth\tests\* → tests/
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

// 3. 定义 ThinkPHP 全局 config() 助手桩
//
// 本项目并未通过 Composer 自动加载框架 helper（config / app / runtime_path 均不存在），
// 而 wise-oauth 源码（OAuthTokenEncryptor / OAuthUserResolver）会调用 config()。
// 同时 TestCase::mockConfig() 正是把配置写入 $GLOBALS['__think_config']，
// 这里按该约定读取，并回退到 think\facade\Config 桩。
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
