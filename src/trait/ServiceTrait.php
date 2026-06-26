<?php
declare(strict_types=1);

namespace wise\oauth\trait;

use think\facade\Config;

/**
 * WiseAdmin 包 Service 提供者共用 Trait
 *
 * 将包内 config/{configName}.php 的默认配置与宿主应用的配置进行递归合并，
 * 宿主应用配置优先。合并后通过 Config::set() 写入全局。
 */
trait ServiceTrait
{
    /**
     * 合并包默认配置到全局配置
     *
     * @param string $configName 配置名（不含 .php 后缀）
     * @return array<int|string, mixed> 合并后的配置
     */
    protected function mergeConfig(string $configName): array
    {
        $defaultConfig = $this->loadPackageDefaultConfig($configName);
        if ($defaultConfig === null) {
            return [];
        }

        $appConfig = Config::get($configName, []);
        $mergedConfig = $this->arrayMergeRecursive($defaultConfig, $appConfig);
        Config::set($mergedConfig, $configName);
        return $mergedConfig;
    }

    /**
     * 递归合并数组（override 优先于 base）
     *
     * 与 array_merge_recursive() 不同，本方法在遇到同名 key 时用 override 值覆盖 base 值，
     * 而不是将两者合并为嵌套数组。这使得宿主配置可以完全覆盖默认配置的任意层级。
     *
     * @param array<int|string, mixed> $base     默认配置（被覆盖方）
     * @param array<int|string, mixed> $override 覆盖配置（优先方）
     * @return array<int|string, mixed> 合并后的配置
     */
    protected function arrayMergeRecursive(array $base, array $override): array
    {
        $result = $base;

        foreach ($override as $key => $value) {
            if (is_int($key)) {
                $result[] = $value;
            } elseif (is_array($value) && isset($result[$key]) && is_array($result[$key])) {
                $result[$key] = $this->arrayMergeRecursive($result[$key], $value);
            } else {
                $result[$key] = $value;
            }
        }

        return $result;
    }

    /**
     * 加载包默认配置文件
     *
     * @param string $configName 配置名（不含 .php 后缀）
     * @return array|null 配置数组，文件不存在时返回 null
     */
    protected function loadPackageDefaultConfig(string $configName): ?array
    {
        $filePath = $this->getPackageConfigFilePath($configName);

        if (!file_exists($filePath)) {
            return null;
        }

        return require $filePath;
    }

    /**
     * 获取包内配置文件的绝对路径
     *
     * @param string $configName 配置名（不含 .php 后缀）
     * @return string 配置文件绝对路径
     */
    protected function getPackageConfigFilePath(string $configName): string
    {
        return dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . $configName . '.php';
    }
}
