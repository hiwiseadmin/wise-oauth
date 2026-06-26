<?php
/**
 * PHPUnit 引导文件
 *
 * 自动加载 Composer autoload（从项目根目录），
 * 为 wise-oauth 测试环境做准备。
 */

// 查找项目根目录（向上4级：tests → Unit → oauth → wise-oauth → packages → wiseadmin → packages → src）
$projectRoot = dirname(__DIR__, 5);

// 加载项目 Composer autoload
$autoloadPath = $projectRoot . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'autoload.php';
if (file_exists($autoloadPath)) {
    require_once $autoloadPath;
}

// 包自身的 autoload
$packageAutoload = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'autoload.php';
if (file_exists($packageAutoload)) {
    require_once $packageAutoload;
}
