<?php
declare(strict_types=1);

namespace wise\oauth\tests;

use PHPUnit\Framework\TestCase as PHPUnitTestCase;

/**
 * wise-oauth 测试基类
 *
 * 提供模拟 ThinkPHP Facade 的辅助方法。
 */
abstract class TestCase extends PHPUnitTestCase
{
    /**
     * Mock ThinkPHP config() 函数
     *
     * @param array $config
     */
    protected function mockConfig(array $config): void
    {
        $GLOBALS['__think_config'] = array_merge(
            $GLOBALS['__think_config'] ?? [],
            $config
        );
    }

    protected function setUp(): void
    {
        parent::setUp();
        $GLOBALS['__think_config'] = [];
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        $GLOBALS['__think_config'] = [];
    }
}
