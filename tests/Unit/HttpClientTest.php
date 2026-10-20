<?php
declare(strict_types=1);

namespace wise\oauth\tests\Unit;

use wise\oauth\service\HttpClient;
use wise\oauth\tests\TestCase;

/**
 * HttpClient 断路器初始化单元测试
 *
 * 回归重点：断路器不得硬绑定 Redis —— 未指定 store 时应回退到应用默认缓存，
 * 配置关闭熔断时不得构造断路器（避免无缓存环境整体不可用）。
 */
class HttpClientTest extends TestCase
{
    /**
     * 读取受保护的 breaker 属性
     */
    protected function readBreaker(HttpClient $client): mixed
    {
        $property = new \ReflectionProperty(HttpClient::class, 'breaker');
        $property->setAccessible(true);

        return $property->getValue($client);
    }

    public function testBreakerIsDisabledByConfig(): void
    {
        $client = new HttpClient([
            'breaker_service' => 'github',
            'breaker_config'  => ['enabled' => false],
        ]);

        $this->assertNull(
            $this->readBreaker($client),
            'enabled=false 时不应构造断路器'
        );
    }

    public function testBreakerFallsBackToDefaultCacheStore(): void
    {
        // 未指定 store：应使用应用默认缓存（而非硬编码 redis）
        $client = new HttpClient(['breaker_service' => 'qq']);

        $this->assertNotNull(
            $this->readBreaker($client),
            '未指定 store 时应回退到应用默认缓存并成功构造断路器'
        );
    }

    public function testBreakerUsesConfiguredStore(): void
    {
        $client = new HttpClient([
            'breaker_service' => 'github',
            'breaker_config'  => ['store' => 'shared_file'],
        ]);

        $this->assertNotNull(
            $this->readBreaker($client),
            '显式指定 store 时应成功构造断路器'
        );
    }

    public function testNoBreakerWithoutServiceName(): void
    {
        $client = new HttpClient([]);

        $this->assertNull($this->readBreaker($client));
    }
}
