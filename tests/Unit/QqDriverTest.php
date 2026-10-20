<?php
declare(strict_types=1);

namespace wise\oauth\tests\Unit;

use wise\oauth\driver\QqDriver;
use wise\oauth\exception\OAuthException;
use wise\oauth\service\HttpClient;
use wise\oauth\tests\TestCase;

/**
 * 假响应队列：按顺序出队，供注入的 HTTP 客户端使用
 */
class ResponseQueue
{
    /** @var array<int, mixed> */
    protected array $items = [];

    public function push(mixed $value): void
    {
        $this->items[] = $value;
    }

    public function shift(mixed $default = []): mixed
    {
        return $this->items === [] ? $default : array_shift($this->items);
    }
}

/**
 * QQ 驱动响应解析单元测试（不发起真实 HTTP）
 *
 * 回归重点：`$userResponse['ret'] ?? -1 !== 0` 这类运算符优先级写法，
 * 以及失败响应缺少 msg 字段时的边界处理。
 */
class QqDriverTest extends TestCase
{
    protected ResponseQueue $queue;

    protected function setUp(): void
    {
        parent::setUp();
        $this->queue = new ResponseQueue();
    }

    /**
     * 构造注入了假 HTTP 客户端的 QQ 驱动
     */
    protected function createDriver(): QqDriver
    {
        $queue = $this->queue;

        $client = new class ($queue) extends HttpClient {
            public function __construct(private ResponseQueue $queue)
            {
            }

            public function get(string $url, array $headers = [], array $query = []): array
            {
                return (array) $this->queue->shift([]);
            }

            public function post(string $url, array $data = [], array $headers = []): array
            {
                return (array) $this->queue->shift([]);
            }

            public function postRaw(string $url, array $data = [], array $headers = []): string
            {
                return (string) $this->queue->shift('');
            }
        };

        return new QqDriver([
            'app_id'       => '100000001',
            'app_secret'   => 'qq_test_secret',
            'redirect_uri' => 'https://example.com/oauth/callback/qq',
        ], $client);
    }

    public function testGetUserParsesProfileOnSuccess(): void
    {
        $driver = $this->createDriver();

        // 1) token 响应（QQ 返回 URL-encoded）
        $this->queue->push('access_token=qq_access_token&expires_in=7776000');
        // 2) openid 响应（JSON）
        $this->queue->push('{"openid":"OPENID_ABC"}');
        // 3) 用户资料：正常返回 ret=0
        $this->queue->push([
            'ret'            => 0,
            'nickname'       => 'QQ用户',
            'gender'         => '男',
            'figureurl_qq_2' => 'https://example.com/avatar.png',
        ]);

        $info = $driver->getUser('auth_code');

        $this->assertSame('qq', $info->platform);
        $this->assertSame('OPENID_ABC', $info->openid);
        $this->assertSame('QQ用户', $info->nickname);
        $this->assertSame('male', $info->gender);
        $this->assertSame('qq_access_token', $info->accessToken);
        $this->assertSame(7776000, $info->expiresIn);
    }

    public function testGetUserThrowsWhenRetIsNotZero(): void
    {
        $driver = $this->createDriver();

        $this->queue->push('access_token=qq_access_token');
        $this->queue->push('{"openid":"OPENID_ABC"}');
        $this->queue->push(['ret' => 100030, 'msg' => '接口调用频率受限']);

        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('接口调用频率受限');

        $driver->getUser('auth_code');
    }

    public function testFailureWithoutMsgKeyFallsBackToDefaultText(): void
    {
        $driver = $this->createDriver();

        $this->queue->push('access_token=qq_access_token');
        $this->queue->push('{"openid":"OPENID_ABC"}');
        // 失败响应缺少 msg 字段：不得触发 "Undefined array key" 警告
        $this->queue->push(['ret' => 100030]);

        try {
            $driver->getUser('auth_code');
            $this->fail('应抛出 OAuthException');
        } catch (OAuthException $e) {
            $this->assertStringContainsString('未知错误', $e->getMessage());
        }
    }

    public function testGetUserThrowsWhenOpenidMissing(): void
    {
        $driver = $this->createDriver();

        $this->queue->push('access_token=qq_access_token');
        $this->queue->push('{"error":1}');

        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('QQ 获取 OpenID 失败');

        $driver->getUser('auth_code');
    }
}
