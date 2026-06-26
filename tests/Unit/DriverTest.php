<?php
declare(strict_types=1);

namespace wise\oauth\tests\Unit;

use wise\oauth\driver\GithubDriver;
use wise\oauth\driver\WechatOpenDriver;
use wise\oauth\driver\WechatMpDriver;
use wise\oauth\driver\QqDriver;
use wise\oauth\driver\DingtalkDriver;
use wise\oauth\driver\GiteeDriver;
use wise\oauth\driver\GoogleDriver;
use wise\oauth\driver\WeiboDriver;
use wise\oauth\enums\Platform;
use wise\oauth\tests\TestCase;

/**
 * OAuth 驱动单元测试
 *
 * 测试所有驱动的基本属性（平台标识、显示名称、默认 Scopes）和 URL 构造。
 * 不测试实际的 HTTP 调用（需要真实 token）。
 */
class DriverTest extends TestCase
{
    /**
     * 构建测试用驱动配置
     */
    protected function getTestConfig(string $platform): array
    {
        return [
            'wechat_open' => [
                'app_id'       => 'wx_test_app',
                'app_secret'   => 'wx_test_secret',
                'redirect_uri' => 'https://example.com/oauth/callback/wechat_open',
            ],
            'wechat_mp' => [
                'app_id'       => 'wx_mp_test_app',
                'app_secret'   => 'wx_mp_test_secret',
                'redirect_uri' => 'https://example.com/oauth/callback/wechat_mp',
            ],
            'qq' => [
                'app_id'       => '100000001',
                'app_secret'   => 'qq_test_secret',
                'redirect_uri' => 'https://example.com/oauth/callback/qq',
            ],
            'github' => [
                'client_id'     => 'gh_client_test',
                'client_secret' => 'gh_secret_test',
                'redirect_uri'  => 'https://example.com/oauth/callback/github',
            ],
            'dingtalk' => [
                'app_key'      => 'ding_test_key',
                'app_secret'   => 'ding_test_secret',
                'redirect_uri' => 'https://example.com/oauth/callback/dingtalk',
            ],
            'gitee' => [
                'client_id'     => 'gitee_client_test',
                'client_secret' => 'gitee_secret_test',
                'redirect_uri'  => 'https://example.com/oauth/callback/gitee',
            ],
            'google' => [
                'client_id'     => 'google_client_test',
                'client_secret' => 'google_secret_test',
                'redirect_uri'  => 'https://example.com/oauth/callback/google',
            ],
            'weibo' => [
                'app_key'      => '1234567',
                'app_secret'   => 'weibo_secret_test',
                'redirect_uri' => 'https://example.com/oauth/callback/weibo',
            ],
        ][$platform];
    }

    // ==================== 平台标识测试 ====================

    public function testGithubDriverPlatform(): void
    {
        $driver = new GithubDriver($this->getTestConfig('github'));
        $this->assertEquals('github', $driver->getPlatform());
        $this->assertEquals('GitHub', $driver->getPlatformName());
    }

    public function testWechatOpenDriverPlatform(): void
    {
        $driver = new WechatOpenDriver($this->getTestConfig('wechat_open'));
        $this->assertEquals('wechat_open', $driver->getPlatform());
        $this->assertEquals('微信开放平台', $driver->getPlatformName());
    }

    public function testWechatMpDriverPlatform(): void
    {
        $driver = new WechatMpDriver($this->getTestConfig('wechat_mp'));
        $this->assertEquals('wechat_mp', $driver->getPlatform());
        $this->assertEquals('微信公众号', $driver->getPlatformName());
    }

    public function testQqDriverPlatform(): void
    {
        $driver = new QqDriver($this->getTestConfig('qq'));
        $this->assertEquals('qq', $driver->getPlatform());
        $this->assertEquals('QQ', $driver->getPlatformName());
    }

    public function testDingtalkDriverPlatform(): void
    {
        $driver = new DingtalkDriver($this->getTestConfig('dingtalk'));
        $this->assertEquals('dingtalk', $driver->getPlatform());
        $this->assertEquals('钉钉', $driver->getPlatformName());
    }

    public function testGiteeDriverPlatform(): void
    {
        $driver = new GiteeDriver($this->getTestConfig('gitee'));
        $this->assertEquals('gitee', $driver->getPlatform());
        $this->assertEquals('码云', $driver->getPlatformName());
    }

    public function testGoogleDriverPlatform(): void
    {
        $driver = new GoogleDriver($this->getTestConfig('google'));
        $this->assertEquals('google', $driver->getPlatform());
        $this->assertEquals('Google', $driver->getPlatformName());
    }

    public function testWeiboDriverPlatform(): void
    {
        $driver = new WeiboDriver($this->getTestConfig('weibo'));
        $this->assertEquals('weibo', $driver->getPlatform());
        $this->assertEquals('微博', $driver->getPlatformName());
    }

    // ==================== 默认 Scopes 测试 ====================

    public function testDriversHaveDefaultScopes(): void
    {
        $drivers = [
            new GithubDriver($this->getTestConfig('github')),
            new WechatOpenDriver($this->getTestConfig('wechat_open')),
            new WechatMpDriver($this->getTestConfig('wechat_mp')),
            new QqDriver($this->getTestConfig('qq')),
            new GiteeDriver($this->getTestConfig('gitee')),
            new GoogleDriver($this->getTestConfig('google')),
            new WeiboDriver($this->getTestConfig('weibo')),
        ];

        foreach ($drivers as $driver) {
            $scopes = $driver->getDefaultScopes();
            $this->assertIsArray($scopes, "{$driver->getPlatform()} scopes 应为数组");
            $this->assertNotEmpty($scopes, "{$driver->getPlatform()} scopes 不应为空");
        }
    }

    // ==================== Auth URL 生成测试 ====================

    public function testGithubAuthUrlContainsRequiredParams(): void
    {
        $driver = new GithubDriver($this->getTestConfig('github'));
        $state  = bin2hex(random_bytes(32));
        $url    = $driver->getAuthUrl($state);

        $this->assertStringContainsString('github.com/login/oauth/authorize', $url);
        $this->assertStringContainsString('client_id=gh_client_test', $url);
        $this->assertStringContainsString('state=' . $state, $url);
        $this->assertStringContainsString('scope=user%3Aemail', $url);
    }

    public function testWechatOpenAuthUrlContainsRequiredParams(): void
    {
        $driver = new WechatOpenDriver($this->getTestConfig('wechat_open'));
        $state  = bin2hex(random_bytes(32));
        $url    = $driver->getAuthUrl($state);

        $this->assertStringContainsString('open.weixin.qq.com/connect/qrconnect', $url);
        $this->assertStringContainsString('appid=wx_test_app', $url);
        $this->assertStringContainsString('scope=snsapi_login', $url);
        $this->assertStringContainsString('#wechat_redirect', $url);
    }

    public function testWechatMpAuthUrlContainsRequiredParams(): void
    {
        $driver = new WechatMpDriver($this->getTestConfig('wechat_mp'));
        $state  = bin2hex(random_bytes(32));
        $url    = $driver->getAuthUrl($state);

        $this->assertStringContainsString('open.weixin.qq.com/connect/oauth2/authorize', $url);
        $this->assertStringContainsString('appid=wx_mp_test_app', $url);
        $this->assertStringContainsString('scope=snsapi_userinfo', $url);
        $this->assertStringContainsString('#wechat_redirect', $url);
    }

    public function testQqAuthUrlContainsRequiredParams(): void
    {
        $driver = new QqDriver($this->getTestConfig('qq'));
        $state  = bin2hex(random_bytes(32));
        $url    = $driver->getAuthUrl($state);

        $this->assertStringContainsString('graph.qq.com/oauth2.0/authorize', $url);
        $this->assertStringContainsString('client_id=100000001', $url);
    }

    public function testGoogleAuthUrlContainsRequiredParams(): void
    {
        $driver = new GoogleDriver($this->getTestConfig('google'));
        $state  = bin2hex(random_bytes(32));
        $url    = $driver->getAuthUrl($state);

        $this->assertStringContainsString('accounts.google.com/o/oauth2/v2/auth', $url);
        $this->assertStringContainsString('client_id=google_client_test', $url);
        $this->assertStringContainsString('scope=openid+profile+email', $url);
    }

    // ==================== Token 刷新默认实现 ====================

    public function testDefaultRefreshTokenReturnsEmptyArray(): void
    {
        $drivers = [
            new GithubDriver($this->getTestConfig('github')),
            new WeiboDriver($this->getTestConfig('weibo')),
        ];

        foreach ($drivers as $driver) {
            $result = $driver->refreshToken('some_token');
            $this->assertIsArray($result);
            $this->assertEmpty($result, "{$driver->getPlatform()} 默认刷新应返回空数组");
        }
    }

    // ==================== 枚举一致 ====================

    public function testDriverPlatformsMatchEnumConstants(): void
    {
        $driverMap = [
            WechatOpenDriver::class => Platform::WECHAT_OPEN,
            WechatMpDriver::class   => Platform::WECHAT_MP,
            QqDriver::class         => Platform::QQ,
            GithubDriver::class     => Platform::GITHUB,
            DingtalkDriver::class   => Platform::DINGTALK,
            GiteeDriver::class      => Platform::GITEE,
            GoogleDriver::class     => Platform::GOOGLE,
            WeiboDriver::class      => Platform::WEIBO,
        ];

        foreach ($driverMap as $driverClass => $expectedPlatform) {
            $config = $this->getTestConfig($expectedPlatform);
            $driver = new $driverClass($config);
            $this->assertEquals(
                $expectedPlatform,
                $driver->getPlatform(),
                "{$driverClass} getPlatform() 应与 Platform 枚举一致"
            );
        }
    }
}
