<?php
declare(strict_types=1);

namespace wise\oauth;

use think\facade\Event;
use wise\oauth\config\OAuthSecretCheck;
use wise\oauth\event\OAuthUserBound;
use wise\oauth\event\OAuthUserLoggedIn;
use wise\oauth\event\OAuthUserRegistered;
use wise\oauth\event\OAuthUserUnbound;
use wise\oauth\subscribe\OAuthEventSubscriber;
use wise\support\config\ConfigCheckCollector;
use wise\support\contracts\EnvSeedProvider;
use wise\support\ExtPoint;
use wise\support\ExtPoints;
use wise\support\traits\RegistersMigrations;
use wise\support\traits\ServiceTrait;

/**
 * WiseAdmin OAuth 第三方登录 — ThinkPHP Service 提供者
 *
 * 注册配置、命令和核心服务到容器。
 */
class OAuthServiceProvider extends \think\Service implements EnvSeedProvider
{

    use RegistersMigrations;
    use ServiceTrait;

    /**
     * 声明需要播种到 .env 的 OAuth 第三方客户端凭证
     *
     * 全部为第三方平台申请的 client_id/secret，留空占位由用户填写，
     * 绝不在安装时生成假值。
     */
    public static function envSeeds(): array
    {
        return [
            'DINGTALK_APP_KEY'    => ['type' => 'external', 'default' => '', 'comment' => '钉钉开放平台 AppKey'],
            'DINGTALK_APP_SECRET' => ['type' => 'external', 'default' => '', 'comment' => '钉钉开放平台 AppSecret'],
            'GITEE_CLIENT_ID'     => ['type' => 'external', 'default' => '', 'comment' => 'Gitee Client ID'],
            'GITEE_CLIENT_SECRET' => ['type' => 'external', 'default' => '', 'comment' => 'Gitee Client Secret'],
            'GITHUB_CLIENT_ID'     => ['type' => 'external', 'default' => '', 'comment' => 'GitHub Client ID'],
            'GITHUB_CLIENT_SECRET' => ['type' => 'external', 'default' => '', 'comment' => 'GitHub Client Secret'],
            'GOOGLE_CLIENT_ID'     => ['type' => 'external', 'default' => '', 'comment' => 'Google Client ID'],
            'GOOGLE_CLIENT_SECRET' => ['type' => 'external', 'default' => '', 'comment' => 'Google Client Secret'],
            'QQ_APP_ID'     => ['type' => 'external', 'default' => '', 'comment' => 'QQ 互联 AppId'],
            'QQ_APP_SECRET' => ['type' => 'external', 'default' => '', 'comment' => 'QQ 互联 AppKey'],
            'WECHAT_MP_APP_ID'     => ['type' => 'external', 'default' => '', 'comment' => '微信公众平台 AppId'],
            'WECHAT_MP_APP_SECRET' => ['type' => 'external', 'default' => '', 'comment' => '微信公众平台 AppSecret'],
            'WECHAT_OPEN_APP_ID'     => ['type' => 'external', 'default' => '', 'comment' => '微信开放平台 AppId'],
            'WECHAT_OPEN_APP_SECRET' => ['type' => 'external', 'default' => '', 'comment' => '微信开放平台 AppSecret'],
            'WEIBO_APP_KEY'    => ['type' => 'external', 'default' => '', 'comment' => '微博开放平台 AppKey'],
            'WEIBO_APP_SECRET' => ['type' => 'external', 'default' => '', 'comment' => '微博开放平台 AppSecret'],
        ];
    }

    public function register(): void
    {
        $this->mergeConfig('wise-oauth');

        $this->app->make(ConfigCheckCollector::class)->register(
            new OAuthSecretCheck($this->app->config)
        );

        $this->app->bind(OAuthManager::class, function () {
            return new OAuthManager();
        });

        $this->app->bind(OAuthUserResolver::class, function () {
            return new OAuthUserResolver();
        });

        $this->app->bind(OAuthStateManager::class, function () {
            return new OAuthStateManager();
        });

        $this->app->bind(OAuthTokenEncryptor::class, function () {
            return new OAuthTokenEncryptor();
        });
    }

    /**
     * 启动服务
     */
    public function boot(): void
    {
        $this->registerMigrations();

        Event::listen(OAuthUserLoggedIn::class, [OAuthEventSubscriber::class, 'onUserLoggedIn']);
        Event::listen(OAuthUserRegistered::class, [OAuthEventSubscriber::class, 'onUserRegistered']);
        Event::listen(OAuthUserBound::class, [OAuthEventSubscriber::class, 'onUserBound']);
        Event::listen(OAuthUserUnbound::class, [OAuthEventSubscriber::class, 'onUserUnbound']);

        $this->registerOAuthExtPoints();
    }

    /**
     * 将 wise-oauth.platforms 中的平台驱动注册到连接器体系
     *
     * 取代原 oauth.driver 扩展点：驱动继承 AbstractDriver（实现 OAuthConnectorInterface），
     * 注册到 ExtPoints::EXTERNAL_CONNECTOR（类型 ConnectorType::OAUTH）。
     */
    protected function registerOAuthExtPoints(): void
    {
        $platforms = $this->app->config->get('wise-oauth.platforms', []);
        foreach ($platforms as $name => $config) {
            $driverClass = $config['driver'] ?? null;
            if ($driverClass && class_exists($driverClass)) {
                ExtPoint::register(ExtPoints::EXTERNAL_CONNECTOR, $name, $driverClass);
            }
        }
    }
}
