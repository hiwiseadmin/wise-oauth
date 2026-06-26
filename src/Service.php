<?php
declare(strict_types=1);

namespace wise\oauth;

use think\facade\Event;
use wise\oauth\command\Publish;
use wise\oauth\trait\ServiceTrait;
use wise\oauth\subscribe\OAuthEventSubscriber;

/**
 * WiseAdmin OAuth 第三方登录 — ThinkPHP Service 提供者
 *
 * 注册配置、命令和核心服务到容器。
 */
class Service extends \think\Service
{
    use ServiceTrait;

    /**
     * 注册服务
     */
    public function register(): void
    {
        // 合并默认配置
        $this->mergeConfig('wise-oauth');

        // 绑定核心编排器（单例）
        $this->app->bind(OAuthManager::class, function () {
            return new OAuthManager();
        });

        // 绑定用户解析器（单例）
        $this->app->bind(OAuthUserResolver::class, function () {
            return new OAuthUserResolver();
        });

        // 绑定 State 管理器（单例）
        $this->app->bind(OAuthStateManager::class, function () {
            return new OAuthStateManager();
        });

        // 绑定 Token 加密器（单例）
        $this->app->bind(OAuthTokenEncryptor::class, function () {
            return new OAuthTokenEncryptor();
        });

        // 注册命令
        if ($this->app->runningInConsole()) {
            $this->commands([
                Publish::class,
            ]);
        }
    }

    /**
     * 启动服务
     */
    public function boot(): void
    {
        // 注册 OAuth 事件订阅者（自动处理登录/绑定/解绑等事件）
        Event::subscribe(OAuthEventSubscriber::class);
    }
}
