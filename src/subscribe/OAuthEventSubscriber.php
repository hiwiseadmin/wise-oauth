<?php
declare(strict_types=1);

namespace wise\oauth\subscribe;

use wise\oauth\event\OAuthUserBound;
use wise\oauth\event\OAuthUserLoggedIn;
use wise\oauth\event\OAuthUserRegistered;
use wise\oauth\event\OAuthUserUnbound;

/**
 * OAuth 事件订阅者
 *
 * 业务方可通过 ThinkPHP 事件系统的 listen 配置监听 OAuth 事件：
 *
 * app/event.php:
 *   'listen' => [
 *       \wise\oauth\event\OAuthUserLoggedIn::class => [
 *           \app\listener\OAuthLoginListener::class,
 *       ],
 *   ],
 *
 * 本订阅者提供默认的空实现，作为扩展模板。
 * 已在 OAuthServiceProvider::boot() 中按「完整类名」显式注册（Event::subscribe 的
 * 智能订阅按短类名注册，与 trigger(new XxxEvent()) 的完整类名永远匹配不上）。
 */
class OAuthEventSubscriber
{
    /**
     * OAuth 登录成功
     */
    public function onUserLoggedIn(OAuthUserLoggedIn $event): void
    {
    }

    /**
     * OAuth 新用户注册
     */
    public function onUserRegistered(OAuthUserRegistered $event): void
    {
    }

    /**
     * OAuth 绑定成功
     */
    public function onUserBound(OAuthUserBound $event): void
    {
    }

    /**
     * OAuth 解绑
     */
    public function onUserUnbound(OAuthUserUnbound $event): void
    {
    }
}
