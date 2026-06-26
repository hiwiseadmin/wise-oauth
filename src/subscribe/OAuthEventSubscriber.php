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
 */
class OAuthEventSubscriber
{
    /**
     * OAuth 登录成功
     */
    public function onUserLoggedIn(OAuthUserLoggedIn $event): void
    {
        // 默认无操作。业务方可监听此事件记录登录日志、发送通知等。
    }

    /**
     * OAuth 新用户注册
     */
    public function onUserRegistered(OAuthUserRegistered $event): void
    {
        // 默认无操作。业务方可监听此事件发送欢迎通知、初始化设置等。
    }

    /**
     * OAuth 绑定成功
     */
    public function onUserBound(OAuthUserBound $event): void
    {
        // 默认无操作。业务方可监听此事件记录操作日志、发送安全提醒等。
    }

    /**
     * OAuth 解绑
     */
    public function onUserUnbound(OAuthUserUnbound $event): void
    {
        // 默认无操作。业务方可监听此事件记录操作日志、发送安全提醒等。
    }
}
