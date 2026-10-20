<?php
declare(strict_types=1);

namespace wise\oauth\enums;

/**
 * OAuth 平台枚举
 *
 * 预定义常见的 OAuth 平台标识，便于 IDE 自动补全和类型约束。
 * 自定义平台直接使用字符串即可，无需修改此枚举。
 */
final class Platform
{
    /** 微信开放平台（扫码登录） */
    public const WECHAT_OPEN = 'wechat_open';

    /** 微信公众平台（网页授权） */
    public const WECHAT_MP = 'wechat_mp';

    /**
     * 微信小游戏（`wx.login` → code2session）
     *
     * 【为什么它不是"驱动型"平台】小游戏的 code2session 由 `wise-wx` 的 `LoginService` 完成
     * （`appid`/`secret` 在 `wise-wx` 配置里），拿到的 openid 会**直接构造 `OAuthUserInfo`**
     * 交给 `OAuthManager::loginOrRegister()` 做「绑定 + 自动注册」。
     * 所以本平台**不需要** `config('wise-oauth.platforms')` 里的 driver 条目
     * （`createBinding()` 不校验平台白名单，`loginOrRegister()` 也不取 driver）。
     */
    public const WECHAT_MINIGAME = 'wechat_minigame';

    /** QQ 互联 */
    public const QQ = 'qq';

    /** GitHub OAuth */
    public const GITHUB = 'github';

    /** 钉钉 */
    public const DINGTALK = 'dingtalk';

    /** 码云 Gitee */
    public const GITEE = 'gitee';

    /** Google OAuth */
    public const GOOGLE = 'google';

    /** 微博 */
    public const WEIBO = 'weibo';

    /**
     * 平台标识 → 显示名称 映射
     *
     * ⚠️ 新增平台常量时**必须**在这里补一行：`isKnown()` 依赖它做校验
     * （`wise-member` 的绑定/解绑接口用它拦非法平台），`label()` 也靠它出中文名。
     *
     * @return array<string, string>
     */
    public static function labels(): array
    {
        return [
            self::WECHAT_OPEN     => '微信开放平台',
            self::WECHAT_MP       => '微信公众号',
            self::WECHAT_MINIGAME => '微信小游戏',
            self::QQ              => 'QQ',
            self::GITHUB          => 'GitHub',
            self::DINGTALK        => '钉钉',
            self::GITEE           => '码云',
            self::GOOGLE          => 'Google',
            self::WEIBO           => '微博',
        ];
    }

    /**
     * 获取平台显示名称
     *
     * @param  string $platform 平台标识
     * @return string
     */
    public static function label(string $platform): string
    {
        return self::labels()[$platform] ?? $platform;
    }

    /**
     * 判断是否为已知平台
     *
     * @param  string $platform
     * @return bool
     */
    public static function isKnown(string $platform): bool
    {
        return isset(self::labels()[$platform]);
    }
}
