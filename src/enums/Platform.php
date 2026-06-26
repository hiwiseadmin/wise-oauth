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
     * @return array<string, string>
     */
    public static function labels(): array
    {
        return [
            self::WECHAT_OPEN => '微信开放平台',
            self::WECHAT_MP   => '微信公众号',
            self::QQ          => 'QQ',
            self::GITHUB      => 'GitHub',
            self::DINGTALK    => '钉钉',
            self::GITEE       => '码云',
            self::GOOGLE      => 'Google',
            self::WEIBO       => '微博',
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
