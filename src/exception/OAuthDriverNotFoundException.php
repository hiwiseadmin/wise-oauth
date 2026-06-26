<?php
declare(strict_types=1);

namespace wise\oauth\exception;

/**
 * OAuth 驱动未找到异常
 *
 * 在配置文件中未找到对应平台的驱动时抛出。
 */
class OAuthDriverNotFoundException extends OAuthException
{
    public function __construct(string $platform, int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct(
            "未找到 OAuth 平台驱动：{$platform}，请检查 wise-oauth 配置中的 platforms 节点",
            $code,
            $previous,
            $platform
        );
    }
}
