<?php
declare(strict_types=1);

namespace wise\oauth\exception;

/**
 * OAuth 驱动未找到异常
 *
 * 在配置文件中未找到对应平台的驱动时抛出。
 *
 * 错误码：ErrorCode::DRIVER_NOT_FOUND (40200)
 * HTTP：404
 */
class OAuthDriverNotFoundException extends OAuthException
{
    public function __construct(string $platform, int $code = ErrorCode::DRIVER_NOT_FOUND->value, ?\Throwable $previous = null)
    {
        // 驱动未找到属于资源不存在，HTTP 状态码 404
        parent::__construct(
            "未找到 OAuth 平台驱动：{$platform}，请检查 wise-oauth 配置中的 platforms 节点",
            $code,
            $previous,
            $platform,
            [],
            404,
        );
    }
}
