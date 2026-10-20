<?php
declare(strict_types=1);

namespace wise\oauth\exception;

use wise\support\exception\WiseException;

/**
 * OAuth 基础异常
 *
 * 所有 OAuth 相关异常的基类。
 * 捕获此异常等同于捕获所有 OAuth 异常。
 *
 * 错误码：ErrorCode::OAUTH_ERROR (40000)
 * HTTP：400
 */
class OAuthException extends WiseException
{
    /** @var string|null 平台标识 */
    public ?string $platform = null;

    /**
     * @param string          $message  异常消息
     * @param int             $code     业务错误码（传 0 时回退到 ErrorCode::OAUTH_ERROR，
     *                                  兼容旧代码 `new OAuthException($msg, 0, ...)` 的约定）
     * @param \Throwable|null $previous 前一异常
     * @param string|null     $platform 平台标识
     * @param array           $context  附加上下文
     * @param int             $httpCode HTTP 状态码（默认 400）
     */
    public function __construct(
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null,
        ?string $platform = null,
        array $context = [],
        int $httpCode = 400,
    ) {
        $code = $code ?: ErrorCode::OAUTH_ERROR->value;
        parent::__construct($code, $message, $httpCode, $previous, $context);
        $this->platform = $platform;
    }
}
