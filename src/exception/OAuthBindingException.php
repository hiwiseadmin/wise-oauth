<?php
declare(strict_types=1);

namespace wise\oauth\exception;

/**
 * OAuth 绑定异常
 *
 * 绑定/解绑操作失败时抛出，例如：
 * - 该平台已绑定
 * - 该第三方账号已被其他用户绑定
 * - 解绑后将无法登录
 */
class OAuthBindingException extends OAuthException
{
    public function __construct(string $message = '', int $code = 0, ?\Throwable $previous = null, ?string $platform = null)
    {
        parent::__construct($message, $code, $previous, $platform);
    }
}
