<?php
declare(strict_types=1);

namespace wise\oauth\exception;

/**
 * OAuth 基础异常
 *
 * 所有 OAuth 相关异常的基类。
 * 捕获此异常等同于捕获所有 OAuth 异常。
 */
class OAuthException extends \RuntimeException
{
    /** @var string|null 平台标识 */
    public ?string $platform = null;

    /** @var array 附加上下文 */
    public array $context = [];

    /**
     * @param string          $message  异常消息
     * @param int             $code     错误码
     * @param \Throwable|null $previous 前一异常
     * @param string|null     $platform 平台标识
     * @param array           $context  附加上下文
     */
    public function __construct(
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null,
        ?string $platform = null,
        array $context = []
    ) {
        parent::__construct($message, $code, $previous);
        $this->platform = $platform;
        $this->context = $context;
    }
}
