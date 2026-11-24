<?php
declare(strict_types=1);

namespace wise\oauth\exception;

use wise\support\circuit\CircuitBreakerExceptionInterface;
use wise\support\exception\GeneralErrorCode;
use wise\support\exception\WiseException;

/**
 * 服务不可用异常（熔断触发）
 *
 * 当 wise-oauth 的断路器处于 OPEN 状态时抛出，表示上游 OAuth 平台
 * 已被熔断保护拦截，短时间内不应继续发起请求。
 *
 * 携带 retry_after 秒数，供上层控制器通过 JsonResponse::circuitResponse()
 * 映射为 HTTP 503 + Retry-After 头。
 *
 * 注：刻意不继承 OAuthException，避免被现有 OAuth 异常处理逻辑误吞。
 *
 * 错误码：GeneralErrorCode::SERVICE_UNAVAILABLE (151)
 * HTTP：503
 */
class ServiceUnavailableException extends WiseException implements CircuitBreakerExceptionInterface
{
    protected int $retryAfter;

    public function __construct(
        string $message = 'OAuth service is temporarily unavailable (circuit breaker open)',
        int $retryAfter = 30,
        string $platform = '',
        ?\Throwable $previous = null
    ) {
        $this->retryAfter = $retryAfter;
        $msg = $platform ? "{$message} [{$platform}]" : $message;
        parent::__construct(
            GeneralErrorCode::SERVICE_UNAVAILABLE->value,
            $msg,
            503,
            $previous,
            ['retry_after' => $retryAfter, 'platform' => $platform],
        );
    }

    public function getRetryAfter(): int
    {
        return $this->retryAfter;
    }
}
