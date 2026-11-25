<?php
declare(strict_types=1);

namespace wise\oauth\exception;

use wise\support\exception\ErrorCodeInterface;

/**
 * wise-oauth 业务错误码（号段 40000~49999）
 *
 * 号段分配约定（见 wise-support\exception\WiseException 号段全景）：
 *  40000~40099  OAuth 通用错误
 *  40100~40199  绑定/解绑错误
 *  40200~40299  平台驱动错误
 *
 * @package wise\oauth\exception
 */
enum ErrorCode: int implements ErrorCodeInterface
{
    /** OAuth 通用错误 */
    case OAUTH_ERROR      = 40000;

    /** 绑定/解绑失败 */
    case BINDING_ERROR    = 40100;

    /** 平台驱动未找到 */
    case DRIVER_NOT_FOUND = 40200;

    /**
     * 错误码对应的默认中文说明
     */
    public function defaultMessage(): string
    {
        return match ($this) {
            self::OAUTH_ERROR      => 'OAuth 处理失败',
            self::BINDING_ERROR    => 'OAuth 绑定/解绑失败',
            self::DRIVER_NOT_FOUND => 'OAuth 平台驱动未找到',
        };
    }
}
