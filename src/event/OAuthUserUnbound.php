<?php
declare(strict_types=1);

namespace wise\oauth\event;

/**
 * OAuth 解绑事件
 *
 * 当用户解绑第三方平台时触发。
 * 注意：解绑后绑定记录已被删除，事件携带 userId / userType / platform 参数。
 * 监听方可记录操作日志、发送安全提醒等。
 */
class OAuthUserUnbound
{
    /** @var int 本地用户 ID */
    public int $userId;

    /** @var string 用户类型 */
    public string $userType;

    /** @var string 被解绑的平台标识 */
    public string $platform;

    public function __construct(int $userId, string $userType, string $platform)
    {
        $this->userId   = $userId;
        $this->userType = $userType;
        $this->platform = $platform;
    }
}
