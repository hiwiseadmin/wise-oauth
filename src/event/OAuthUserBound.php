<?php
declare(strict_types=1);

namespace wise\oauth\event;

use think\Model;
use wise\oauth\entity\OAuthUserInfo;
use wise\oauth\model\OAuthUserModel;

/**
 * OAuth 绑定成功事件
 *
 * 当已登录用户新增第三方平台绑定时触发。
 * 监听方可记录操作日志、发送安全提醒等。
 */
class OAuthUserBound
{
    /** @var Model 本地用户 */
    public Model $user;

    /** @var OAuthUserModel 新创建的绑定记录 */
    public OAuthUserModel $binding;

    /** @var OAuthUserInfo OAuth 用户原始信息 */
    public OAuthUserInfo $oauthInfo;

    public function __construct(Model $user, OAuthUserModel $binding, OAuthUserInfo $oauthInfo)
    {
        $this->user      = $user;
        $this->binding   = $binding;
        $this->oauthInfo = $oauthInfo;
    }
}
