<?php
declare(strict_types=1);

namespace wise\oauth\event;

use think\Model;
use wise\oauth\entity\OAuthUserInfo;
use wise\oauth\model\OAuthUserModel;

/**
 * OAuth 登录成功事件
 *
 * 当用户通过 OAuth 登录成功（包括已有绑定登录和新注册后登录）时触发。
 * 监听方可记录登录日志、发送欢迎通知等。
 */
class OAuthUserLoggedIn
{
    /** @var Model 本地用户模型实例 */
    public Model $user;

    /** @var OAuthUserModel OAuth 绑定记录 */
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
