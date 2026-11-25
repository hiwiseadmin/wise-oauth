<?php
declare(strict_types=1);

namespace wise\oauth\event;

use think\Model;
use wise\oauth\entity\OAuthUserInfo;
use wise\oauth\model\OAuthUserModel;

/**
 * OAuth 新用户注册事件
 *
 * 当 OAuth 用户无法匹配到本地用户，触发自动注册创建新账号时触发。
 * 监听方可发送欢迎通知、初始化默认设置等。
 */
class OAuthUserRegistered
{
    /** @var Model 新创建的本地用户 */
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
