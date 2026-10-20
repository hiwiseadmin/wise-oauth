<?php
declare(strict_types=1);

namespace wise\oauth\facade;

use think\Facade;
use wise\oauth\entity\OAuthUserInfo;
use wise\oauth\model\OAuthUserModel;

/**
 * OAuth 门面
 *
 * 提供静态代理调用 OAuthManager 的便捷方式。
 *
 * 使用示例：
 * ```
 * use wise\oauth\facade\OAuth;
 *
 * $url = OAuth::getAuthUrl('github');
 * $userInfo = OAuth::handleCallback('github', $code, $state);
 * $result = OAuth::loginOrRegister($userInfo, 'admin');
 * OAuth::bindUser($userId, 'admin', $userInfo);
 * OAuth::unbindUser($userId, 'admin', 'github');
 * $bindings = OAuth::getUserBindings($userId, 'admin');
 * ```
 *
 * @method static \wise\oauth\contract\OAuthDriverInterface driver(string $platform)
 * @method static array                                    getEnabledPlatforms()
 * @method static string                                   getAuthUrl(string $platform, ?string $redirectUri = null)
 * @method static OAuthUserInfo                            handleCallback(string $platform, string $code, ?string $state = null, ?string $redirectUri = null)
 * @method static array                                    loginOrRegister(OAuthUserInfo $userInfo, string $userType)
 * @method static OAuthUserModel                           bindUser(int $userId, string $userType, OAuthUserInfo $userInfo)
 * @method static bool                                     unbindUser(int $userId, string $userType, string $platform)
 * @method static OAuthUserModel[]                         getUserBindings(int $userId, string $userType)
 * @method static bool                                     hasBinding(int $userId, string $userType, string $platform)
 *
 * @see \wise\oauth\OAuthManager
 */
class OAuth extends Facade
{
    /**
     * 获取 Facade 对应的实际类
     *
     * @return string
     */
    protected static function getFacadeClass(): string
    {
        return \wise\oauth\OAuthManager::class;
    }
}
