<?php
declare(strict_types=1);

namespace wise\oauth\traits;

use wise\oauth\facade\OAuth;
use wise\oauth\model\OAuthUserModel;

/**
 * OAuth 绑定 Trait
 *
 * 使用此 Trait 的用户模型获得 OAuth 绑定/解绑/查询能力。
 *
 * 使用方式：
 * ```php
 * class Admin extends BaseModel
 * {
 *     use \wise\auth\traits\HasRoles;
 *     use \wise\oauth\traits\HasOAuth;
 * }
 * ```
 *
 * 提供的方法：
 * - oauthBindings()          多态一对多关联
 * - getOAuthBindings()       获取所有绑定列表
 * - hasOAuthBinding()        检查是否绑定了某平台
 * - getOAuthBinding()        获取某平台绑定记录
 * - getBoundPlatforms()      获取已绑定的平台列表
 * - getOAuthUserType()       获取多态类型标识
 */
trait HasOAuth
{
    /**
     * OAuth 绑定关联（多态一对多）
     *
     * @return \think\model\relation\MorphMany
     */
    public function oauthBindings()
    {
        // 注意 morphMany() 的签名是 (model, morph, type)：
        //   第 2 参是"多态字段定义"（字段名或 [类型字段, 外键字段]），
        //   第 3 参是"多态类型值"（写入 user_type 的值），必须与
        //   OAuthManager::createBinding() 落库的 $userType 一致（admin / member）。
        // 旧写法把 'user_type' 当类型值传入，会生成
        // `WHERE user_id = ? AND user_type = 'user_type'`，导致绑定查询恒为空。
        return $this->morphMany(
            OAuthUserModel::class,
            ['user_type', 'user_id'],
            $this->getOAuthUserType()
        );
    }

    /**
     * 获取所有 OAuth 绑定列表
     *
     * @return OAuthUserModel[]
     */
    public function getOAuthBindings(): array
    {
        return $this->oauthBindings()->select()->all();
    }

    /**
     * 检查是否绑定了指定平台
     *
     * @param  string $platform 平台标识
     * @return bool
     */
    public function hasOAuthBinding(string $platform): bool
    {
        return $this->oauthBindings()
            ->where('platform', $platform)
            ->find() !== null;
    }

    /**
     * 获取指定平台的 OAuth 绑定记录
     *
     * @param  string $platform 平台标识
     * @return OAuthUserModel|null
     */
    public function getOAuthBinding(string $platform): ?OAuthUserModel
    {
        return $this->oauthBindings()
            ->where('platform', $platform)
            ->find();
    }

    /**
     * 获取所有已绑定的平台标识列表
     *
     * @return string[]
     */
    public function getBoundPlatforms(): array
    {
        return $this->oauthBindings()->column('platform');
    }

    /**
     * 获取 OAuth 绑定的去重计数
     *
     * @return int
     */
    public function getOAuthBindingCount(): int
    {
        return $this->oauthBindings()->count();
    }

    /**
     * 获取用户类型标识（多态必需）
     *
     * 默认从类名推断：Admin → admin, Member → member
     * 若规则不匹配，可在子模型中覆盖此方法。
     *
     * @return string
     */
    public function getOAuthUserType(): string
    {
        $class = get_class($this);
        $parts = explode('\\', $class);
        $className = array_pop($parts);

        // Admin → admin, Member → member, User → user
        return strtolower($className);
    }

    /**
     * 解绑指定平台（便捷方法）
     *
     * @param  string $platform 平台标识
     * @return bool
     *
     * @throws \wise\oauth\exception\OAuthBindingException
     */
    public function unbindOAuth(string $platform): bool
    {
        $binding = $this->getOAuthBinding($platform);

        if (!$binding) {
            return false;
        }

        return OAuth::unbindUser(
            $this->getKey(),
            $this->getOAuthUserType(),
            $platform
        );
    }

    /**
     * 获取脱敏后的绑定信息（用于前端展示）
     *
     * @return array<array{platform: string, platform_name: string, nickname: string, avatar: string, bound_at: string}>
     */
    public function getOAuthBindingsForDisplay(): array
    {
        $bindings = $this->getOAuthBindings();
        $result = [];

        foreach ($bindings as $binding) {
            $platform = $binding->getAttr('platform') ?: '';
            $result[] = [
                'platform'      => $platform,
                'platform_name' => $binding->getPlatformName(),
                'nickname'      => $binding->getAttr('nickname') ?: '',
                'avatar'        => $binding->getAttr('avatar') ?: '',
                'bound_at'      => $binding->getAttr('create_time') ?: '',
            ];
        }

        return $result;
    }
}
