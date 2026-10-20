<?php
declare(strict_types=1);

namespace wise\oauth\model;

use think\Model;
use wise\oauth\OAuthTokenEncryptor;
use wise\oauth\enums\Platform;

/**
 * OAuth 用户绑定模型
 *
 * 对应 oauth_users 表，采用多态关联模式（user_type + user_id）。
 * 支持 Admin 和 Member 两种用户体系。
 *
 * 约束：
 * - uk_user_platform：同一用户在同一平台只能绑定一次
 * - uk_platform_openid：一个 OAuth 账号只能绑定到一个本地用户
 *
 * @property int    $id
 * @property string $user_type        用户类型
 * @property int    $user_id          本地用户ID
 * @property string $platform         平台标识
 * @property string $openid           平台用户唯一标识
 * @property string $union_id         跨应用统一ID
 * @property string $nickname         第三方昵称
 * @property string $avatar           第三方头像URL
 * @property string $email            第三方邮箱
 * @property string $mobile           第三方手机号
 * @property string $raw_data         原始响应数据JSON
 * @property string $access_token     访问令牌（加密）
 * @property string $refresh_token    刷新令牌（加密）
 * @property string $token_expires_at Token过期时间
 * @property string $last_login_at    最后登录时间
 * @property string $last_login_ip    最后登录IP
 * @property string $create_time       创建时间
 * @property string $update_time       更新时间
 */
class OAuthUserModel extends Model
{
    /** @var string 表名（框架自动添加 ws_ 前缀） */
    protected $name = 'oauth_users';

    /** @var bool 自动时间戳 */
    protected $autoWriteTimestamp = true;

    /** @var string 创建时间字段 */
    protected $createTime = 'create_time';

    /** @var string 更新时间字段 */
    protected $updateTime = 'update_time';

    /** @var string[] JSON 类型字段 */
    protected $json = ['raw_data'];

    /** @var string[] 隐藏字段（toArray 时排除） */
    protected $hidden = ['access_token', 'refresh_token', 'raw_data'];

    /**
     * 获取解密后的 Access Token
     *
     * @return string
     */
    public function getDecryptedAccessToken(): string
    {
        $encryptor = app(OAuthTokenEncryptor::class);
        return $encryptor->decryptIfEnabled($this->getAttr('access_token') ?: '');
    }

    /**
     * 获取解密后的 Refresh Token
     *
     * @return string
     */
    public function getDecryptedRefreshToken(): string
    {
        $encryptor = app(OAuthTokenEncryptor::class);
        return $encryptor->decryptIfEnabled($this->getAttr('refresh_token') ?: '');
    }

    /**
     * 多态用户关联
     *
     * 根据 user_type 动态关联到 Admin 或 Member 模型。
     * 使用 MorphTo 多态关联。
     *
     * @return \think\model\relation\MorphTo
     */
    public function user()
    {
        // 过滤掉"提供该模型的包未安装"的映射：morphTo 一旦命中缺失的类会直接致命错误。
        // 配置里的 `::class` 只是字符串常量（不触发自动加载），故必须在这里做存在性校验。
        $map = array_filter([
            'admin'  => config('wise-oauth.user_models.admin', \app\admin\model\Admin::class),
            'member' => config('wise-oauth.user_models.member', \wise\member\model\Member::class),
        ], static fn ($class): bool => is_string($class) && $class !== '' && class_exists($class));

        return $this->morphTo('user', $map, 'user_type', 'user_id');
    }

    /**
     * 判断 Access Token 是否已过期
     *
     * @return bool true 表示已过期
     */
    public function isTokenExpired(): bool
    {
        $expiresAt = $this->getAttr('token_expires_at');
        if (empty($expiresAt)) {
            return false; // 无过期时间视为永不过期
        }
        return strtotime($expiresAt) < time();
    }

    /**
     * 获取平台显示名称
     *
     * @return string
     */
    public function getPlatformName(): string
    {
        return Platform::label($this->getAttr('platform') ?: '');
    }
}
