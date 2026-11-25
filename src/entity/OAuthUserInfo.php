<?php
declare(strict_types=1);

namespace wise\oauth\entity;

/**
 * OAuth 用户信息 — 标准化值对象
 *
 * 各平台驱动将原始 OAuth 响应转换为该对象，供 OAuthUserResolver 使用。
 * 字段与 oauth_users 表一一对应，确保可以无缝落库。
 */
class OAuthUserInfo
{
    /** @var string 平台标识 */
    public string $platform = '';

    /** @var string 平台用户唯一标识（必须） */
    public string $openid = '';

    /** @var string|null 跨应用统一 ID（如微信 UnionID） */
    public ?string $unionId = null;

    /** @var string|null 昵称 */
    public ?string $nickname = null;

    /** @var string|null 头像 URL */
    public ?string $avatar = null;

    /** @var string|null 邮箱 */
    public ?string $email = null;

    /** @var string|null 手机号 */
    public ?string $mobile = null;

    /** @var string|null 性别（male / female） */
    public ?string $gender = null;

    /** @var string 访问令牌 */
    public string $accessToken = '';

    /** @var string|null 刷新令牌 */
    public ?string $refreshToken = null;

    /** @var int|null Token 有效期（秒） */
    public ?int $expiresIn = null;

    /** @var array 原始响应数据（JSON 序列化存储） */
    public array $raw = [];

    /**
     * 转为数组（用于落库）
     *
     * @return array
     */
    public function toArray(): array
    {
        return [
            'platform'      => $this->platform,
            'openid'        => $this->openid,
            'union_id'      => $this->unionId,
            'nickname'      => $this->nickname,
            'avatar'        => $this->avatar,
            'email'         => $this->email,
            'mobile'        => $this->mobile,
            'gender'        => $this->gender,
            'access_token'  => $this->accessToken,
            'refresh_token' => $this->refreshToken,
            'expires_in'    => $this->expiresIn,
            'raw'           => $this->raw,
        ];
    }

    /**
     * 从数组创建实例
     *
     * @param  array $data
     * @return static
     */
    public static function fromArray(array $data): self
    {
        $info = new self();
        $info->platform     = $data['platform'] ?? '';
        $info->openid       = $data['openid'] ?? '';
        $info->unionId      = $data['union_id'] ?? null;
        $info->nickname     = $data['nickname'] ?? null;
        $info->avatar       = $data['avatar'] ?? null;
        $info->email        = $data['email'] ?? null;
        $info->mobile       = $data['mobile'] ?? null;
        $info->gender       = $data['gender'] ?? null;
        $info->accessToken  = $data['access_token'] ?? '';
        $info->refreshToken = $data['refresh_token'] ?? null;
        $info->expiresIn    = $data['expires_in'] ?? null;
        $info->raw          = $data['raw'] ?? [];
        return $info;
    }
}
