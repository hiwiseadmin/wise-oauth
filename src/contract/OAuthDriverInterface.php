<?php
declare(strict_types=1);

namespace wise\oauth\contract;

use wise\oauth\entity\OAuthUserInfo;
use wise\oauth\exception\OAuthException;

/**
 * OAuth 驱动接口
 *
 * 所有第三方登录平台驱动必须实现此接口。
 * 实现类需在配置文件的 platforms.{key}.driver 中注册。
 *
 * 设计要点：
 * - getAuthUrl() 生成授权跳转 URL
 * - getUser() 通过授权码换取用户信息，返回标准化的 OAuthUserInfo
 * - refreshToken() 用于延长 token 有效期（非所有平台支持）
 * - getPlatform() / getDefaultScopes() 提供平台元信息
 */
interface OAuthDriverInterface
{
    /**
     * 获取平台标识
     *
     * @return string 如 'wechat_open', 'github', 'qq'
     */
    public function getPlatform(): string;

    /**
     * 获取平台显示名称
     *
     * @return string 如 '微信开放平台', 'GitHub'
     */
    public function getPlatformName(): string;

    /**
     * 获取授权跳转 URL
     *
     * @param  string      $state              CSRF 防跨站令牌（必填）
     * @param  string|null $redirectUri        回调地址（null 则用配置默认值）
     * @param  string|null $codeChallenge      PKCE code_challenge（null 则不启用 PKCE）
     * @param  string|null $codeChallengeMethod PKCE 变换方法（通常为 S256）
     * @return string      完整的 OAuth 授权页面 URL
     */
    public function getAuthUrl(string $state, ?string $redirectUri = null, ?string $codeChallenge = null, ?string $codeChallengeMethod = null): string;

    /**
     * 通过授权码获取用户信息
     *
     * 标准流程：code → access_token → 用户信息 API
     *
     * @param  string      $code          授权码
     * @param  string|null $state         CSRF 令牌（用于回传校验，非所有平台支持）
     * @param  string|null $redirectUri   回调地址（必须与获取 code 时一致）
     * @param  string|null $codeVerifier  PKCE code_verifier（null 则不启用 PKCE）
     * @return OAuthUserInfo              标准化的用户信息对象
     *
     * @throws OAuthException 获取失败时抛出
     */
    public function getUser(string $code, ?string $state = null, ?string $redirectUri = null, ?string $codeVerifier = null): OAuthUserInfo;

    /**
     * 刷新 Access Token
     *
     * 对于 token 有过期时间的平台，通过 refresh_token 换取新的 access_token。
     * 对于 token 永不过期的平台（如 GitHub），返回空数组。
     *
     * @param  string $refreshToken 当前的 refresh_token
     * @return array  新的 token 信息：
     *                ['access_token' => '...', 'refresh_token' => '...', 'expires_in' => 7200]
     *
     * @throws OAuthException
     */
    public function refreshToken(string $refreshToken): array;

    /**
     * 获取驱动的默认 Scopes
     *
     * @return string[] 授权范围列表
     */
    public function getDefaultScopes(): array;
}
