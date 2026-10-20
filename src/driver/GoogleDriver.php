<?php
declare(strict_types=1);

namespace wise\oauth\driver;

use wise\oauth\entity\OAuthUserInfo;
use wise\oauth\exception\OAuthException;

/**
 * Google OAuth 2.0 驱动
 *
 * 基于 OpenID Connect 协议。
 * Token URL 返回 JSON，用户信息通过 userinfo endpoint 获取。
 * ID Token 中的 sub 字段即为用户唯一标识。
 *
 * @see https://developers.google.com/identity/openid-connect/openid-connect
 */
class GoogleDriver extends AbstractDriver
{
    protected string $authBaseUrl  = 'https://accounts.google.com/o/oauth2/v2/auth';
    protected string $tokenUrl     = 'https://oauth2.googleapis.com/token';
    protected string $userInfoUrl  = 'https://openidconnect.googleapis.com/v1/userinfo';

    public function getPlatform(): string
    {
        return 'google';
    }

    public function getPlatformName(): string
    {
        return 'Google';
    }

    public function getDefaultScopes(): array
    {
        return ['openid', 'profile', 'email'];
    }

    public function getAuthUrl(string $state, ?string $redirectUri = null, ?string $codeChallenge = null, ?string $codeChallengeMethod = null): string
    {
        $query = http_build_query([
            'client_id'     => $this->getAppId(),
            'redirect_uri'  => $this->getRedirectUri($redirectUri),
            'response_type' => 'code',
            'scope'         => implode(' ', $this->config['scopes'] ?? $this->getDefaultScopes()),
            'state'         => $state,
            'access_type'   => 'offline',
            'prompt'        => 'consent',
        ]);

        return "{$this->authBaseUrl}?{$query}";
    }

    public function getUser(string $code, ?string $state = null, ?string $redirectUri = null, ?string $codeVerifier = null): OAuthUserInfo
    {
        // Step 1: code → access_token + id_token
        $tokenResponse = $this->httpPost($this->tokenUrl, [
            'client_id'     => $this->getAppId(),
            'client_secret' => $this->getAppSecret(),
            'code'          => $code,
            'grant_type'    => 'authorization_code',
            'redirect_uri'  => $this->getRedirectUri($redirectUri),
        ]);

        if (!empty($tokenResponse['error'])) {
            throw new OAuthException(
                "Google 获取 Token 失败：{$tokenResponse['error_description']}",
                0,
                null,
                $this->getPlatform()
            );
        }

        $accessToken  = $tokenResponse['access_token'] ?? '';
        $refreshToken = $tokenResponse['refresh_token'] ?? null;
        $expiresIn    = (int) ($tokenResponse['expires_in'] ?? 3600);

        if (empty($accessToken)) {
            throw new OAuthException('Google 返回的 Token 数据不完整');
        }

        // Step 2: access_token → 用户信息
        $userResponse = $this->httpGet($this->userInfoUrl, [
            'Authorization' => "Bearer {$accessToken}",
        ]);

        if (empty($userResponse['sub'])) {
            throw new OAuthException('Google 获取用户信息失败');
        }

        $info = new OAuthUserInfo();
        $info->platform     = $this->getPlatform();
        $info->openid       = $userResponse['sub'] ?? '';
        $info->nickname     = $userResponse['name'] ?? '';
        $info->avatar       = $userResponse['picture'] ?? '';
        $info->email        = $userResponse['email'] ?? '';
        $info->gender       = $userResponse['gender'] ?? null;
        $info->accessToken  = $accessToken;
        $info->refreshToken = $refreshToken;
        $info->expiresIn    = $expiresIn;
        $info->raw          = $userResponse;

        return $info;
    }

    public function refreshToken(string $refreshToken): array
    {
        $response = $this->httpPost($this->tokenUrl, [
            'client_id'     => $this->getAppId(),
            'client_secret' => $this->getAppSecret(),
            'refresh_token' => $refreshToken,
            'grant_type'    => 'refresh_token',
        ]);

        if (!empty($response['error'])) {
            throw new OAuthException("Google 刷新 Token 失败：{$response['error_description']}");
        }

        return [
            'access_token'  => $response['access_token'] ?? '',
            'expires_in'    => (int) ($response['expires_in'] ?? 3600),
        ];
    }
}
