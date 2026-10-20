<?php
declare(strict_types=1);

namespace wise\oauth\driver;

use wise\oauth\entity\OAuthUserInfo;
use wise\oauth\exception\OAuthException;

/**
 * 钉钉驱动 — 扫码登录
 *
 * 钉钉 OAuth 2.0 流程：
 * 1. 构造授权 URL（使用旧版扫码协议）
 * 2. 通过临时授权码换取用户 token
 * 3. 通过 token 获取用户信息
 *
 * @see https://open.dingtalk.com/document/orgapp/scan-qr-code-to-log-on-to-third-party-websites
 */
class DingtalkDriver extends AbstractDriver
{
    protected string $authBaseUrl  = 'https://login.dingtalk.com/oauth2/auth';
    protected string $tokenUrl     = 'https://api.dingtalk.com/v1.0/oauth2/userAccessToken';
    protected string $userInfoUrl  = 'https://api.dingtalk.com/v1.0/contact/users/me';

    public function getPlatform(): string
    {
        return 'dingtalk';
    }

    public function getPlatformName(): string
    {
        return '钉钉';
    }

    public function getDefaultScopes(): array
    {
        return ['openid', 'corpid'];
    }

    public function getAuthUrl(string $state, ?string $redirectUri = null, ?string $codeChallenge = null, ?string $codeChallengeMethod = null): string
    {
        $query = http_build_query([
            'redirect_uri'  => $this->getRedirectUri($redirectUri),
            'response_type' => 'code',
            'client_id'     => $this->getAppId(),
            'scope'         => implode(' ', $this->config['scopes'] ?? $this->getDefaultScopes()),
            'state'         => $state,
            'prompt'        => 'consent',
        ]);

        return "{$this->authBaseUrl}?{$query}";
    }

    public function getUser(string $code, ?string $state = null, ?string $redirectUri = null, ?string $codeVerifier = null): OAuthUserInfo
    {
        // Step 1: code → access_token
        $tokenResponse = $this->httpPost($this->tokenUrl, [
            'clientId'     => $this->getAppId(),
            'clientSecret' => $this->getAppSecret(),
            'code'         => $code,
            'grantType'    => 'authorization_code',
        ], [
            'Content-Type' => 'application/json',
        ]);

        $accessToken  = $tokenResponse['accessToken'] ?? '';
        $refreshToken = $tokenResponse['refreshToken'] ?? null;
        $expiresIn    = (int) ($tokenResponse['expireIn'] ?? 7200);

        if (empty($accessToken)) {
            $errorMsg = $tokenResponse['message'] ?? $tokenResponse['msg'] ?? '未知错误';
            throw new OAuthException(
                "钉钉获取 Token 失败: {$errorMsg}",
                (int) ($tokenResponse['code'] ?? 0),
                null,
                $this->getPlatform()
            );
        }

        // Step 2: access_token → 用户信息
        $userResponse = $this->httpGet($this->userInfoUrl, [
            'x-acs-dingtalk-access-token' => $accessToken,
        ]);

        if (empty($userResponse['openId'])) {
            $errorMsg = $userResponse['message'] ?? $userResponse['msg'] ?? '未知错误';
            throw new OAuthException(
                "钉钉获取用户信息失败: {$errorMsg}",
                (int) ($userResponse['code'] ?? 0),
                null,
                $this->getPlatform()
            );
        }

        $info = new OAuthUserInfo();
        $info->platform     = $this->getPlatform();
        $info->openid       = $userResponse['openId'] ?? '';
        $info->unionId      = $userResponse['unionId'] ?? null;
        $info->nickname     = $userResponse['nick'] ?? '';
        $info->avatar       = $userResponse['avatarUrl'] ?? '';
        $info->email        = $userResponse['email'] ?? '';
        $info->mobile       = $userResponse['mobile'] ?? '';
        $info->accessToken  = $accessToken;
        $info->refreshToken = $refreshToken;
        $info->expiresIn    = $expiresIn;
        $info->raw          = $userResponse;

        return $info;
    }

    public function refreshToken(string $refreshToken): array
    {
        $response = $this->httpPost($this->tokenUrl, [
            'clientId'     => $this->getAppId(),
            'clientSecret' => $this->getAppSecret(),
            'refreshToken' => $refreshToken,
            'grantType'    => 'refresh_token',
        ], [
            'Content-Type' => 'application/json',
        ]);

        if (empty($response['accessToken'])) {
            throw new OAuthException('钉钉刷新 Token 失败');
        }

        return [
            'access_token'  => $response['accessToken'],
            'refresh_token' => $response['refreshToken'] ?? $refreshToken,
            'expires_in'    => (int) ($response['expireIn'] ?? 7200),
        ];
    }
}
