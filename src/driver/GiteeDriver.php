<?php
declare(strict_types=1);

namespace wise\oauth\driver;

use wise\oauth\entity\OAuthUserInfo;
use wise\oauth\exception\OAuthException;

/**
 * 码云 Gitee 驱动
 *
 * 标准 OAuth 2.0 authorization_code 流程，与 GitHub API 非常相似。
 * Token 通过 POST 返回 JSON，用户信息通过 API 获取。
 *
 * @see https://gitee.com/api/v5/oauth_doc
 */
class GiteeDriver extends AbstractDriver
{
    protected string $authBaseUrl  = 'https://gitee.com/oauth/authorize';
    protected string $tokenUrl     = 'https://gitee.com/oauth/token';
    protected string $userApiUrl   = 'https://gitee.com/api/v5/user';
    protected string $emailsUrl    = 'https://gitee.com/api/v5/emails';

    public function getPlatform(): string
    {
        return 'gitee';
    }

    public function getPlatformName(): string
    {
        return '码云';
    }

    public function getDefaultScopes(): array
    {
        return ['user_info', 'emails'];
    }

    public function getAuthUrl(string $state, ?string $redirectUri = null, ?string $codeChallenge = null, ?string $codeChallengeMethod = null): string
    {
        $query = http_build_query([
            'client_id'    => $this->getAppId(),
            'redirect_uri' => $this->getRedirectUri($redirectUri),
            'response_type' => 'code',
            'scope'        => implode(' ', $this->config['scopes'] ?? $this->getDefaultScopes()),
            'state'        => $state,
        ]);

        return "{$this->authBaseUrl}?{$query}";
    }

    public function getUser(string $code, ?string $state = null, ?string $redirectUri = null, ?string $codeVerifier = null): OAuthUserInfo
    {
        // Step 1: code → access_token
        $tokenResponse = $this->httpPost($this->tokenUrl, [
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'client_id'     => $this->getAppId(),
            'client_secret' => $this->getAppSecret(),
            'redirect_uri'  => $this->getRedirectUri($redirectUri),
        ]);

        if (!empty($tokenResponse['error'])) {
            throw new OAuthException(
                "Gitee 获取 Token 失败：{$tokenResponse['error_description']}",
                0,
                null,
                $this->getPlatform()
            );
        }

        $accessToken  = $tokenResponse['access_token'] ?? '';
        $refreshToken = $tokenResponse['refresh_token'] ?? null;
        $expiresIn    = (int) ($tokenResponse['expires_in'] ?? 0);

        if (empty($accessToken)) {
            throw new OAuthException('Gitee 返回的 Token 数据不完整');
        }

        // Step 2: access_token → 用户信息
        $userResponse = $this->httpGet($this->userApiUrl, [], [
            'access_token' => $accessToken,
        ]);

        if (empty($userResponse['id'])) {
            throw new OAuthException('Gitee 获取用户信息失败');
        }

        // Step 3: 获取邮箱
        $email = $userResponse['email'] ?? '';
        try {
            $emails = $this->httpGet($this->emailsUrl, [], [
                'access_token' => $accessToken,
            ]);

            foreach ($emails as $emailItem) {
                if (!empty($emailItem['state']) && $emailItem['state'] === 'confirmed') {
                    $email = $emailItem['email'];
                    break;
                }
            }
        } catch (\Throwable $e) {
            // 邮箱获取失败不中断
        }

        $info = new OAuthUserInfo();
        $info->platform     = $this->getPlatform();
        $info->openid       = (string) ($userResponse['id'] ?? '');
        $info->nickname     = $userResponse['login'] ?? $userResponse['name'] ?? '';
        $info->avatar       = $userResponse['avatar_url'] ?? '';
        $info->email        = $email;
        $info->accessToken  = $accessToken;
        $info->refreshToken = $refreshToken;
        $info->expiresIn    = $expiresIn;
        $info->raw          = $userResponse;

        return $info;
    }

    public function refreshToken(string $refreshToken): array
    {
        $response = $this->httpPost($this->tokenUrl, [
            'grant_type'    => 'refresh_token',
            'refresh_token' => $refreshToken,
        ]);

        if (!empty($response['error'])) {
            throw new OAuthException("Gitee 刷新 Token 失败：{$response['error_description']}");
        }

        return [
            'access_token'  => $response['access_token'] ?? '',
            'refresh_token' => $response['refresh_token'] ?? $refreshToken,
            'expires_in'    => (int) ($response['expires_in'] ?? 0),
        ];
    }
}
