<?php
declare(strict_types=1);

namespace wise\oauth\driver;

use wise\oauth\entity\OAuthUserInfo;
use wise\oauth\exception\OAuthException;

/**
 * GitHub OAuth 驱动
 *
 * 标准 OAuth 2.0 authorization_code 流程。
 * Token 通过 POST 返回 JSON（Accept: application/json），
 * 用户信息通过 API 获取，邮箱需要单独请求。
 * GitHub token 不会过期（除非用户撤销权限）。
 *
 * @see https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
 */
class GithubDriver extends AbstractDriver
{
    protected string $authBaseUrl  = 'https://github.com/login/oauth/authorize';
    protected string $tokenUrl     = 'https://github.com/login/oauth/access_token';
    protected string $userApiUrl   = 'https://api.github.com/user';
    protected string $emailApiUrl  = 'https://api.github.com/user/emails';

    public function getPlatform(): string
    {
        return 'github';
    }

    public function getPlatformName(): string
    {
        return 'GitHub';
    }

    public function getDefaultScopes(): array
    {
        return ['user:email'];
    }

    public function getAuthUrl(string $state, ?string $redirectUri = null, ?string $codeChallenge = null, ?string $codeChallengeMethod = null): string
    {
        $query = http_build_query([
            'client_id'    => $this->getAppId(),
            'redirect_uri' => $this->getRedirectUri($redirectUri),
            'scope'        => implode(' ', $this->config['scopes'] ?? $this->getDefaultScopes()),
            'state'        => $state,
            'allow_signup' => 'true',
        ]);

        return "{$this->authBaseUrl}?{$query}";
    }

    public function getUser(string $code, ?string $state = null, ?string $redirectUri = null, ?string $codeVerifier = null): OAuthUserInfo
    {
        // Step 1: code → access_token
        $tokenResponse = $this->httpPost($this->tokenUrl, [
            'client_id'     => $this->getAppId(),
            'client_secret' => $this->getAppSecret(),
            'code'          => $code,
            'redirect_uri'  => $this->getRedirectUri($redirectUri),
        ], ['Accept' => 'application/json']);

        if (!empty($tokenResponse['error'])) {
            throw new OAuthException(
                "GitHub 获取 Token 失败：{$tokenResponse['error_description']}",
                0,
                null,
                $this->getPlatform()
            );
        }

        $accessToken = $tokenResponse['access_token'] ?? '';

        if (empty($accessToken)) {
            throw new OAuthException('GitHub 返回的 Token 数据不完整');
        }

        // Step 2: access_token → 用户信息
        $userResponse = $this->httpGet($this->userApiUrl, [
            'Authorization' => "Bearer {$accessToken}",
            'Accept'        => 'application/json',
        ]);

        if (empty($userResponse['id'])) {
            throw new OAuthException('GitHub 获取用户信息失败');
        }

        // Step 3: 获取主邮箱（GitHub 邮箱接口独立）
        $email = $userResponse['email'] ?? '';
        try {
            $emails = $this->httpGet($this->emailApiUrl, [
                'Authorization' => "Bearer {$accessToken}",
                'Accept'        => 'application/json',
            ]);

            foreach ($emails as $emailItem) {
                if (!empty($emailItem['primary']) && !empty($emailItem['verified'])) {
                    $email = $emailItem['email'];
                    break;
                }
            }
        } catch (\Throwable $e) {
            // 邮箱获取失败不中断流程
        }

        $info = new OAuthUserInfo();
        $info->platform     = $this->getPlatform();
        $info->openid       = (string) ($userResponse['id'] ?? '');
        $info->nickname     = $userResponse['login'] ?? '';
        $info->avatar       = $userResponse['avatar_url'] ?? '';
        $info->email        = $email;
        $info->accessToken  = $accessToken;
        $info->raw          = $userResponse;

        // GitHub token 不会过期
        return $info;
    }
}
