<?php
declare(strict_types=1);

namespace wise\oauth\driver;

use wise\oauth\entity\OAuthUserInfo;
use wise\oauth\exception\OAuthException;

/**
 * 微博驱动
 *
 * OAuth 2.0 authorization_code 流程。
 * Token URL 返回 URL-encoded 或 JSON（取决于 Accept），
 * 用户信息通过 uid + users/show API 获取。
 *
 * @see https://open.weibo.com/wiki/Connect/login
 */
class WeiboDriver extends AbstractDriver
{
    protected string $authBaseUrl  = 'https://api.weibo.com/oauth2/authorize';
    protected string $tokenUrl     = 'https://api.weibo.com/oauth2/access_token';
    protected string $userShowUrl  = 'https://api.weibo.com/2/users/show.json';

    public function getPlatform(): string
    {
        return 'weibo';
    }

    public function getPlatformName(): string
    {
        return '微博';
    }

    public function getDefaultScopes(): array
    {
        return ['all'];
    }

    public function getAuthUrl(string $state, ?string $redirectUri = null): string
    {
        $query = http_build_query([
            'client_id'    => $this->getAppId(),
            'redirect_uri' => $this->getRedirectUri($redirectUri),
            'response_type' => 'code',
            'scope'        => implode(',', $this->config['scopes'] ?? $this->getDefaultScopes()),
            'state'        => $state,
            'display'      => 'default',
        ]);

        return "{$this->authBaseUrl}?{$query}";
    }

    public function getUser(string $code, ?string $state = null, ?string $redirectUri = null): OAuthUserInfo
    {
        // Step 1: code → access_token
        $tokenResponse = $this->httpPost($this->tokenUrl, [
            'client_id'     => $this->getAppId(),
            'client_secret' => $this->getAppSecret(),
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => $this->getRedirectUri($redirectUri),
        ]);

        if (!empty($tokenResponse['error'])) {
            throw new OAuthException(
                "微博获取 Token 失败：{$tokenResponse['error_description']}",
                0,
                null,
                $this->getPlatform()
            );
        }

        $accessToken = $tokenResponse['access_token'] ?? '';
        $uid         = $tokenResponse['uid'] ?? '';
        $expiresIn   = (int) ($tokenResponse['expires_in'] ?? 0);

        if (empty($accessToken) || empty($uid)) {
            throw new OAuthException('微博返回的 Token 数据不完整');
        }

        // Step 2: uid + access_token → 用户信息
        $userResponse = $this->httpGet($this->userShowUrl, [], [
            'access_token' => $accessToken,
            'uid'          => $uid,
        ]);

        if (!empty($userResponse['error_code'])) {
            throw new OAuthException(
                "微博获取用户信息失败：{$userResponse['error']}",
                (int) $userResponse['error_code'],
                null,
                $this->getPlatform()
            );
        }

        $info = new OAuthUserInfo();
        $info->platform     = $this->getPlatform();
        $info->openid       = (string) $uid;
        $info->nickname     = $userResponse['screen_name'] ?? $userResponse['name'] ?? '';
        $info->avatar       = $userResponse['avatar_large'] ?? $userResponse['profile_image_url'] ?? '';
        $gender = $userResponse['gender'] ?? '';
        $info->gender       = $gender === 'm' ? 'male' : ($gender === 'f' ? 'female' : null);
        $info->accessToken  = $accessToken;
        $info->expiresIn    = $expiresIn;
        $info->raw          = $userResponse;

        return $info;
    }
}
