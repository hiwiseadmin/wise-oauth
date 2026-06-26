<?php
declare(strict_types=1);

namespace wise\oauth\driver;

use wise\oauth\entity\OAuthUserInfo;
use wise\oauth\exception\OAuthException;

/**
 * 微信公众号驱动 — 网页授权
 *
 * OAuth 2.0 authorization_code 流程。
 * 支持 snsapi_base（静默，只获取 openid）和 snsapi_userinfo（弹窗授权，获取详细信息）。
 * Token URL 返回 JSON，用户信息 URL 返回 JSON。
 *
 * @see https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html
 */
class WechatMpDriver extends AbstractDriver
{
    protected string $authBaseUrl  = 'https://open.weixin.qq.com/connect/oauth2/authorize';
    protected string $tokenUrl     = 'https://api.weixin.qq.com/sns/oauth2/access_token';
    protected string $userInfoUrl  = 'https://api.weixin.qq.com/sns/userinfo';
    protected string $refreshUrl   = 'https://api.weixin.qq.com/sns/oauth2/refresh_token';

    public function getPlatform(): string
    {
        return 'wechat_mp';
    }

    public function getPlatformName(): string
    {
        return '微信公众号';
    }

    public function getDefaultScopes(): array
    {
        return ['snsapi_userinfo'];
    }

    public function getAuthUrl(string $state, ?string $redirectUri = null): string
    {
        $scopes = $this->config['scopes'] ?? $this->getDefaultScopes();
        $scope = is_array($scopes) ? implode(',', $scopes) : $scopes;

        $query = http_build_query([
            'appid'         => $this->getAppId(),
            'redirect_uri'  => $this->getRedirectUri($redirectUri),
            'response_type' => 'code',
            'scope'         => $scope,
            'state'         => $state,
        ]);

        return "{$this->authBaseUrl}?{$query}#wechat_redirect";
    }

    public function getUser(string $code, ?string $state = null, ?string $redirectUri = null): OAuthUserInfo
    {
        // Step 1: code → access_token
        $tokenResponse = $this->httpGet($this->tokenUrl, [], [
            'appid'      => $this->getAppId(),
            'secret'     => $this->getAppSecret(),
            'code'       => $code,
            'grant_type' => 'authorization_code',
        ]);

        if (!empty($tokenResponse['errcode'])) {
            throw new OAuthException(
                "微信公众号获取 Token 失败：{$tokenResponse['errmsg']}",
                (int) $tokenResponse['errcode'],
                null,
                $this->getPlatform()
            );
        }

        $accessToken  = $tokenResponse['access_token'] ?? '';
        $refreshToken = $tokenResponse['refresh_token'] ?? null;
        $expiresIn    = (int) ($tokenResponse['expires_in'] ?? 7200);
        $openid       = $tokenResponse['openid'] ?? '';
        $scope        = $tokenResponse['scope'] ?? '';

        if (empty($accessToken) || empty($openid)) {
            throw new OAuthException('微信公众号返回的 Token 数据不完整');
        }

        $info = new OAuthUserInfo();
        $info->platform     = $this->getPlatform();
        $info->openid       = $openid;
        $info->unionId      = $tokenResponse['unionid'] ?? null;
        $info->accessToken  = $accessToken;
        $info->refreshToken = $refreshToken;
        $info->expiresIn    = $expiresIn;
        $info->raw          = $tokenResponse;

        // Step 2: 如果是 snsapi_userinfo 授权（含多 scope 场景），获取用户详细信息
        if (strpos($scope, 'snsapi_userinfo') !== false) {
            $userResponse = $this->httpGet($this->userInfoUrl, [], [
                'access_token' => $accessToken,
                'openid'       => $openid,
                'lang'         => 'zh_CN',
            ]);

            if (!empty($userResponse['errcode'])) {
                // userinfo 获取失败不中断流程，仅保留 openid
            } else {
                $info->nickname = $userResponse['nickname'] ?? '';
                $info->avatar   = $userResponse['headimgurl'] ?? '';
                $info->gender   = ($userResponse['sex'] ?? 0) == 1 ? 'male' : 'female';
                $info->raw      = $userResponse;
            }
        }

        return $info;
    }

    public function refreshToken(string $refreshToken): array
    {
        $response = $this->httpGet($this->refreshUrl, [], [
            'appid'         => $this->getAppId(),
            'grant_type'    => 'refresh_token',
            'refresh_token' => $refreshToken,
        ]);

        if (!empty($response['errcode'])) {
            throw new OAuthException(
                "微信公众号刷新 Token 失败：{$response['errmsg']}",
                (int) $response['errcode'],
                null,
                $this->getPlatform()
            );
        }

        return [
            'access_token'  => $response['access_token'] ?? '',
            'refresh_token' => $response['refresh_token'] ?? $refreshToken,
            'expires_in'    => (int) ($response['expires_in'] ?? 7200),
        ];
    }
}
