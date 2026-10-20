<?php
declare(strict_types=1);

namespace wise\oauth\driver;

use wise\oauth\entity\OAuthUserInfo;
use wise\oauth\exception\OAuthException;

/**
 * 微信开放平台驱动 — 扫码登录
 *
 * OAuth 2.0 authorization_code 流程。
 * Token URL 返回 JSON，用户信息 URL 返回 JSON。
 *
 * @see https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html
 */
class WechatOpenDriver extends AbstractDriver
{
    protected string $authBaseUrl  = 'https://open.weixin.qq.com/connect/qrconnect';
    protected string $tokenUrl     = 'https://api.weixin.qq.com/sns/oauth2/access_token';
    protected string $userInfoUrl  = 'https://api.weixin.qq.com/sns/userinfo';
    protected string $refreshUrl   = 'https://api.weixin.qq.com/sns/oauth2/refresh_token';

    public function getPlatform(): string
    {
        return 'wechat_open';
    }

    public function getPlatformName(): string
    {
        return '微信开放平台';
    }

    public function getDefaultScopes(): array
    {
        return ['snsapi_login'];
    }

    public function getAuthUrl(string $state, ?string $redirectUri = null, ?string $codeChallenge = null, ?string $codeChallengeMethod = null): string
    {
        $query = http_build_query([
            'appid'         => $this->getAppId(),
            'redirect_uri'  => $this->getRedirectUri($redirectUri),
            'response_type' => 'code',
            'scope'         => implode(',', $this->config['scopes'] ?? $this->getDefaultScopes()),
            'state'         => $state,
        ]);

        return "{$this->authBaseUrl}?{$query}#wechat_redirect";
    }

    public function getUser(string $code, ?string $state = null, ?string $redirectUri = null, ?string $codeVerifier = null): OAuthUserInfo
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
                "微信获取 Token 失败：{$tokenResponse['errmsg']}",
                (int) $tokenResponse['errcode'],
                null,
                $this->getPlatform()
            );
        }

        $accessToken  = $tokenResponse['access_token'] ?? '';
        $refreshToken = $tokenResponse['refresh_token'] ?? null;
        $expiresIn    = (int) ($tokenResponse['expires_in'] ?? 7200);
        $openid       = $tokenResponse['openid'] ?? '';
        $unionId      = $tokenResponse['unionid'] ?? null;

        if (empty($accessToken) || empty($openid)) {
            throw new OAuthException('微信返回的 Token 数据不完整');
        }

        // Step 2: access_token → 用户信息
        $userResponse = $this->httpGet($this->userInfoUrl, [], [
            'access_token' => $accessToken,
            'openid'       => $openid,
            'lang'         => 'zh_CN',
        ]);

        if (!empty($userResponse['errcode'])) {
            throw new OAuthException(
                "微信获取用户信息失败：{$userResponse['errmsg']}",
                (int) $userResponse['errcode'],
                null,
                $this->getPlatform()
            );
        }

        $info = new OAuthUserInfo();
        $info->platform     = $this->getPlatform();
        $info->openid       = $openid;
        $info->unionId      = $unionId ?: ($userResponse['unionid'] ?? null);
        $info->nickname     = $userResponse['nickname'] ?? '';
        $info->avatar       = $userResponse['headimgurl'] ?? '';
        $sex = $userResponse['sex'] ?? 0;
        $info->gender       = $sex == 1 ? 'male' : ($sex == 2 ? 'female' : null);
        $info->accessToken  = $accessToken;
        $info->refreshToken = $refreshToken;
        $info->expiresIn    = $expiresIn;
        $info->raw          = $userResponse;

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
                "微信刷新 Token 失败：{$response['errmsg']}",
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
