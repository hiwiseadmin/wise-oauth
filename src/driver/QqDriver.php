<?php
declare(strict_types=1);

namespace wise\oauth\driver;

use wise\oauth\entity\OAuthUserInfo;
use wise\oauth\exception\OAuthException;

/**
 * QQ 互联驱动
 *
 * QQ 互联 OAuth 2.0 流程的特殊之处：
 * 1. Token URL 返回 URL-encoded 格式（不是 JSON）
 * 2. 需要额外一步获取 openid（通过 /oauth2.0/me 接口）
 * 3. openid 返回格式为 callback( {...} );
 *
 * @see https://wiki.connect.qq.com/
 */
class QqDriver extends AbstractDriver
{
    protected string $authBaseUrl  = 'https://graph.qq.com/oauth2.0/authorize';
    protected string $tokenUrl     = 'https://graph.qq.com/oauth2.0/token';
    protected string $openidUrl    = 'https://graph.qq.com/oauth2.0/me';
    protected string $userInfoUrl  = 'https://graph.qq.com/user/get_user_info';

    public function getPlatform(): string
    {
        return 'qq';
    }

    public function getPlatformName(): string
    {
        return 'QQ';
    }

    public function getDefaultScopes(): array
    {
        return ['get_user_info'];
    }

    public function getAuthUrl(string $state, ?string $redirectUri = null, ?string $codeChallenge = null, ?string $codeChallengeMethod = null): string
    {
        $query = http_build_query([
            'response_type' => 'code',
            'client_id'     => $this->getAppId(),
            'redirect_uri'  => $this->getRedirectUri($redirectUri),
            'state'         => $state,
            'scope'         => implode(',', $this->config['scopes'] ?? $this->getDefaultScopes()),
            'display'       => '',
        ]);

        return "{$this->authBaseUrl}?{$query}";
    }

    public function getUser(string $code, ?string $state = null, ?string $redirectUri = null, ?string $codeVerifier = null): OAuthUserInfo
    {
        // Step 1: code → access_token（QQ 返回 URL-encoded 格式）
        $rawResponse = $this->httpPostRaw($this->tokenUrl, [
            'grant_type'    => 'authorization_code',
            'client_id'     => $this->getAppId(),
            'client_secret' => $this->getAppSecret(),
            'code'          => $code,
            'redirect_uri'  => $this->getRedirectUri($redirectUri),
        ]);

        parse_str($rawResponse, $tokenResponse);

        if (!empty($tokenResponse['error'])) {
            throw new OAuthException(
                "QQ 获取 Token 失败：{$tokenResponse['error_description']}",
                (int) ($tokenResponse['error'] ?? 0),
                null,
                $this->getPlatform()
            );
        }

        $accessToken = $tokenResponse['access_token'] ?? '';
        $expiresIn   = (int) ($tokenResponse['expires_in'] ?? 0);

        if (empty($accessToken)) {
            throw new OAuthException('QQ 返回的 Token 数据不完整');
        }

        // Step 2: access_token → openid（QQ 特有步骤）
        $openidRaw = $this->httpPostRaw("{$this->openidUrl}?access_token={$accessToken}&fmt=json");
        $openidData = json_decode($openidRaw, true);

        if (empty($openidData['openid'])) {
            // 尝试解析 callback 格式
            if (preg_match('/callback\s*\(\s*(.+)\s*\)\s*;/is', $openidRaw, $matches)) {
                $openidData = json_decode($matches[1], true) ?: [];
            }
        }

        $openid = $openidData['openid'] ?? '';

        if (empty($openid)) {
            throw new OAuthException('QQ 获取 OpenID 失败');
        }

        // Step 3: openid + access_token → 用户信息
        $userResponse = $this->httpGet($this->userInfoUrl, [], [
            'access_token'       => $accessToken,
            'oauth_consumer_key' => $this->getAppId(),
            'openid'             => $openid,
        ]);

        // 注意运算符优先级：必须先加括号再比较，否则 `?? -1 !== 0` 会被解析为
        // `?? (-1 !== 0)` → `?? true`，接口未返回 ret 字段时误判为失败
        if (($userResponse['ret'] ?? -1) !== 0) {
            throw new OAuthException(
                'QQ 获取用户信息失败：' . ($userResponse['msg'] ?? '未知错误'),
                (int) ($userResponse['ret'] ?? -1),
                null,
                $this->getPlatform()
            );
        }

        $info = new OAuthUserInfo();
        $info->platform     = $this->getPlatform();
        $info->openid       = $openid;
        $info->nickname     = $userResponse['nickname'] ?? '';
        $info->avatar       = $userResponse['figureurl_qq_2'] ?? $userResponse['figureurl_qq_1'] ?? '';
        $gender = $userResponse['gender'] ?? '';
        $info->gender       = $gender === '男' ? 'male' : ($gender === '女' ? 'female' : null);
        $info->accessToken  = $accessToken;
        $info->expiresIn    = $expiresIn;
        $info->raw          = $userResponse;

        return $info;
    }
}
