<?php
declare(strict_types=1);

namespace wise\oauth\trait;

use think\facade\Request;
use wise\oauth\facade\OAuth;
use wise\oauth\enums\Platform;
use wise\oauth\exception\OAuthException;

/**
 * API OAuth Trait（JWT-based 前后端分离）
 *
 * 用于 SPA / 移动端等前后端分离场景的会员第三方登录。
 * 需要控制器具备以下能力：
 *   - success($msg, $data) / error($msg) 方法（通过 JsonResponse trait 或 ApiController 提供）
 *   - Request::instance() 可用
 *
 * 登录流程：
 * 1. 前端 GET /api/oauth/auth/:platform → 获得 authUrl
 * 2. 前端跳转到 authUrl
 * 3. 第三方回调到 redirect_uri（由前端配置）
 * 4. 前端将 code 提交到 POST /api/oauth/login/:platform
 * 5. 后端返回 JWT token
 *
 * 路由建议：
 *   GET  /api/oauth/auth/:platform    → oauthAuthUrl
 *   POST /api/oauth/login/:platform   → oauthLogin
 *   GET  /api/oauth/platforms         → oauthApiPlatforms
 *   GET  /api/oauth/bindings          → oauthApiBindings   [需 JWT 认证]
 *   POST /api/oauth/bind/:platform    → oauthApiBind       [需 JWT 认证]
 *   POST /api/oauth/unbind/:platform  → oauthApiUnbind     [需 JWT 认证]
 */
trait OAuthApiTrait
{
    /**
     * 获取授权 URL
     */
    public function oauthAuthUrl(string $platform)
    {
        try {
            $redirectUri = Request::get('redirect_uri', '');
            $authUrl = OAuth::getAuthUrl($platform, $redirectUri ?: null);

            return $this->success('', [
                'auth_url' => $authUrl,
                'platform' => $platform,
            ]);
        } catch (OAuthException $e) {
            return $this->error($e->getMessage());
        }
    }

    /**
     * OAuth 登录（返回 JWT Token）
     */
    public function oauthLogin(string $platform)
    {
        $code        = Request::post('code', '');
        $state       = Request::post('state', '');
        $redirectUri = Request::post('redirect_uri', '');

        if (empty($code)) {
            return $this->error('缺少授权码参数');
        }

        try {
            $userInfo = OAuth::handleCallback($platform, $code, $state, $redirectUri ?: null);
            $result   = OAuth::loginOrRegister($userInfo, 'member');
            $member   = $result['local_user'];

            // 签发 JWT Token（依赖 wise-jwt 包）
            $jwtService = app(\wise\jwt\Jwt::class);
            $token = $jwtService->issue([
                'sub'  => $member->getKey(),
                'type' => 'member',
            ]);

            // 更新登录信息
            if (method_exists($member, 'save')) {
                $member->setAttr('last_login_time', date('Y-m-d H:i:s'));
                $member->setAttr('last_login_ip', Request::ip());
                $member->setAttr('login_count', ($member->getAttr('login_count') ?? 0) + 1);
                $member->save();
            }

            return $this->success('登录成功', [
                'token'         => $token,
                'user'          => [
                    'id'       => $member->getKey(),
                    'username' => $member->getAttr('username'),
                    'nickname' => $member->getAttr('nickname'),
                    'avatar'   => $member->getAttr('avatar'),
                ],
                'is_new'        => $result['is_new'],
                'platform'      => $platform,
                'platform_name' => Platform::label($platform),
            ]);

        } catch (OAuthException $e) {
            return $this->error($e->getMessage());
        }
    }

    /**
     * 获取已启用的平台列表
     */
    public function oauthApiPlatforms()
    {
        $platforms = OAuth::getEnabledPlatforms();
        return $this->success('', $platforms);
    }

    /**
     * 获取当前会员 OAuth 绑定列表（需 JWT 认证）
     */
    public function oauthApiBindings()
    {
        $memberId = $this->getCurrentOAuthMemberId();
        if (!$memberId) {
            return $this->error('请先登录');
        }

        try {
            $bindings = OAuth::getUserBindings($memberId, 'member');

            $result = [];
            foreach ($bindings as $binding) {
                $platform = $binding->getAttr('platform') ?: '';
                $result[] = [
                    'platform'      => $platform,
                    'platform_name' => $binding->getPlatformName(),
                    'nickname'      => $binding->getAttr('nickname') ?: '',
                    'avatar'        => $binding->getAttr('avatar') ?: '',
                    'bound_at'      => $binding->getAttr('create_time') ?: '',
                ];
            }

            return $this->success('', ['bindings' => $result]);

        } catch (OAuthException $e) {
            return $this->error($e->getMessage());
        }
    }

    /**
     * 绑定 OAuth 平台（需 JWT 认证）
     */
    public function oauthApiBind(string $platform)
    {
        $memberId = $this->getCurrentOAuthMemberId();
        if (!$memberId) {
            return $this->error('请先登录');
        }

        $code  = Request::post('code', '');
        $state = Request::post('state', '');

        if (empty($code)) {
            return $this->error('缺少授权码参数');
        }

        try {
            $userInfo = OAuth::handleCallback($platform, $code, $state);
            $binding  = OAuth::bindUser($memberId, 'member', $userInfo);

            return $this->success('绑定成功', [
                'platform'      => $platform,
                'platform_name' => $binding->getPlatformName(),
                'nickname'      => $binding->getAttr('nickname'),
            ]);

        } catch (OAuthException $e) {
            return $this->error($e->getMessage());
        }
    }

    /**
     * 解绑 OAuth 平台（需 JWT 认证）
     */
    public function oauthApiUnbind(string $platform)
    {
        $memberId = $this->getCurrentOAuthMemberId();
        if (!$memberId) {
            return $this->error('请先登录');
        }

        try {
            OAuth::unbindUser($memberId, 'member', $platform);
            return $this->success('解绑成功');

        } catch (OAuthException $e) {
            return $this->error($e->getMessage());
        }
    }

    /**
     * 从 JWT 中间件注入的请求中获取当前会员 ID
     *
     * @return int|null
     */
    protected function getCurrentOAuthMemberId(): ?int
    {
        $request = Request::instance();

        // 尝试从 member 中间件注入的对象获取
        $member = $request->member ?? null;
        if ($member && method_exists($member, 'getKey')) {
            return (int) $member->getKey();
        }

        // 尝试从 JWT Payload 获取
        $jwtPayload = $request->jwtPayload ?? $request->jwt_payload ?? null;
        if (is_array($jwtPayload) && isset($jwtPayload['sub'])) {
            return (int) $jwtPayload['sub'];
        }

        return null;
    }
}
