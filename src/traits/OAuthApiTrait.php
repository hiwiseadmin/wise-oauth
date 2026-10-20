<?php
declare(strict_types=1);

namespace wise\oauth\traits;

use think\facade\Request;
use wise\oauth\facade\OAuth;
use wise\oauth\enums\Platform;
use wise\oauth\exception\OAuthException;
use wise\support\context\ContextualLogger;
use wise\support\exception\WiseException;
use wise\support\facade\JWT;

/**
 * API OAuth Trait（JWT-based 前后端分离）
 *
 * 用于 SPA / 移动端等前后端分离场景的会员第三方登录。
 * 需要控制器具备以下能力：
 *   - success($msg, $data) / error($msg) 方法（通过 wise\support\traits\JsonResponse 或 ApiController 提供）
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
            $redirectUri = (string) Request::get('redirect_uri', '');

            // 回调地址只允许等于服务端配置值：避免把客户端任意 URL 透传给上游
            // 造成开放重定向 / 授权码被转发到外部域名
            $configured = (string) config("wise-oauth.platforms.{$platform}.redirect_uri", '');
            if ($redirectUri !== '' && !hash_equals($configured, $redirectUri)) {
                return $this->error('非法的回调地址');
            }

            $authUrl = OAuth::getAuthUrl($platform, $redirectUri ?: null);

            return $this->success('', [
                'auth_url' => $authUrl,
                'platform' => $platform,
            ]);
        } catch (WiseException | \RuntimeException $e) {
            // 覆盖 OAuthException、ServiceUnavailableException（熔断，非 OAuthException 子类）
            // 以及 encrypt_key 未配置时抛出的 RuntimeException
            return $this->error($e->getMessage());
        } catch (\Throwable $e) {
            ContextualLogger::error('[wise-oauth] OAuth API 异常: ' . $e->getMessage());
            return $this->error('第三方登录失败，请稍后重试');
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

            // 签发 JWT Token（通过 wise-support 统一 JWT facade）
            $token = JWT::issue($member->getKey(), [
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

        } catch (WiseException | \RuntimeException $e) {
            // 覆盖 OAuthException、ServiceUnavailableException（熔断，非 OAuthException 子类）
            // 以及 encrypt_key 未配置时抛出的 RuntimeException
            return $this->error($e->getMessage());
        } catch (\Throwable $e) {
            ContextualLogger::error('[wise-oauth] OAuth API 异常: ' . $e->getMessage());
            return $this->error('第三方登录失败，请稍后重试');
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

        } catch (WiseException | \RuntimeException $e) {
            // 覆盖 OAuthException、ServiceUnavailableException（熔断，非 OAuthException 子类）
            // 以及 encrypt_key 未配置时抛出的 RuntimeException
            return $this->error($e->getMessage());
        } catch (\Throwable $e) {
            ContextualLogger::error('[wise-oauth] OAuth API 异常: ' . $e->getMessage());
            return $this->error('第三方登录失败，请稍后重试');
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

        } catch (WiseException | \RuntimeException $e) {
            // 覆盖 OAuthException、ServiceUnavailableException（熔断，非 OAuthException 子类）
            // 以及 encrypt_key 未配置时抛出的 RuntimeException
            return $this->error($e->getMessage());
        } catch (\Throwable $e) {
            ContextualLogger::error('[wise-oauth] OAuth API 异常: ' . $e->getMessage());
            return $this->error('第三方登录失败，请稍后重试');
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

        } catch (WiseException | \RuntimeException $e) {
            // 覆盖 OAuthException、ServiceUnavailableException（熔断，非 OAuthException 子类）
            // 以及 encrypt_key 未配置时抛出的 RuntimeException
            return $this->error($e->getMessage());
        } catch (\Throwable $e) {
            ContextualLogger::error('[wise-oauth] OAuth API 异常: ' . $e->getMessage());
            return $this->error('第三方登录失败，请稍后重试');
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

        // 优先 AuthManager 统一入口
        if (function_exists('auth_id')) {
            $id = auth_id('api');
            if ($id !== null) {
                return (int) $id;
            }
        }

        // 尝试从 member 中间件注入的对象获取
        $member = $request->member ?? null;
        if ($member && method_exists($member, 'getKey')) {
            return (int) $member->getKey();
        }

        // 回退：从 JWT Payload 获取（兼容旧版本中间件）
        $jwtPayload = $request->jwtPayload ?? $request->jwt_payload ?? null;
        if (is_array($jwtPayload) && isset($jwtPayload['sub'])) {
            return (int) $jwtPayload['sub'];
        }

        return null;
    }
}
