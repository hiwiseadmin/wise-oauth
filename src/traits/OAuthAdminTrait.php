<?php
declare(strict_types=1);

namespace wise\oauth\traits;

use think\facade\Session;
use wise\oauth\facade\OAuth;
use wise\oauth\exception\OAuthException;
use wise\support\context\ContextualLogger;
use wise\support\context\RequestContext;
use wise\support\exception\WiseException;
use wise\support\facade\Auth;

/**
 * Admin OAuth Trait（Web 后台 Session-based）
 *
 * 框架控制器引入此 Trait 即可获得第三方 OAuth 登录/绑定/解绑能力。
 * 需要控制器具备以下能力：
 *   - success($msg, $data) / error($msg) 方法（通过 wise\support\traits\JsonResponse 或 BaseController 提供）
 *   - request() / session() 辅助函数
 *
 * 路由建议：
 *   GET  /admin/oauth/redirect/:platform  → redirect
 *   GET  /admin/oauth/callback/:platform   → callback
 *   GET  /admin/oauth/platforms            → oauthPlatforms
 *   GET  /admin/oauth/bindings             → oauthBindings
 *   POST /admin/oauth/bind/:platform       → oauthBind
 *   POST /admin/oauth/unbind/:platform     → oauthUnbind
 *
 * 需将以下路由加入 wise-auth 白名单：
 *   /admin/oauth/redirect/:platform
 *   /admin/oauth/callback/:platform
 */
trait OAuthAdminTrait
{
    /**
     * 重定向到 OAuth 授权页面
     */
    public function oauthRedirect(string $platform)
    {
        try {
            $authUrl = OAuth::getAuthUrl($platform);
            return redirect($authUrl);
        } catch (OAuthException $e) {
            Session::flash('oauth_error', $e->getMessage());
            return redirect('/admin/login');
        }
    }

    /**
     * OAuth 回调处理
     */
    public function oauthCallback(string $platform)
    {
        $code  = request()->get('code', '');
        $state = request()->get('state', '');

        if (empty($code)) {
            Session::flash('oauth_error', '授权失败：未获取到授权码');
            return redirect('/admin/login');
        }

        try {
            $userInfo = OAuth::handleCallback($platform, $code, $state);
            $result   = OAuth::loginOrRegister($userInfo, 'admin');
            $admin    = $result['local_user'];

            // 写入 Session（SessionGuard 读取 admin_id 判断登录状态）
            session('admin_id', $admin->getKey());
            session('admin_username', $admin->getAttr('username'));
            session('admin_nickname', $admin->getAttr('nickname') ?: $admin->getAttr('username'));
            session('admin_password_token', $this->generateOAuthPasswordToken($admin));
            session('admin_last_login_time', date('Y-m-d H:i:s'));

            // 写入 RequestContext（AuthManager + TokenGuard 统一读取入口）
            RequestContext::setUser($admin);
            RequestContext::setGuard('admin');

            if (method_exists($admin, 'save')) {
                $admin->setAttr('login_failed', 0);
                $admin->setAttr('last_failed_time', null);
                $admin->setAttr('last_login_time', date('Y-m-d H:i:s'));
                $admin->setAttr('last_login_ip', request()->ip());
                $admin->save();
            }

            return redirect('/admin/index');

        } catch (WiseException | \RuntimeException $e) {
            // 覆盖 OAuthException、ServiceUnavailableException（熔断，非 OAuthException 子类）
            // 以及 encrypt_key 未配置时抛出的 RuntimeException
            Session::flash('oauth_error', $e->getMessage());
            return redirect('/admin/login');
        } catch (\Throwable $e) {
            // 其余未预期异常：记录日志并给出可读提示，避免 500 白页
            ContextualLogger::error('[wise-oauth] OAuth 回调异常: ' . $e->getMessage());
            Session::flash('oauth_error', '第三方登录失败，请稍后重试');
            return redirect('/admin/login');
        }
    }

    /**
     * 获取已启用的平台列表（用于登录页展示）
     */
    public function oauthPlatforms()
    {
        $platforms = OAuth::getEnabledPlatforms();
        return $this->success('', $platforms);
    }

    /**
     * 获取当前管理员 OAuth 绑定列表
     */
    public function oauthBindings()
    {
        $adminId = auth_id('admin');
        if (!$adminId) {
            return $this->error('请先登录');
        }

        try {
            $bindings = OAuth::getUserBindings((int) $adminId, 'admin');

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
     * 绑定 OAuth 平台
     */
    public function oauthBind(string $platform)
    {
        $adminId = auth_id('admin');
        if (!$adminId) {
            return $this->error('请先登录');
        }

        $code  = request()->post('code', '');
        $state = request()->post('state', '');

        if (empty($code)) {
            return $this->error('缺少授权码参数');
        }

        try {
            $userInfo = OAuth::handleCallback($platform, $code, $state);
            $binding  = OAuth::bindUser((int) $adminId, 'admin', $userInfo);

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
     * 解绑 OAuth 平台
     */
    public function oauthUnbind(string $platform)
    {
        $adminId = auth_id('admin');
        if (!$adminId) {
            return $this->error('请先登录');
        }

        try {
            OAuth::unbindUser((int) $adminId, 'admin', $platform);
            return $this->success('解绑成功');

        } catch (OAuthException $e) {
            return $this->error($e->getMessage());
        }
    }

    /**
     * 生成管理员密码令牌
     *
     * 该令牌写入 session('admin_password_token')，供 SessionGuard 判定
     * "密码是否变更 / 会话是否仍有效"，因此必须**不可预测**：
     * 原实现由 adminId + 可推测的 create_time（空密码场景）派生并截断到 64bit，
     * 攻击者可离线复算后伪造会话指纹。这里改为直接使用 CSPRNG。
     *
     * 保留 $admin 形参以兼容既有调用方 / 子类重写。
     *
     * @param \think\Model $admin
     * @return string
     */
    protected function generateOAuthPasswordToken($admin): string
    {
        return bin2hex(random_bytes(32));
    }
}
