<?php
declare(strict_types=1);

namespace wise\oauth\trait;

use think\facade\Session;
use wise\oauth\facade\OAuth;
use wise\oauth\exception\OAuthException;

/**
 * Admin OAuth Trait（Web 后台 Session-based）
 *
 * 框架控制器引入此 Trait 即可获得第三方 OAuth 登录/绑定/解绑能力。
 * 需要控制器具备以下能力：
 *   - success($msg, $data) / error($msg) 方法（通过 JsonResponse trait 或 BaseController 提供）
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

            session('admin_id', $admin->getKey());
            session('admin_username', $admin->getAttr('username'));
            session('admin_nickname', $admin->getAttr('nickname') ?: $admin->getAttr('username'));
            session('admin_password_token', $this->generateOAuthPasswordToken($admin));
            session('admin_last_login_time', date('Y-m-d H:i:s'));

            if (method_exists($admin, 'save')) {
                $admin->setAttr('login_failed', 0);
                $admin->setAttr('last_failed_time', null);
                $admin->setAttr('last_login_time', date('Y-m-d H:i:s'));
                $admin->setAttr('last_login_ip', request()->ip());
                $admin->save();
            }

            return redirect('/admin/index');

        } catch (OAuthException $e) {
            Session::flash('oauth_error', $e->getMessage());
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
        $adminId = session('admin_id');
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
        $adminId = session('admin_id');
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
        $adminId = session('admin_id');
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
     * 使用 HMAC-SHA256 替代原系统 MD5 方案。
     * OAuth 自动注册的管理员没有密码（空字符串），
     * 使用随机盐确保令牌不可预测。
     *
     * @param \think\Model $admin
     * @return string
     */
    protected function generateOAuthPasswordToken($admin): string
    {
        $adminId  = $admin->getKey();
        $password = $admin->getData('password') ?? '';

        $salt = $password ?: ($admin->getAttr('create_time') ?? bin2hex(random_bytes(16)));

        return substr(hash_hmac('sha256', (string) $adminId, $salt), 8, 16);
    }
}
