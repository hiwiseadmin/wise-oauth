<?php
declare(strict_types=1);

namespace wise\oauth;

use think\facade\Db;
use think\facade\Event;
use wise\oauth\contract\OAuthDriverInterface;
use wise\oauth\entity\OAuthUserInfo;
use wise\oauth\enums\Platform;
use wise\oauth\event\OAuthUserBound;
use wise\oauth\event\OAuthUserLoggedIn;
use wise\oauth\event\OAuthUserRegistered;
use wise\oauth\event\OAuthUserUnbound;
use wise\oauth\exception\OAuthBindingException;
use wise\oauth\exception\OAuthDriverNotFoundException;
use wise\oauth\exception\OAuthException;
use wise\oauth\model\OAuthUserModel;
use wise\support\rate\RateLimiter;

/**
 * OAuth 核心编排器
 *
 * 全部对外 API 的统一入口。编排驱动调用、用户查找/创建、绑定/解绑、事件触发等流程。
 *
 * 典型调用流程：
 * ```
 * $manager = app(OAuthManager::class);
 *
 * // 1. 获取授权 URL
 * $url = $manager->getAuthUrl('github');
 *
 * // 2. 处理回调
 * $userInfo = $manager->handleCallback('github', $code, $state);
 *
 * // 3. 登录或注册
 * $result = $manager->loginOrRegister($userInfo, 'admin');
 *
 * // 4. 绑定/解绑
 * $manager->bindUser($userId, 'admin', $userInfo);
 * $manager->unbindUser($userId, 'admin', 'github');
 * ```
 */
class OAuthManager
{
    /** @var array<string, OAuthDriverInterface> 驱动实例缓存 */
    protected array $driverInstances = [];

    /**
     * 获取平台驱动实例（惰性加载，单例缓存）
     *
     * @param  string $platform 平台标识
     * @return OAuthDriverInterface
     *
     * @throws OAuthDriverNotFoundException
     */
    public function driver(string $platform): OAuthDriverInterface
    {
        if (!isset($this->driverInstances[$platform])) {
            $platforms = config('wise-oauth.platforms', []);
            $config = $platforms[$platform] ?? null;

            if (!$config || empty($config['driver'])) {
                throw new OAuthDriverNotFoundException($platform);
            }

            // 检查平台是否启用
            if (isset($config['enabled']) && $config['enabled'] === false) {
                throw new OAuthException("OAuth 平台 {$platform} 未启用", 0, null, $platform);
            }

            $driverClass = $config['driver'];
            if (!class_exists($driverClass)) {
                throw new OAuthDriverNotFoundException($platform);
            }

            $this->driverInstances[$platform] = new $driverClass($config);
        }

        return $this->driverInstances[$platform];
    }

    /**
     * 获取所有已启用的平台列表
     *
     * @return array<array{key: string, name: string}>
     */
    public function getEnabledPlatforms(): array
    {
        $platforms = config('wise-oauth.platforms', []);
        $result = [];

        foreach ($platforms as $key => $config) {
            if (isset($config['enabled']) && $config['enabled'] === false) {
                continue;
            }
            if (empty($config['driver'])) {
                continue;
            }

            $result[] = [
                'key'  => $key,
                'name' => Platform::label($key),
            ];
        }

        return $result;
    }

    // ==================== 授权流程 ====================

    /**
     * 获取 OAuth 授权跳转 URL
     *
     * @param  string      $platform    平台标识
     * @param  string|null $redirectUri 回调地址（null 则用配置默认值）
     * @return string      完整的授权 URL
     */
    public function getAuthUrl(string $platform, ?string $redirectUri = null): string
    {
        $driver = $this->driver($platform);
        $stateManager = app(OAuthStateManager::class);

        if (config('wise-oauth.pkce_enabled', false)) {
            $pkce = $stateManager->generateWithPkce();
            return $driver->getAuthUrl($pkce['state'], $redirectUri, $pkce['code_challenge'], 'S256');
        }

        $state = $stateManager->generate();
        return $driver->getAuthUrl($state, $redirectUri);
    }

    /**
     * 处理 OAuth 回调
     *
     * 校验 state 防 CSRF，频率限制，调用驱动获取用户信息。
     *
     * @param  string      $platform    平台标识
     * @param  string      $code        授权码
     * @param  string|null $state       CSRF state
     * @param  string|null $redirectUri  回调地址
     * @return OAuthUserInfo            标准化用户信息
     *
     * @throws OAuthException
     */
    public function handleCallback(
        string $platform,
        string $code,
        ?string $state = null,
        ?string $redirectUri = null
    ): OAuthUserInfo {
        // 1. 频率限制前置：非法 state 也必须计数，否则该接口可被无限刷
        $this->applyRateLimit($platform);

        // 2. 校验 state（防 CSRF）—— 一次性消费，不存在任何绕过路径
        if (empty($state)) {
            throw new OAuthException('缺少 state 参数，拒绝回调', 0, null, $platform);
        }

        $stateManager = app(OAuthStateManager::class);
        if (!$stateManager->validate($state)) {
            throw new OAuthException('无效的 state 参数，请重新发起授权', 0, null, $platform);
        }

        // 3. 调用驱动获取用户信息（PKCE 模式下取一次性 code_verifier）
        $driver       = $this->driver($platform);
        $codeVerifier = $stateManager->getCodeVerifier($state);

        return $driver->getUser($code, $state, $redirectUri, $codeVerifier);
    }

    // ==================== 登录/注册流程 ====================

    /**
     * OAuth 登录或注册
     *
     * 核心流程：
     * 1. 通过 OAuth 标识查找已有绑定
     * 2. 找到 → 直接登录
     * 3. 未找到 → 尝试 email/mobile 自动关联
     * 4. 仍不匹配 → 自动注册（如果配置允许）
     *
     * @param  OAuthUserInfo $userInfo OAuth 用户信息
     * @param  string        $userType 用户类型 admin/member
     * @return array{oauth_user: OAuthUserModel, local_user: \think\Model, is_new: bool}
     *
     * @throws OAuthException
     */
    public function loginOrRegister(OAuthUserInfo $userInfo, string $userType): array
    {
        $platform  = $userInfo->platform;
        $config    = config('wise-oauth', []);
        $resolver  = app(OAuthUserResolver::class);
        $encryptor = app(OAuthTokenEncryptor::class);

        // Step 1: 通过 OAuth 标识查找已有绑定
        $existingBinding = $resolver->findBindingByOAuth(
            $userInfo->openid,
            $platform,
            $userInfo->unionId
        );

        if ($existingBinding) {
            // 验证用户类型一致
            if ($existingBinding->getAttr('user_type') !== $userType) {
                throw new OAuthException(
                    '该第三方账号已绑定到其他类型的用户',
                    0,
                    null,
                    $platform
                );
            }

            // 已有绑定 → 加载本地用户
            $localUser = $resolver->resolveLocalUser($existingBinding);
            if (!$localUser) {
                throw new OAuthException('关联的用户账号不存在，绑定数据异常', 0, null, $platform);
            }

            // 更新绑定信息（昵称、头像、token）
            $this->updateBindingInfo($existingBinding, $userInfo, $encryptor);

            // 更新用户本地信息
            $this->updateUserProfile($localUser, $userInfo);

            // 触发登录事件
            Event::trigger(new OAuthUserLoggedIn($localUser, $existingBinding, $userInfo));

            return [
                'oauth_user' => $existingBinding,
                'local_user' => $localUser,
                'is_new'     => false,
            ];
        }

        // Step 2: 尝试通过 email 自动关联
        if ($config['auto_link']['email'] ?? false && !empty($userInfo->email)) {
            $localUser = $resolver->findByEmail($userInfo->email, $userType);
            if ($localUser) {
                $binding = $this->createBinding($localUser, $userType, $userInfo, $encryptor);
                Event::trigger(new OAuthUserBound($localUser, $binding, $userInfo));
                return [
                    'oauth_user' => $binding,
                    'local_user' => $localUser,
                    'is_new'     => false,
                ];
            }
        }

        // Step 3: 尝试通过手机号自动关联
        if ($config['auto_link']['mobile'] ?? false && !empty($userInfo->mobile)) {
            $localUser = $resolver->findByMobile($userInfo->mobile, $userType);
            if ($localUser) {
                $binding = $this->createBinding($localUser, $userType, $userInfo, $encryptor);
                Event::trigger(new OAuthUserBound($localUser, $binding, $userInfo));
                return [
                    'oauth_user' => $binding,
                    'local_user' => $localUser,
                    'is_new'     => false,
                ];
            }
        }

        // Step 4: 自动注册
        if (!($config['auto_register'] ?? true)) {
            throw new OAuthException(
                '未找到关联账号，且自动注册功能已禁用。请先注册账号后再绑定。',
                0,
                null,
                $platform
            );
        }

        // 本地用户与绑定记录必须原子创建：否则绑定失败（如并发唯一键冲突）会在库里
        // 留下一个没有任何绑定关系的孤儿账号，用户重试回调时又会再建一个账号
        $localUser = null;
        $binding   = null;

        Db::transaction(function () use (
            $resolver,
            $userInfo,
            $userType,
            $encryptor,
            &$localUser,
            &$binding
        ): void {
            $localUser = $resolver->createLocalUser($userInfo, $userType);
            $binding   = $this->createBinding($localUser, $userType, $userInfo, $encryptor);
        });

        // 更新用户本地信息
        $this->updateUserProfile($localUser, $userInfo);

        Event::trigger(new OAuthUserRegistered($localUser, $binding, $userInfo));

        return [
            'oauth_user' => $binding,
            'local_user' => $localUser,
            'is_new'     => true,
        ];
    }

    // ==================== 绑定/解绑 ====================

    /**
     * 绑定 OAuth 账号到已登录用户
     *
     * @param  int           $userId   本地用户 ID
     * @param  string        $userType 用户类型
     * @param  OAuthUserInfo $userInfo OAuth 用户信息
     * @return OAuthUserModel
     *
     * @throws OAuthBindingException
     */
    public function bindUser(int $userId, string $userType, OAuthUserInfo $userInfo): OAuthUserModel
    {
        $platform = $userInfo->platform;

        // 检查是否已绑定
        $existing = OAuthUserModel::where('user_type', $userType)
            ->where('user_id', $userId)
            ->where('platform', $platform)
            ->find();

        if ($existing) {
            throw new OAuthBindingException(
                "该平台（{$platform}）已绑定，请先解绑",
                0,
                null,
                $platform
            );
        }

        // 检查该 OAuth 账号是否已被其他用户绑定
        $otherBinding = OAuthUserModel::where('platform', $platform)
            ->where('openid', $userInfo->openid)
            ->find();

        if ($otherBinding) {
            throw new OAuthBindingException(
                '该第三方账号已被其他用户绑定',
                0,
                null,
                $platform
            );
        }

        $resolver  = app(OAuthUserResolver::class);
        $encryptor = app(OAuthTokenEncryptor::class);

        $localUser = $resolver->resolveLocalUserById($userId, $userType);
        if (!$localUser) {
            throw new OAuthBindingException('用户不存在');
        }

        $binding = $this->createBinding($localUser, $userType, $userInfo, $encryptor);

        Event::trigger(new OAuthUserBound($localUser, $binding, $userInfo));

        return $binding;
    }

    /**
     * 解绑 OAuth 账号
     *
     * @param  int    $userId   本地用户 ID
     * @param  string $userType 用户类型
     * @param  string $platform 平台标识
     * @return bool
     *
     * @throws OAuthBindingException
     */
    public function unbindUser(int $userId, string $userType, string $platform): bool
    {
        $binding = OAuthUserModel::where('user_type', $userType)
            ->where('user_id', $userId)
            ->where('platform', $platform)
            ->find();

        if (!$binding) {
            throw new OAuthBindingException(
                "该平台（{$platform}）未绑定",
                0,
                null,
                $platform
            );
        }

        // 确保用户有至少一种登录方式
        $resolver = app(OAuthUserResolver::class);
        $resolver->ensureLoginMethod($userId, $userType, $platform);

        try {
            $binding->delete();
        } catch (\think\db\exception\DbException $e) {
            throw new OAuthBindingException(
                "解绑失败：数据库操作异常",
                0,
                $e,
                $platform
            );
        }

        Event::trigger(new OAuthUserUnbound($userId, $userType, $platform));

        return true;
    }

    /**
     * 获取用户所有绑定列表
     *
     * @param  int    $userId   本地用户 ID
     * @param  string $userType 用户类型
     * @return OAuthUserModel[]
     */
    public function getUserBindings(int $userId, string $userType): array
    {
        return OAuthUserModel::where('user_type', $userType)
            ->where('user_id', $userId)
            ->select()
            ->all();
    }

    /**
     * 检查用户是否绑定了指定平台
     *
     * @param  int    $userId
     * @param  string $userType
     * @param  string $platform
     * @return bool
     */
    public function hasBinding(int $userId, string $userType, string $platform): bool
    {
        return OAuthUserModel::where('user_type', $userType)
            ->where('user_id', $userId)
            ->where('platform', $platform)
            ->find() !== null;
    }

    // ============================================================
    // 内部方法
    // ============================================================

    /**
     * 创建绑定记录
     *
     * @param  \think\Model    $localUser
     * @param  string          $userType
     * @param  OAuthUserInfo   $info
     * @param  OAuthTokenEncryptor $encryptor
     * @return OAuthUserModel
     */
    protected function createBinding(
        $localUser,
        string $userType,
        OAuthUserInfo $info,
        OAuthTokenEncryptor $encryptor
    ): OAuthUserModel {
        $encryptedAccessToken  = $encryptor->encryptIfEnabled($info->accessToken);
        $encryptedRefreshToken = $info->refreshToken
            ? $encryptor->encryptIfEnabled($info->refreshToken)
            : null;

        $ip = request()->ip();

        $model = new OAuthUserModel();
        $model->setAttr('user_type',        $userType);
        $model->setAttr('user_id',          $localUser->getKey());
        $model->setAttr('platform',         $info->platform);
        $model->setAttr('openid',           $info->openid);
        $model->setAttr('union_id',         $info->unionId);
        $model->setAttr('nickname',         $info->nickname);
        $model->setAttr('avatar',           $info->avatar);
        $model->setAttr('email',            $info->email);
        $model->setAttr('mobile',           $info->mobile);
        $model->setAttr('raw_data',         json_encode($info->raw, JSON_UNESCAPED_UNICODE));
        $model->setAttr('access_token',     $encryptedAccessToken);
        $model->setAttr('refresh_token',    $encryptedRefreshToken);
        $model->setAttr('token_expires_at', $info->expiresIn
            ? date('Y-m-d H:i:s', time() + $info->expiresIn)
            : null);
        $model->setAttr('last_login_at',    date('Y-m-d H:i:s'));
        $model->setAttr('last_login_ip',    $ip);

        try {
            $model->save();
        } catch (\think\db\exception\DbException $e) {
            // 约束冲突（并发绑定）→ 转换为业务异常。
            // 依据结构化的 PDO 错误信息判断（SQLSTATE 23000 / MySQL 1062），
            // 而不是匹配 'Duplicate' / '1062' 之类的英文错误文案。
            $pdoError   = $e->getData()['PDO Error Info'] ?? [];
            $sqlState   = (string) ($pdoError['SQLSTATE'] ?? '');
            $driverCode = (int) ($pdoError['Driver Error Code'] ?? 0);

            if ($sqlState === '23000' || $driverCode === 1062) {
                throw new OAuthBindingException(
                    '该平台或第三方账号已被绑定，可能是并发请求导致',
                    0,
                    $e,
                    $info->platform
                );
            }
            throw $e;
        }

        return $model;
    }

    /**
     * 更新绑定记录的信息
     *
     * @param OAuthUserModel      $binding
     * @param OAuthUserInfo       $info
     * @param OAuthTokenEncryptor $encryptor
     */
    protected function updateBindingInfo(
        OAuthUserModel $binding,
        OAuthUserInfo $info,
        OAuthTokenEncryptor $encryptor
    ): void {
        // 只用非空值覆盖：微信小游戏（code2session，仅 openid/unionid）、
        // snsapi_base 等流程不会返回资料/令牌，无条件覆盖会把已存的有效数据清空
        foreach (['nickname', 'avatar', 'email', 'mobile'] as $field) {
            if (!empty($info->{$field})) {
                $binding->setAttr($field, $info->{$field});
            }
        }

        if ($info->accessToken !== '') {
            $binding->setAttr('access_token', $encryptor->encryptIfEnabled($info->accessToken));
        }
        if ($info->refreshToken) {
            $binding->setAttr('refresh_token', $encryptor->encryptIfEnabled($info->refreshToken));
        }
        if ($info->expiresIn) {
            $binding->setAttr('token_expires_at', date('Y-m-d H:i:s', time() + $info->expiresIn));
        }

        $binding->setAttr('last_login_at', date('Y-m-d H:i:s'));
        $binding->setAttr('last_login_ip', request()->ip());
        $binding->save();
    }

    /**
     * 更新本地用户的个人资料
     *
     * @param \think\Model  $user
     * @param OAuthUserInfo $info
     */
    protected function updateUserProfile($user, OAuthUserInfo $info): void
    {
        $updated = false;

        // 仅当本地字段为空时才填充（不覆盖用户已设置的信息）
        $fields = ['nickname', 'email', 'mobile'];
        foreach ($fields as $field) {
            $current = $user->getAttr($field) ?? '';
            $oauthValue = $info->{$field} ?? '';

            if (empty($current) && !empty($oauthValue)) {
                $user->setAttr($field, $oauthValue);
                $updated = true;
            }
        }

        // Avatar 同理
        if (empty($user->getAttr('avatar') ?? '') && !empty($info->avatar)) {
            $user->setAttr('avatar', $info->avatar);
            $updated = true;
        }

        if ($updated) {
            $user->save();
        }
    }

    /**
     * 频率限制
     *
     * 使用 wise\support\rate\RateLimiter 统一限流能力，
     * 支持滑动窗口、原子操作、X-RateLimit-* 标准响应头。
     *
     * @param string $platform
     * @throws OAuthException
     */
    protected function applyRateLimit(string $platform): void
    {
        $rateLimit = config('wise-oauth.rate_limit', []);
        if (!($rateLimit['enabled'] ?? false)) {
            return;
        }

        $ip = request()->ip();
        $key = "{$platform}:{$ip}";
        $maxAttempts  = (int) ($rateLimit['max_attempts'] ?? 10);
        $decayMinutes = (int) ($rateLimit['decay_minutes'] ?? 1);

        $limiter = RateLimiter::for($maxAttempts, $decayMinutes * 60)
            ->withPrefix('oauth_rate')
            ->by($key);

        if ($limiter->tooManyAttempts()) {
            throw new OAuthException(
                "操作过于频繁，请{$decayMinutes}分钟后再试",
                0,
                null,
                $platform
            );
        }

        $limiter->hit();
    }
}
