<?php
declare(strict_types=1);

namespace wise\oauth;

use think\facade\Cache;
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
        $platforms = config('wise-oauth.platforms', []);
        $config = $platforms[$platform] ?? null;

        if (!$config || empty($config['driver'])) {
            throw new OAuthDriverNotFoundException($platform);
        }

        if (isset($config['enabled']) && $config['enabled'] === false) {
            throw new OAuthException("OAuth 平台 {$platform} 未启用", 0, null, $platform);
        }

        $driverClass = $config['driver'];
        if (!class_exists($driverClass)) {
            throw new OAuthDriverNotFoundException($platform);
        }

        $cacheKey = $platform . ':' . $this->configFingerprint($config);

        if (!isset($this->driverInstances[$cacheKey])) {
            foreach (array_keys($this->driverInstances) as $key) {
                if (str_starts_with((string) $key, $platform . ':')) {
                    unset($this->driverInstances[$key]);
                }
            }

            $this->driverInstances[$cacheKey] = new $driverClass($config);
        }

        return $this->driverInstances[$cacheKey];
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

        if (config('wise-oauth.pkce_enabled', false) && $this->driverSupportsPkce($driver)) {
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
        $this->applyRateLimit($platform);

        if (empty($state)) {
            throw new OAuthException('缺少 state 参数，拒绝回调', 0, null, $platform);
        }

        $stateManager = app(OAuthStateManager::class);
        if (!$stateManager->validate($state)) {
            throw new OAuthException('无效的 state 参数，请重新发起授权', 0, null, $platform);
        }

        $driver       = $this->driver($platform);
        $codeVerifier = $stateManager->getCodeVerifier($state);

        return $driver->getUser($code, $state, $redirectUri, $codeVerifier);
    }


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

        $existingBinding = $resolver->findBindingByOAuth(
            $userInfo->openid,
            $platform,
            $userInfo->unionId
        );

        if ($existingBinding) {
            if ($existingBinding->getAttr('user_type') !== $userType) {
                throw new OAuthException(
                    '该第三方账号已绑定到其他类型的用户',
                    0,
                    null,
                    $platform
                );
            }

            $localUser = $resolver->resolveLocalUser($existingBinding);
            if (!$localUser) {
                throw new OAuthException('关联的用户账号不存在，绑定数据异常', 0, null, $platform);
            }

            $this->updateBindingInfo($existingBinding, $userInfo, $encryptor);

            $this->updateUserProfile($localUser, $userInfo);

            Event::trigger(new OAuthUserLoggedIn($localUser, $existingBinding, $userInfo));

            return [
                'oauth_user' => $existingBinding,
                'local_user' => $localUser,
                'is_new'     => false,
            ];
        }

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

        if (!($config['auto_register'] ?? true)) {
            throw new OAuthException(
                '未找到关联账号，且自动注册功能已禁用。请先注册账号后再绑定。',
                0,
                null,
                $platform
            );
        }

        $localUser = null;
        $binding   = null;

        try {
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
        } catch (OAuthBindingException $e) {
            $existing  = $resolver->findBindingByOAuth($userInfo->openid, $platform, $userInfo->unionId);
            $localUser = $existing ? $resolver->resolveLocalUser($existing) : null;

            if (!$existing || !$localUser) {
                throw $e;
            }

            $this->updateBindingInfo($existing, $userInfo, $encryptor);
            Event::trigger(new OAuthUserLoggedIn($localUser, $existing, $userInfo));

            return [
                'oauth_user' => $existing,
                'local_user' => $localUser,
                'is_new'     => false,
            ];
        }

        $this->updateUserProfile($localUser, $userInfo);

        Event::trigger(new OAuthUserRegistered($localUser, $binding, $userInfo));

        return [
            'oauth_user' => $binding,
            'local_user' => $localUser,
            'is_new'     => true,
        ];
    }


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

        $resolver = app(OAuthUserResolver::class);

        try {
            Db::transaction(function () use ($resolver, $userId, $userType, $platform): void {
                $locked = OAuthUserModel::where('user_type', $userType)
                    ->where('user_id', $userId)
                    ->where('platform', $platform)
                    ->lock(true)
                    ->find();

                if (!$locked) {
                    throw new OAuthBindingException("该平台（{$platform}）未绑定", 0, null, $platform);
                }

                $resolver->ensureLoginMethod($userId, $userType, $platform);
                $locked->delete();
            });
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

        $ip = $this->clientIp();

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
        $model->setAttr('raw_data',         $this->encodeRawData($info->raw));
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
        $binding->setAttr('last_login_ip', $this->clientIp());
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

        $fields = ['nickname', 'email', 'mobile'];
        foreach ($fields as $field) {
            $current = $user->getAttr($field) ?? '';
            $oauthValue = $info->{$field} ?? '';

            if (empty($current) && !empty($oauthValue)) {
                $user->setAttr($field, $oauthValue);
                $updated = true;
            }
        }

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
     * 固定窗口计数（按 平台 + 客户端 IP 维度）。
     *
     * 注意：这里刻意不复用 `RateLimiter::hit()` —— think-cache 的 Driver 基类与
     * File / Redis 等驱动都**没有** expire() 方法，`method_exists($cache, 'expire')`
     * 恒为 false，`inc()` 首次创建的计数键 expire=0（永不过期），达到上限后该 IP
     * 会被**永久**拒绝。因此在包内自行保证"首次计数时写入 TTL"。
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

        $maxAttempts  = (int) ($rateLimit['max_attempts'] ?? 10);
        $decaySeconds = max(1, (int) ($rateLimit['decay_minutes'] ?? 1) * 60);

        $store    = (string) ($rateLimit['store'] ?? '');
        $cache    = $store !== '' ? Cache::store($store) : Cache::store();
        $cacheKey = 'oauth_rate:' . $platform . ':' . $this->clientIp();

        if (method_exists($cache, 'inc')) {
            $hits = (int) $cache->inc($cacheKey, 1);
            if ($hits === 1) {
                $cache->set($cacheKey, 1, $decaySeconds);
            }
        } else {
            $hits = (int) $cache->get($cacheKey, 0) + 1;
            $cache->set($cacheKey, $hits, $decaySeconds);
        }

        if ($hits > $maxAttempts) {
            throw new OAuthException(
                '操作过于频繁，请' . (int) ceil($decaySeconds / 60) . '分钟后再试',
                0,
                null,
                $platform
            );
        }
    }

    /**
     * 取客户端 IP（HTTP / 队列 / CLI 通用）
     *
     * 直接把 request() 写进编排器会把 OAuthManager 绑死在 HTTP 请求上：
     * Swoole 的队列消费、协程任务或 CLI（例如小游戏 code2session 在异步任务里
     * 落库）没有请求上下文，会抛异常并连带回滚整个绑定事务。
     */
    protected function clientIp(): string
    {
        try {
            if (function_exists('request')) {
                return (string) request()->ip();
            }
        } catch (\Throwable) {
        }

        return '';
    }

    /**
     * 生成配置指纹（用于实例缓存键）
     *
     * 配置里若出现闭包（例如动态注入的解析器），serialize() 会抛异常，
     * 此处降级为固定值，宁可少缓存也不能让登录流程直接崩掉。
     *
     * @param  array $config
     * @return string
     */
    protected function configFingerprint(array $config): string
    {
        try {
            return md5(serialize($config));
        } catch (\Throwable) {
            return 'static';
        }
    }

    /**
     * 驱动是否真正实现了 PKCE
     *
     * 接口签名里有 code_challenge / code_verifier，但历史驱动只是"占位"未使用；
     * 只有显式声明 supportsPkce() 的驱动才走 PKCE，避免"开关打开了却没防护"。
     */
    protected function driverSupportsPkce(OAuthDriverInterface $driver): bool
    {
        return is_callable([$driver, 'supportsPkce'])
            && (bool) call_user_func([$driver, 'supportsPkce']);
    }

    /**
     * 序列化原始响应数据
     *
     * 保存为 JSON 字符串（而非数组）：模型的 `$json = ['raw_data']` 只在值为
     * 非标量时才编码，这里显式编码可保证只有一条编码路径，且能兜住非法 UTF-8
     * （上游偶发脏数据不会把整条绑定记录写空）。
     *
     * @param array $raw
     * @return string
     */
    protected function encodeRawData(array $raw): string
    {
        $json = json_encode(
            $raw,
            JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR
        );

        return is_string($json) ? $json : '{}';
    }
}
