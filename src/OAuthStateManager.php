<?php
declare(strict_types=1);

namespace wise\oauth;

use think\facade\Cache;

/**
 * OAuth State 管理器
 *
 * 生成并校验 state 参数，防止 CSRF 攻击。
 *
 * 工作原理：
 * 1. 生成随机 state，存入缓存（TTL 默认 600 秒）
 * 2. 回调时校验 state 是否在缓存中存在
 * 3. 校验成功后立即删除（一次性消费），防止重放攻击
 *
 * PKCE 扩展（可选）：
 * 生成 code_verifier + code_challenge，state 关联 verifier，
 * 回调时用 verifier 校验 challenge。
 */
class OAuthStateManager
{
    /** @var string 缓存键前缀 */
    protected string $prefix = 'oauth:state:';

    /** @var string PKCE 缓存键前缀 */
    protected string $pkcePrefix = 'oauth:pkce:';

    /**
     * 生成 state 令牌
     *
     * @return string 32 字节随机十六进制字符串
     */
    public function generate(): string
    {
        $state = bin2hex(random_bytes(32));
        $ttl = (int) config('wise-oauth.state_ttl', 600);

        Cache::set($this->prefix . $state, $this->sessionFingerprint(), $ttl);

        return $state;
    }

    /**
     * 校验 state 令牌（一次性消费 + 会话绑定）
     *
     * @param  string $state 回调携带的 state
     * @return bool   是否有效
     */
    public function validate(string $state): bool
    {
        if ($state === '') {
            return false;
        }

        $key    = $this->prefix . $state;
        $stored = Cache::get($key);

        if ($stored !== null) {
            Cache::delete($key);
        }

        if ($stored === null) {
            return false;
        }

        return hash_equals((string) $stored, $this->sessionFingerprint());
    }

    /**
     * 浏览器指纹：把 state 绑定到发起授权的浏览器
     *
     * 不能用原生 session：ThinkPHP 的 session 走 think\session\Store 自定义驱动，
     * 进程内从不调用 session_start()，`session_status()` 恒为 PHP_SESSION_NONE，
     * 原实现永远返回空串 —— 等于没有绑定（login CSRF 防护失效）。Swoole 常驻下
     * session_id() 还是进程级全局状态，协程并发时会读到其他请求的 id。
     *
     * 这里使用「UA + Accept-Language」做弱绑定：两个阶段必然一致，且不随网络
     * 切换（IP 变化）而失效。需要更强绑定（例如多设备共用同一指纹的场景）时，
     * 应在 generate() 里下发首方 HttpOnly Cookie 并在本方法内改为读取该 Cookie。
     *
     * @return string 指纹哈希；无法获取请求上下文时返回空串
     */
    protected function sessionFingerprint(): string
    {
        if (!function_exists('request')) {
            return '';
        }

        try {
            $request = request();
            if (!is_object($request) || !method_exists($request, 'header')) {
                return '';
            }

            return hash('sha256', (string) $request->header('user-agent', '')
                . '|' . (string) $request->header('accept-language', ''));
        } catch (\Throwable) {
            return '';
        }
    }

    /**
     * 生成 PKCE 增强的 state 令牌
     *
     * 返回 code_verifier 和 code_challenge，驱动需将 challenge 附加到授权 URL。
     *
     * @return array ['state' => '...', 'code_verifier' => '...', 'code_challenge' => '...']
     */
    public function generateWithPkce(): array
    {
        $state        = bin2hex(random_bytes(32));
        $codeVerifier = bin2hex(random_bytes(64));
        $codeChallenge = rtrim(
            strtr(
                base64_encode(hash('sha256', $codeVerifier, true)),
                '+/',
                '-_'
            ),
            '='
        );

        $ttl = (int) config('wise-oauth.state_ttl', 600);
        Cache::set($this->prefix . $state, $this->sessionFingerprint(), $ttl);
        Cache::set($this->pkcePrefix . $state, $codeVerifier, $ttl);

        return [
            'state'          => $state,
            'code_verifier'  => $codeVerifier,
            'code_challenge' => $codeChallenge,
        ];
    }

    /**
     * 获取 PKCE code_verifier
     *
     * @param  string $state
     * @return string|null
     */
    public function getCodeVerifier(string $state): ?string
    {
        $key = $this->pkcePrefix . $state;
        $verifier = Cache::get($key);
        Cache::delete($key);
        return $verifier ?: null;
    }
}
