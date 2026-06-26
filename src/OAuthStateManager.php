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

        Cache::set($this->prefix . $state, true, $ttl);

        return $state;
    }

    /**
     * 校验 state 令牌（一次性消费）
     *
     * @param  string $state 回调携带的 state
     * @return bool   是否有效
     */
    public function validate(string $state): bool
    {
        $key = $this->prefix . $state;
        $exists = Cache::get($key);

        if ($exists) {
            Cache::delete($key); // 一次性消费
            return true;
        }

        return false;
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
        Cache::set($this->prefix . $state, true, $ttl);
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
        Cache::delete($key); // 一次性消费
        return $verifier ?: null;
    }
}
