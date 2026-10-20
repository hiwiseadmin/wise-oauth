<?php
declare(strict_types=1);

namespace wise\oauth;

use wise\support\context\ContextualLogger;
use RuntimeException;

/**
 * OAuth Token 加密器
 *
 * 对存储的 access_token / refresh_token 进行 AES-256-CBC 加密。
 * 加密密钥通过 SHA256 从配置密钥派生，确保固定 32 字节长度。
 *
 * 格式规范：
 * - 加密输出：`aes$` + base64(32B HMAC + 16B IV + ciphertext)
 * - 明文（加密关闭）/ 旧版 token：无前缀，直接返回原值
 *
 * 安全原则：
 * - encrypt() 失败时抛异常，禁止静默回退明文
 * - decrypt() 通过 `aes$` 前缀自动识别加密/明文数据，向下兼容
 * - 每次加密使用随机 IV，确保相同明文产生不同密文
 */
class OAuthTokenEncryptor
{
    /** @var string 加密算法 */
    protected string $cipher = 'AES-256-CBC';

    /** @var string 加密格式前缀 */
    protected const PREFIX = 'aes$';

    /** @var string 派生的加密密钥（固定 32 字节） */
    protected string $key;

    /** @var bool 是否已就绪（密钥派生成功） */
    protected bool $ready = false;

    public function __construct()
    {
        $configKey = config('wise-oauth.encrypt_key');
        $appKey = config('app.app_key', '');
        $rawKey = $configKey ?: $appKey;

        if (empty($rawKey)) {
            ContextualLogger::warning('[wise-oauth] 加密密钥未配置，Token 将以明文存储。请在 config/wise-oauth.php 中设置 encrypt_key');
            $this->ready = false;
            $this->key = '';
            return;
        }

        // 通过 SHA256 派生 32 字节密钥（兼容任意长度的原始密钥）
        $this->key = hash('sha256', $rawKey, true);
        $this->ready = true;
    }

    /**
     * 加密明文
     *
     * @param  string $plaintext 明文
     * @return string `aes$` + base64(HMAC + IV + ciphertext)
     *
     * @throws RuntimeException 加密失败时抛出（绝不静默回退明文）
     */
    public function encrypt(string $plaintext): string
    {
        if (empty($plaintext)) {
            return '';
        }

        if (!$this->ready) {
            throw new RuntimeException(
                '[wise-oauth] Token 加密密钥未配置，无法加密。请在 config/wise-oauth.php 中设置 encrypt_key'
            );
        }

        try {
            $ivLength = openssl_cipher_iv_length($this->cipher);
            $iv = random_bytes($ivLength);
            $encrypted = openssl_encrypt(
                $plaintext, $this->cipher, $this->key, OPENSSL_RAW_DATA, $iv
            );

            if ($encrypted === false) {
                throw new RuntimeException(
                    '[wise-oauth] Token 加密失败: ' . openssl_error_string()
                );
            }

            // 计算 HMAC-SHA256 认证标签（IV + ciphertext）
            $hmac = hash_hmac('sha256', $iv . $encrypted, $this->key, true);

            return self::PREFIX . base64_encode($hmac . $iv . $encrypted);
        } catch (RuntimeException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new RuntimeException(
                '[wise-oauth] Token 加密异常: ' . $e->getMessage(), 0, $e
            );
        }
    }

    /**
     * 解密密文
     *
     * 兼容策略：
     * - `aes$` 前缀 → 加密数据，正常解密
     * - 无前缀 → 旧版明文/未加密数据，直接返回原值（向下兼容）
     * - 解密失败 → 记录日志，返回空字符串
     *
     * @param  string $ciphertext 密文（可能是加密或明文）
     * @return string 明文
     */
    public function decrypt(string $ciphertext): string
    {
        if (empty($ciphertext)) {
            return '';
        }

        // 无 `aes$` 前缀 → 旧版未加密数据，直接返回（向下兼容）
        if (!str_starts_with($ciphertext, self::PREFIX)) {
            return $ciphertext;
        }

        // 剥离前缀
        $ciphertext = substr($ciphertext, strlen(self::PREFIX));

        if (!$this->ready) {
            ContextualLogger::warning('[wise-oauth] Token 解密密钥未配置，无法解密加密数据');
            return '';
        }

        try {
            $data = base64_decode($ciphertext, true);
            if ($data === false) {
                ContextualLogger::warning('[wise-oauth] Token 密文 base64 解码失败');
                return '';
            }

            $hmacLen = 32; // SHA256 = 32 bytes
            $ivLength = openssl_cipher_iv_length($this->cipher);
            $minLength = $hmacLen + $ivLength + 1;

            if (strlen($data) < $minLength) {
                ContextualLogger::warning('[wise-oauth] 密文长度异常，数据可能已损坏');
                return '';
            }

            // 分离 HMAC、IV、密文
            $hmac = substr($data, 0, $hmacLen);
            $iv = substr($data, $hmacLen, $ivLength);
            $encrypted = substr($data, $hmacLen + $ivLength);

            // 验证 HMAC 完整性
            $expectedHmac = hash_hmac('sha256', $iv . $encrypted, $this->key, true);
            if (!hash_equals($expectedHmac, $hmac)) {
                ContextualLogger::warning('[wise-oauth] Token 密文 HMAC 校验失败，数据可能被篡改');
                return '';
            }

            $decrypted = openssl_decrypt(
                $encrypted, $this->cipher, $this->key, OPENSSL_RAW_DATA, $iv
            );

            if ($decrypted === false) {
                ContextualLogger::error('[wise-oauth] Token 解密失败: ' . openssl_error_string());
                return '';
            }

            return $decrypted;
        } catch (\Throwable $e) {
            ContextualLogger::error('[wise-oauth] Token 解密异常: ' . $e->getMessage());
            return '';
        }
    }

    /**
     * 条件加密：根据配置决定是否加密
     *
     * @param  string $plaintext
     * @return string
     *
     * @throws RuntimeException 加密启用但加密失败时抛出
     */
    public function encryptIfEnabled(string $plaintext): string
    {
        // 空串直接返回：**空值不是机密**，没必要加密
        //
        // ⚠️ 这条短路很实际：`OAuthManager::createBinding()` 会无条件加密 `access_token`，
        // 而小游戏（`wechat_minigame`）走 code2session，**根本没有 access_token** ——
        // 原先空串也会进 `encrypt()`，一旦 `encrypt_key` 没配就抛 RuntimeException，
        // 把"没配密钥"变成一个**伪装的登录失败**（排查时只会看到"绑定失败"）。
        if ($plaintext === '') {
            return '';
        }

        if (config('wise-oauth.encrypt_tokens', true)) {
            return $this->encrypt($plaintext);
        }
        return $plaintext;
    }

    /**
     * 条件解密：根据配置决定是否解密
     *
     * @param  string $ciphertext
     * @return string
     */
    public function decryptIfEnabled(string $ciphertext): string
    {
        if (config('wise-oauth.encrypt_tokens', true)) {
            return $this->decrypt($ciphertext);
        }
        return $ciphertext;
    }
}
