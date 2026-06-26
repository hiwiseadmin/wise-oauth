<?php
declare(strict_types=1);

namespace wise\oauth;

use think\facade\Log;

/**
 * OAuth Token 加密器
 *
 * 对存储的 access_token / refresh_token 进行 AES-256-CBC 加密。
 * 加密密钥通过 HKDF-SHA256 从配置密钥派生，确保固定 32 字节长度。
 *
 * 设计原则：
 * - 落库必加密（除非显式关闭 encrypt_tokens）
 * - 每次加密使用随机 IV，确保相同明文产生不同密文
 * - 加密/解密失败记录日志，便于排障
 */
class OAuthTokenEncryptor
{
    /** @var string 加密算法 */
    protected string $cipher = 'AES-256-CBC';

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
            Log::warning('[wise-oauth] 加密密钥未配置，Token 将以明文存储。请在 config/wise-oauth.php 中设置 encrypt_key');
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
     * @return string HMAC + IV + ciphertext 的 Base64 编码
     */
    public function encrypt(string $plaintext): string
    {
        if (empty($plaintext)) {
            return '';
        }

        if (!$this->ready) {
            return $plaintext;
        }

        try {
            $ivLength = openssl_cipher_iv_length($this->cipher);
            $iv = random_bytes($ivLength);
            $encrypted = openssl_encrypt($plaintext, $this->cipher, $this->key, OPENSSL_RAW_DATA, $iv);

            if ($encrypted === false) {
                Log::error('[wise-oauth] Token 加密失败，将以明文存储');
                return $plaintext;
            }

            // 计算 HMAC-SHA256 认证标签（IV + ciphertext）
            $hmac = hash_hmac('sha256', $iv . $encrypted, $this->key, true);

            return base64_encode($hmac . $iv . $encrypted);
        } catch (\Throwable $e) {
            Log::error('[wise-oauth] Token 加密异常: ' . $e->getMessage());
            return $plaintext;
        }
    }

    /**
     * 解密密文
     *
     * @param  string $ciphertext Base64 编码的密文
     * @return string 明文，解密失败返回空字符串
     */
    public function decrypt(string $ciphertext): string
    {
        if (empty($ciphertext)) {
            return '';
        }

        if (!$this->ready) {
            return $ciphertext;
        }

        try {
            $data = base64_decode($ciphertext, true);
            if ($data === false) {
                return ''; // 非 base64 编码
            }

            $hmacLen = 32; // SHA256 = 32 bytes
            $ivLength = openssl_cipher_iv_length($this->cipher);
            $minLength = $hmacLen + $ivLength + 1;

            if (strlen($data) < $minLength) {
                Log::warning('[wise-oauth] 密文长度异常，可能为未加密的旧数据');
                return '';
            }

            // 分离 HMAC、IV、密文
            $hmac = substr($data, 0, $hmacLen);
            $iv = substr($data, $hmacLen, $ivLength);
            $encrypted = substr($data, $hmacLen + $ivLength);

            // 验证 HMAC 完整性
            $expectedHmac = hash_hmac('sha256', $iv . $encrypted, $this->key, true);
            if (!hash_equals($expectedHmac, $hmac)) {
                Log::warning('[wise-oauth] Token 密文 HMAC 校验失败，数据可能被篡改');
                return '';
            }

            $decrypted = openssl_decrypt($encrypted, $this->cipher, $this->key, OPENSSL_RAW_DATA, $iv);

            if ($decrypted === false) {
                Log::error('[wise-oauth] Token 解密失败');
                return '';
            }

            return $decrypted;
        } catch (\Throwable $e) {
            Log::error('[wise-oauth] Token 解密异常: ' . $e->getMessage());
            return '';
        }
    }

    /**
     * 条件加密：根据配置决定是否加密
     *
     * @param  string $plaintext
     * @return string
     */
    public function encryptIfEnabled(string $plaintext): string
    {
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
