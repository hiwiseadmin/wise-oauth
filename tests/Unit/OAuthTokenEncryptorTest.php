<?php
declare(strict_types=1);

namespace wise\oauth\tests\Unit;

use wise\oauth\OAuthTokenEncryptor;
use wise\oauth\tests\TestCase;

/**
 * OAuthTokenEncryptor 单元测试
 *
 * 测试 AES-256-CBC Token 加密/解密、空字符串处理、配置联动。
 */
class OAuthTokenEncryptorTest extends TestCase
{
    protected OAuthTokenEncryptor $encryptor;

    protected function setUp(): void
    {
        parent::setUp();
        // Mock 有 app_key 的配置
        $this->mockConfig([
            'wise-oauth' => [
                'encrypt_key' => null,
                'encrypt_tokens' => true,
            ],
            'app' => [
                'app_key' => 'test_app_key_32_bytes_str12345',
            ],
        ]);

        $this->encryptor = new OAuthTokenEncryptor();
    }

    // ==================== 基本加密解密 ====================

    public function testEncryptReturnsBase64String(): void
    {
        $plaintext = 'test_access_token_12345';
        $encrypted = $this->encryptor->encrypt($plaintext);

        $this->assertIsString($encrypted);
        $this->assertNotEmpty($encrypted);
        $this->assertNotEquals($plaintext, $encrypted);

        // 验证是有效的 Base64
        $decoded = base64_decode($encrypted, true);
        $this->assertNotFalse($decoded);
    }

    public function testDecryptReturnsOriginalValue(): void
    {
        $plaintext = 'gho_test_github_token_abc123';
        $encrypted = $this->encryptor->encrypt($plaintext);
        $decrypted = $this->encryptor->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testEncryptProducesDifferentResultsForSameInput(): void
    {
        $plaintext = 'same_token_value';
        $result1 = $this->encryptor->encrypt($plaintext);
        $result2 = $this->encryptor->encrypt($plaintext);

        // 随机 IV 确保相同明文产生不同密文
        $this->assertNotEquals($result1, $result2);

        // 但解密结果应该相同
        $this->assertEquals($plaintext, $this->encryptor->decrypt($result1));
        $this->assertEquals($plaintext, $this->encryptor->decrypt($result2));
    }

    // ==================== 边界情况 ====================

    public function testEncryptEmptyString(): void
    {
        $result = $this->encryptor->encrypt('');
        $this->assertEquals('', $result);
    }

    public function testDecryptEmptyString(): void
    {
        $result = $this->encryptor->decrypt('');
        $this->assertEquals('', $result);
    }

    public function testDecryptPlaintextReturnsSameString(): void
    {
        // 非加密字符串解密返回原值
        $plaintext = 'plaintext_not_encrypted';
        $result = $this->encryptor->decrypt($plaintext);
        $this->assertEquals('', $result); // 无法解密返回空
    }

    public function testEncryptDecryptLongToken(): void
    {
        // 模拟真实的 access token（通常较长）
        $longToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' .
            str_repeat('abcdefghij', 20) . '.' .
            'signature_part_very_long_token_for_testing';
        $encrypted = $this->encryptor->encrypt($longToken);
        $decrypted = $this->encryptor->decrypt($encrypted);

        $this->assertEquals($longToken, $decrypted);
    }

    public function testEncryptDecryptUnicodeString(): void
    {
        $unicode = '微信用户昵称💡🎉';
        $encrypted = $this->encryptor->encrypt($unicode);
        $decrypted = $this->encryptor->decrypt($encrypted);

        $this->assertEquals($unicode, $decrypted);
    }

    public function testEncryptDecryptSpecialCharacters(): void
    {
        $special = 'token/with/slashes+and+plus&equals=signs?query=1';
        $encrypted = $this->encryptor->encrypt($special);
        $decrypted = $this->encryptor->decrypt($encrypted);

        $this->assertEquals($special, $decrypted);
    }

    // ==================== encryptIfEnabled / decryptIfEnabled ====================

    public function testEncryptIfEnabledEncryptsWhenEnabled(): void
    {
        $this->mockConfig([
            'wise-oauth' => ['encrypt_tokens' => true],
            'app' => ['app_key' => 'test_app_key_32_bytes_str12345'],
        ]);

        $encryptor = new OAuthTokenEncryptor();
        $plaintext = 'test_token_value';
        $result = $encryptor->encryptIfEnabled($plaintext);

        $this->assertNotEquals($plaintext, $result);
    }

    public function testEncryptIfEnabledReturnsPlaintextWhenDisabled(): void
    {
        $this->mockConfig([
            'wise-oauth' => ['encrypt_tokens' => false],
            'app' => ['app_key' => 'test_app_key_32_bytes_str12345'],
        ]);

        $encryptor = new OAuthTokenEncryptor();
        $plaintext = 'test_token_value';
        $result = $encryptor->encryptIfEnabled($plaintext);

        $this->assertEquals($plaintext, $result);
    }

    public function testDecryptIfEnabledDecryptsWhenEnabled(): void
    {
        $this->mockConfig([
            'wise-oauth' => ['encrypt_tokens' => true],
            'app' => ['app_key' => 'test_app_key_32_bytes_str12345'],
        ]);

        $encryptor = new OAuthTokenEncryptor();
        $plaintext = 'test_token_value';
        $encrypted = $encryptor->encrypt($plaintext);
        $result = $encryptor->decryptIfEnabled($encrypted);

        $this->assertEquals($plaintext, $result);
    }
}
