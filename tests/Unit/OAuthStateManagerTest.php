<?php
declare(strict_types=1);

namespace wise\oauth\tests\Unit;

use wise\oauth\OAuthStateManager;
use wise\oauth\tests\TestCase;

/**
 * OAuthStateManager 单元测试
 *
 * 测试 CSRF state 生成、校验、一次性消费机制以及 PKCE 扩展。
 */
class OAuthStateManagerTest extends TestCase
{
    protected OAuthStateManager $manager;

    protected function setUp(): void
    {
        parent::setUp();
        $this->manager = new OAuthStateManager();
    }

    // ==================== State 生成 ====================

    public function testGenerateReturnsString(): void
    {
        $state = $this->manager->generate();
        $this->assertIsString($state);
        $this->assertNotEmpty($state);
    }

    public function testGenerateReturnsHexString(): void
    {
        $state = $this->manager->generate();
        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $state);
    }

    public function testGenerateReturns64CharacterString(): void
    {
        // 32 bytes = 64 hex chars
        $state = $this->manager->generate();
        $this->assertEquals(64, strlen($state));
    }

    public function testGenerateReturnsUniqueValues(): void
    {
        $states = [];
        for ($i = 0; $i < 10; $i++) {
            $states[] = $this->manager->generate();
        }
        $this->assertCount(10, array_unique($states));
    }

    // ==================== State 校验 ====================

    public function testValidateReturnsFalseForInvalidState(): void
    {
        $result = $this->manager->validate('non_existent_state');
        $this->assertFalse($result);
    }

    public function testValidateReturnsFalseForEmptyState(): void
    {
        $result = $this->manager->validate('');
        $this->assertFalse($result);
    }

    // ==================== PKCE 扩展 ====================

    public function testGenerateWithPkceReturnsRequiredKeys(): void
    {
        $pkce = $this->manager->generateWithPkce();
        $this->assertArrayHasKey('state', $pkce);
        $this->assertArrayHasKey('code_verifier', $pkce);
        $this->assertArrayHasKey('code_challenge', $pkce);
    }

    public function testPkceStateIsHexString(): void
    {
        $pkce = $this->manager->generateWithPkce();
        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $pkce['state']);
        $this->assertEquals(64, strlen($pkce['state']));
    }

    public function testPkceCodeVerifierIs128HexChars(): void
    {
        // 64 bytes = 128 hex chars
        $pkce = $this->manager->generateWithPkce();
        $this->assertEquals(128, strlen($pkce['code_verifier']));
    }

    public function testPkceCodeChallengeIsBase64Url(): void
    {
        $pkce = $this->manager->generateWithPkce();
        $this->assertNotEmpty($pkce['code_challenge']);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9\-_]+$/', $pkce['code_challenge']);
    }

    public function testGetCodeVerifierReturnsCorrectValue(): void
    {
        $pkce = $this->manager->generateWithPkce();
        $verifier = $this->manager->getCodeVerifier($pkce['state']);
        $this->assertEquals($pkce['code_verifier'], $verifier);
    }

    public function testGetCodeVerifierReturnsNullForInvalidState(): void
    {
        $verifier = $this->manager->getCodeVerifier('invalid_state');
        $this->assertNull($verifier);
    }

    // ==================== 一次性消费 / 会话绑定 回归 ====================

    public function testValidateReturnsTrueForGeneratedState(): void
    {
        $state = $this->manager->generate();

        $this->assertTrue($this->manager->validate($state));
    }

    public function testValidateConsumesStateOnlyOnce(): void
    {
        $state = $this->manager->generate();

        $this->assertTrue($this->manager->validate($state));
        // 第二次必须失败：state 是一次性令牌，防止重放
        $this->assertFalse($this->manager->validate($state));
    }

    public function testPkceStateCanBeValidatedAndConsumedOnce(): void
    {
        $pkce = $this->manager->generateWithPkce();

        $this->assertTrue($this->manager->validate($pkce['state']));
        $this->assertFalse($this->manager->validate($pkce['state']));
    }

    public function testValidateRejectsStateBoundToAnotherSession(): void
    {
        // 模拟攻击者：把 state 写入缓存，但绑定的是"攻击者会话"的指纹，
        // 受害者在自己的会话中回放该 state 时必须校验失败（login CSRF 防护）
        $state = bin2hex(random_bytes(32));
        \think\facade\Cache::set(
            'oauth:state:' . $state,
            hash('sha256', 'attacker-session-id'),
            600
        );

        $this->assertFalse(
            $this->manager->validate($state),
            'state 必须绑定发起授权的会话，跨会话校验应失败'
        );
    }
}
