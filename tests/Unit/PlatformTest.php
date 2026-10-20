<?php
declare(strict_types=1);

namespace wise\oauth\tests\Unit;

use wise\oauth\enums\Platform;
use wise\oauth\tests\TestCase;

/**
 * Platform 枚举单元测试
 */
class PlatformTest extends TestCase
{
    public function testLabelsReturnsArray(): void
    {
        $labels = Platform::labels();
        $this->assertIsArray($labels);
        $this->assertNotEmpty($labels);
    }

    public function testLabelsContainsAllPlatforms(): void
    {
        $labels = Platform::labels();
        // 微信开放/公众号/小游戏 + QQ + GitHub + 钉钉 + 码云 + Google + 微博
        $this->assertCount(9, $labels);
    }

    public function testKnownPlatformsReturnCorrectLabel(): void
    {
        $this->assertEquals('微信开放平台', Platform::label(Platform::WECHAT_OPEN));
        $this->assertEquals('微信公众号', Platform::label(Platform::WECHAT_MP));
        $this->assertEquals('微信小游戏', Platform::label(Platform::WECHAT_MINIGAME));
        $this->assertEquals('QQ', Platform::label(Platform::QQ));
        $this->assertEquals('GitHub', Platform::label(Platform::GITHUB));
        $this->assertEquals('钉钉', Platform::label(Platform::DINGTALK));
        $this->assertEquals('码云', Platform::label(Platform::GITEE));
        $this->assertEquals('Google', Platform::label(Platform::GOOGLE));
        $this->assertEquals('微博', Platform::label(Platform::WEIBO));
    }

    public function testUnknownPlatformReturnsOriginalString(): void
    {
        $this->assertEquals('unknown_platform', Platform::label('unknown_platform'));
    }

    public function testIsKnownReturnsTrueForKnownPlatforms(): void
    {
        $this->assertTrue(Platform::isKnown(Platform::GITHUB));
        $this->assertTrue(Platform::isKnown(Platform::WECHAT_OPEN));
        $this->assertTrue(Platform::isKnown(Platform::QQ));
    }

    public function testIsKnownReturnsFalseForUnknownPlatforms(): void
    {
        $this->assertFalse(Platform::isKnown('unknown'));
        $this->assertFalse(Platform::isKnown('custom_oauth'));
    }

    public function testAllConstantsAreUnique(): void
    {
        $constants = [
            Platform::WECHAT_OPEN,
            Platform::WECHAT_MP,
            Platform::WECHAT_MINIGAME,
            Platform::QQ,
            Platform::GITHUB,
            Platform::DINGTALK,
            Platform::GITEE,
            Platform::GOOGLE,
            Platform::WEIBO,
        ];

        $this->assertCount(9, array_unique($constants));
    }
}
