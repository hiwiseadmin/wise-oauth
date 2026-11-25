<?php
declare(strict_types=1);

namespace wise\oauth\tests\Unit;

use wise\oauth\entity\OAuthUserInfo;
use wise\oauth\tests\TestCase;

/**
 * OAuthUserInfo 值对象单元测试
 *
 * 测试 toArray / fromArray 的数据完整性。
 */
class OAuthUserInfoTest extends TestCase
{
    public function testCreateEmptyInfo(): void
    {
        $info = new OAuthUserInfo();
        $this->assertEquals('', $info->platform);
        $this->assertEquals('', $info->openid);
        $this->assertNull($info->unionId);
        $this->assertEquals('', $info->accessToken);
        $this->assertEmpty($info->raw);
    }

    public function testSetProperties(): void
    {
        $info = new OAuthUserInfo();
        $info->platform     = 'github';
        $info->openid       = '12345';
        $info->nickname     = 'test_user';
        $info->email        = 'test@example.com';
        $info->accessToken  = 'gho_token_abc';
        $info->unionId      = 'union_xxx';

        $this->assertEquals('github', $info->platform);
        $this->assertEquals('12345', $info->openid);
        $this->assertEquals('test_user', $info->nickname);
        $this->assertEquals('test@example.com', $info->email);
        $this->assertEquals('gho_token_abc', $info->accessToken);
        $this->assertEquals('union_xxx', $info->unionId);
    }

    public function testToArray(): void
    {
        $info = new OAuthUserInfo();
        $info->platform     = 'wechat_open';
        $info->openid       = 'wx_openid_123';
        $info->unionId      = 'wx_union_456';
        $info->nickname     = '微信用户';
        $info->avatar       = 'https://example.com/avatar.jpg';
        $info->accessToken  = 'token_abc';
        $info->refreshToken = 'refresh_xyz';
        $info->expiresIn    = 7200;
        $info->raw          = ['key' => 'value'];

        $array = $info->toArray();

        $this->assertEquals('wechat_open', $array['platform']);
        $this->assertEquals('wx_openid_123', $array['openid']);
        $this->assertEquals('wx_union_456', $array['union_id']);
        $this->assertEquals('微信用户', $array['nickname']);
        $this->assertEquals('https://example.com/avatar.jpg', $array['avatar']);
        $this->assertEquals('token_abc', $array['access_token']);
        $this->assertEquals('refresh_xyz', $array['refresh_token']);
        $this->assertEquals(7200, $array['expires_in']);
        $this->assertEquals(['key' => 'value'], $array['raw']);
    }

    public function testFromArray(): void
    {
        $data = [
            'platform'      => 'google',
            'openid'        => 'google_sub_789',
            'union_id'      => null,
            'nickname'      => 'Google User',
            'avatar'        => 'https://pic.google.com/photo.jpg',
            'email'         => 'google@example.com',
            'access_token'  => 'ya29_token',
            'refresh_token' => 'refresh_token',
            'expires_in'    => 3600,
            'raw'           => ['sub' => 'google_sub_789'],
        ];

        $info = OAuthUserInfo::fromArray($data);

        $this->assertEquals('google', $info->platform);
        $this->assertEquals('google_sub_789', $info->openid);
        $this->assertNull($info->unionId);
        $this->assertEquals('Google User', $info->nickname);
        $this->assertEquals('https://pic.google.com/photo.jpg', $info->avatar);
        $this->assertEquals('google@example.com', $info->email);
        $this->assertEquals('ya29_token', $info->accessToken);
        $this->assertEquals('refresh_token', $info->refreshToken);
        $this->assertEquals(3600, $info->expiresIn);
        $this->assertEquals(['sub' => 'google_sub_789'], $info->raw);
    }

    public function testFromArrayWithPartialData(): void
    {
        $data = [
            'platform'     => 'qq',
            'openid'       => 'qq_openid',
            'access_token' => 'qq_token',
        ];

        $info = OAuthUserInfo::fromArray($data);

        $this->assertEquals('qq', $info->platform);
        $this->assertEquals('qq_openid', $info->openid);
        $this->assertNull($info->nickname);
        $this->assertNull($info->email);
        $this->assertEquals('qq_token', $info->accessToken);
        $this->assertNull($info->refreshToken);
    }

    public function testToArrayFromArrayRoundTrip(): void
    {
        $original = [
            'platform'      => 'github',
            'openid'        => 'gh_12345',
            'union_id'      => null,
            'nickname'      => 'dev_user',
            'avatar'        => 'https://avatars.githubusercontent.com/u/12345',
            'email'         => 'dev@github.com',
            'mobile'        => null,
            'gender'        => null,
            'access_token'  => 'gho_abcdef',
            'refresh_token' => null,
            'expires_in'    => null,
            'raw'           => ['login' => 'dev_user', 'id' => 12345],
        ];

        $info = OAuthUserInfo::fromArray($original);
        $restored = $info->toArray();

        $this->assertEquals($original, $restored);
    }
}
