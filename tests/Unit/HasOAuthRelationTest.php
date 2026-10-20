<?php
declare(strict_types=1);

namespace wise\oauth\tests\Unit;

use think\Model;
use think\model\relation\MorphMany;
use wise\oauth\model\OAuthUserModel;
use wise\oauth\tests\TestCase;
use wise\oauth\traits\HasOAuth;

/**
 * 探针模型：拦截 morphMany() 调用记录实参，避免测试依赖数据库
 */
class OAuthRelationProbe extends Model
{
    use HasOAuth;

    /** @var array{0: string, 1: mixed, 2: string} morphMany 实参 */
    public array $morphArgs = [];

    public function morphMany(string $model, string|array|null $morph = null, string $type = ''): MorphMany
    {
        $this->morphArgs = [$model, $morph, $type];

        return (new \ReflectionClass(MorphMany::class))->newInstanceWithoutConstructor();
    }

    public function getOAuthUserType(): string
    {
        return 'admin';
    }
}

/**
 * HasOAuth 多态关联参数回归测试
 *
 * 回归重点：morphMany() 的第 3 参是"多态类型值"（与 oauth_users.user_type 落库值一致），
 * 而不是字段名。旧写法传入 'user_type' 会生成
 * `WHERE user_id = ? AND user_type = 'user_type'`，导致绑定查询恒为空。
 */
class HasOAuthRelationTest extends TestCase
{
    public function testOauthBindingsPassesMorphTypeValue(): void
    {
        $probe = new OAuthRelationProbe();
        $probe->oauthBindings();

        [$model, $morph, $type] = $probe->morphArgs;

        $this->assertSame(OAuthUserModel::class, $model);
        $this->assertSame(['user_type', 'user_id'], $morph, '第 2 参应为多态字段定义');
        $this->assertSame(
            'admin',
            $type,
            '第 3 参必须是多态类型值（与 oauth_users.user_type 落库值一致），不能是字段名 user_type'
        );
    }
}
