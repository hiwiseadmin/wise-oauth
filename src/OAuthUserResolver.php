<?php
declare(strict_types=1);

namespace wise\oauth;

use wise\support\context\ContextualLogger;
use think\Model;
use wise\oauth\entity\OAuthUserInfo;
use wise\oauth\enums\Platform;
use wise\oauth\exception\OAuthBindingException;
use wise\oauth\exception\OAuthException;
use wise\oauth\model\OAuthUserModel;

/**
 * OAuth 用户解析器
 *
 * 核心职责：将 OAuth 用户信息映射到本地用户。
 *
 * 查找策略（由具体到模糊）：
 * 1. union_id + 平台 → 已有绑定
 * 2. openid + 平台 → 已有绑定
 * 3. email 匹配（可选，需配置启用）
 * 4. mobile 匹配（可选，需配置启用）
 * 5. 自动创建新用户（需配置启用）
 *
 * 支持 Admin 和 Member 两种用户体系。
 */
class OAuthUserResolver
{
    /**
     * 通过 OAuth 标识查找已有绑定
     *
     * 优先 UnionID，其次 OpenID + Platform。
     *
     * @param  string      $openid   平台用户标识
     * @param  string      $platform 平台标识
     * @param  string|null $unionId  跨应用统一 ID
     * @return OAuthUserModel|null
     */
    public function findBindingByOAuth(string $openid, string $platform, ?string $unionId): ?OAuthUserModel
    {
        // 优先通过 union_id 查找（跨应用匹配）
        if ($unionId) {
            $binding = OAuthUserModel::where('platform', $platform)
                ->where('union_id', $unionId)
                ->find();
            if ($binding) {
                return $binding;
            }
        }

        // 通过 openid + platform 查找
        return OAuthUserModel::where('platform', $platform)
            ->where('openid', $openid)
            ->find();
    }

    /**
     * 根据绑定记录加载本地用户
     *
     * @param  OAuthUserModel $binding
     * @return Model|null
     */
    public function resolveLocalUser(OAuthUserModel $binding): ?Model
    {
        $userModelClass = $this->getUserModelClass($binding->getAttr('user_type') ?: '');
        return $userModelClass::find($binding->getAttr('user_id'));
    }

    /**
     * 根据用户 ID 和类型加载本地用户
     *
     * @param  int    $userId
     * @param  string $userType
     * @return Model|null
     */
    public function resolveLocalUserById(int $userId, string $userType): ?Model
    {
        $userModelClass = $this->getUserModelClass($userType);
        return $userModelClass::find($userId);
    }

    /**
     * 通过邮箱查找本地用户
     *
     * @param  string $email
     * @param  string $userType
     * @return Model|null
     */
    public function findByEmail(string $email, string $userType): ?Model
    {
        if (empty($email)) {
            return null;
        }

        $userModelClass = $this->getUserModelClass($userType);

        // 检查模型是否有 email 字段
        try {
            return $userModelClass::where('email', $email)->find();
        } catch (\think\db\exception\DbException $e) {
            ContextualLogger::error("[wise-oauth] 邮箱查找用户失败: {$e->getMessage()}");
            return null;
        }
    }

    /**
     * 通过手机号查找本地用户
     *
     * @param  string $mobile
     * @param  string $userType
     * @return Model|null
     */
    public function findByMobile(string $mobile, string $userType): ?Model
    {
        if (empty($mobile)) {
            return null;
        }

        $userModelClass = $this->getUserModelClass($userType);

        try {
            return $userModelClass::where('mobile', $mobile)->find();
        } catch (\think\db\exception\DbException $e) {
            ContextualLogger::error("[wise-oauth] 手机号查找用户失败: {$e->getMessage()}");
            return null;
        }
    }

    /**
     * 创建本地用户（OAuth 自动注册）
     *
     * @param  OAuthUserInfo $info     OAuth 用户信息
     * @param  string        $userType 用户类型 admin/member
     * @return Model
     */
    public function createLocalUser(OAuthUserInfo $info, string $userType): Model
    {
        if ($userType === 'admin') {
            return $this->createAdmin($info);
        }

        return $this->createMember($info);
    }

    /**
     * 确保用户有至少一种登录方式
     *
     * Admin 有密码登录兜底 → 允许解绑任意平台。
     * Member 需至少有一个其他绑定或已设置密码。
     *
     * @param  int    $userId            本地用户 ID
     * @param  string $userType          用户类型
     * @param  string $unbindingPlatform 正在解绑的平台
     * @return void
     *
     * @throws OAuthBindingException 解绑后将无法登录
     */
    public function ensureLoginMethod(int $userId, string $userType, string $unbindingPlatform): void
    {
        // Admin 有密码登录兜底 → 永远允许解绑
        if ($userType === 'admin') {
            return;
        }

        // Member：检查是否还有其他绑定或密码
        $bindingCount = OAuthUserModel::where('user_type', $userType)
            ->where('user_id', $userId)
            ->where('platform', '<>', $unbindingPlatform)
            ->count();

        if ($bindingCount === 0) {
            $userModelClass = $this->getUserModelClass($userType);
            $user = $userModelClass::find($userId);

            $hasPassword = false;
            if ($user && method_exists($user, 'getData')) {
                $hasPassword = !empty($user->getData('password'));
            }

            if (!$hasPassword) {
                throw new OAuthBindingException(
                    '解绑后将无法登录，请先设置密码或绑定其他平台',
                    0,
                    null,
                    $unbindingPlatform
                );
            }
        }
    }

    // ============================================================
    // 内部方法
    // ============================================================

    /**
     * 获取用户模型类 FQCN
     *
     * @param  string $userType
     * @return string
     * @throws OAuthException 不支持的用户类型
     */
    protected function getUserModelClass(string $userType): string
    {
        $models = config('wise-oauth.user_models', [
            'admin'  => \app\admin\model\Admin::class,
            'member' => \wise\member\model\Member::class,
        ]);

        $class = $models[$userType] ?? null;

        if (!is_string($class) || $class === '') {
            throw new OAuthException("不支持的用户类型：{$userType}");
        }

        // 提供该模型的包可能未安装（如 wise-member 被卸载）：必须在**实例化之前**
        // 抛出业务异常 —— 否则 $class::find() / new $class 会直接致命错误。
        // 配置里的 `::class` 只是字符串常量，不会触发自动加载，故这里必须显式校验。
        if (!class_exists($class)) {
            throw new OAuthException(
                "用户类型 {$userType} 对应的模型不可用（提供该模型的包可能未安装）：{$class}"
            );
        }

        return $class;
    }

    /**
     * 创建 Admin 用户
     *
     * @param  OAuthUserInfo $info
     * @return Model
     */
    protected function createAdmin(OAuthUserInfo $info): Model
    {
        $adminClass = $this->getUserModelClass('admin');

        // 生成唯一用户名：平台前缀 + openid hash
        $username = $this->generateUniqueUsername(
            $info->platform . '_' . substr(hash('sha256', $info->openid), 0, 10),
            $adminClass
        );

        /** @var Model $admin */
        $admin = new $adminClass();
        $admin->username = $username;
        if (method_exists($admin, 'setAttr')) {
            $admin->setAttr('password', ''); // OAuth 用户无密码
            $admin->setAttr('nickname', $info->nickname ?: $username);
            // 第三方登录**没有**邮箱/手机号（小游戏 code2session 只有 openid/unionid）
            // → 统一写空串而不是 NULL：不依赖每个用户体系表的宽松度（`member` 可空，
            // 但 `admins` 等表未必），也让后台列表/导出少一堆 NULL 分支。
            $admin->setAttr('email', (string) ($info->email ?? ''));
            $admin->setAttr('mobile', (string) ($info->mobile ?? ''));
            $admin->setAttr('avatar', $info->avatar ?? '');
            $admin->setAttr('status', 1);
        }
        $admin->save();

        // 分配默认角色（如果 Admin 模型支持）
        $defaultRoles = config('wise-oauth.default_admin_roles', []);
        if (!empty($defaultRoles) && method_exists($admin, 'assignRole')) {
            $admin->assignRole($defaultRoles);
        }

        return $admin;
    }

    /**
     * 创建 Member 用户
     *
     * @param  OAuthUserInfo $info
     * @return Model
     */
    protected function createMember(OAuthUserInfo $info): Model
    {
        $memberClass = $this->getUserModelClass('member');

        $username = $this->generateUniqueUsername(
            $info->platform . '_' . substr(hash('sha256', $info->openid), 0, 10),
            $memberClass
        );

        /** @var Model $member */
        $member = new $memberClass();
        $member->username = $username;
        if (method_exists($member, 'setAttr')) {
            $member->setAttr('password', '');
            $member->setAttr('nickname', $info->nickname ?: $username);
            // 第三方登录**没有**邮箱/手机号（小游戏 code2session 只有 openid/unionid）
            // → 统一写空串而不是 NULL：不依赖数据库宽松度，也让后台列表/导出少一堆 NULL 分支。
            // （注：本项目 `member.email/mobile` 实际是**可空**的，写 NULL 不会报错；
            //  之前误判成"NOT NULL 导致 1048"，实测证伪 —— 真因见 `Member::$defaultSoftDelete`。）
            $member->setAttr('email', (string) ($info->email ?? ''));
            $member->setAttr('mobile', (string) ($info->mobile ?? ''));
            $member->setAttr('avatar', $info->avatar ?? '');
            $member->setAttr('status', 1);
        }
        $member->save();

        return $member;
    }

    /**
     * 生成唯一用户名
     *
     * @param  string $base       基础用户名
     * @param  string $modelClass 模型类 FQCN
     * @return string
     */
    protected function generateUniqueUsername(string $base, string $modelClass): string
    {
        // 清理非法字符，只保留字母数字和下划线
        $username = preg_replace('/[^a-zA-Z0-9_]/', '_', $base);
        $username = substr($username, 0, 50);

        // 处理重名：追加序号（最多尝试100次防止意外死循环）
        $counter     = 1;
        $original    = $username;
        $maxAttempts = 100;
        while ($modelClass::where('username', $username)->find()) {
            if ($counter > $maxAttempts) {
                throw new OAuthException(
                    "无法生成唯一用户名，已尝试 {$maxAttempts} 次，请检查用户名冲突"
                );
            }
            $username = $original . '_' . $counter;
            $counter++;
        }

        return $username;
    }
}
