<?php
declare(strict_types=1);

use think\migration\Migrator;
use think\migration\db\Column;

/**
 * 创建 OAuth 绑定表
 *
 * 使用多态关联模式（user_type + user_id），支持 Admin 和 Member 两种用户体系。
 * 同一平台同一用户唯一绑定，同一 OAuth 账号只能绑定一个本地用户。
 */
class CreateOauthUsersTable extends Migrator
{
    public function up(): void
    {
        $table = $this->table('oauth_users', [
            'engine'    => 'InnoDB',
            'collation' => 'utf8mb4_unicode_ci',
            'comment'   => 'OAuth绑定表',
        ]);

        $table
            ->addColumn(Column::string('user_type', 32)->setNull(false)->setComment('用户类型：admin / member'))
            ->addColumn(Column::integer('user_id')->setNull(false)->setSigned(false)->setComment('本地用户ID'))
            ->addColumn(Column::string('platform', 32)->setNull(false)->setComment('平台标识：wechat_open / qq / github / dingtalk'))
            ->addColumn(Column::string('openid', 128)->setNull(false)->setComment('平台用户唯一标识'))
            ->addColumn(Column::string('union_id', 128)->setNull(true)->setComment('跨应用统一ID（微信UnionID等）'))
            ->addColumn(Column::string('nickname', 100)->setNull(true)->setComment('第三方昵称'))
            ->addColumn(Column::string('avatar', 500)->setNull(true)->setComment('第三方头像URL'))
            ->addColumn(Column::string('email', 100)->setNull(true)->setComment('第三方邮箱'))
            ->addColumn(Column::string('mobile', 20)->setNull(true)->setComment('第三方手机号'))
            ->addColumn(Column::text('raw_data')->setNull(true)->setComment('原始响应数据JSON'))
            ->addColumn(Column::text('access_token')->setNull(true)->setComment('访问令牌AES加密'))
            ->addColumn(Column::text('refresh_token')->setNull(true)->setComment('刷新令牌AES加密'))
            ->addColumn(Column::dateTime('token_expires_at')->setNull(true)->setComment('Token过期时间'))
            ->addColumn(Column::dateTime('last_login_at')->setNull(true)->setComment('最后OAuth登录时间'))
            ->addColumn(Column::string('last_login_ip', 50)->setNull(true)->setComment('最后OAuth登录IP'))
            ->addColumn(Column::dateTime('create_time')->setNull(false)->setComment('首次绑定时间'))
            ->addColumn(Column::dateTime('update_time')->setNull(false)->setComment('更新时间'))
            ->addIndex(['user_type', 'user_id', 'platform'], ['unique' => true, 'name' => 'uk_user_platform'])
            ->addIndex(['platform', 'openid'], ['unique' => true, 'name' => 'uk_platform_openid'])
            ->addIndex(['user_type', 'user_id'], ['name' => 'idx_user_type_id'])
            ->addIndex(['union_id'], ['name' => 'idx_union_id'])
            ->create();
    }

    public function down(): void
    {
        if ($this->hasTable('oauth_users')) {
            $this->table('oauth_users')->drop()->save();
        }
    }
}
