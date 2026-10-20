<?php
declare(strict_types=1);

namespace wise\oauth\config;

use wise\support\config\CheckLevel;
use wise\support\config\CheckResult;
use wise\support\config\ConfigCheckInterface;

/**
 * wise-oauth 平台密钥检测
 *
 * 检测已启用的 OAuth 平台是否配置了必需的 app_secret/client_secret。
 */
class OAuthSecretCheck implements ConfigCheckInterface
{
    /** @var array<string, array{idField: string, secretField: string, secretEnv: string}> */
    private const PLATFORM_KEYS = [
        'wechat_open' => ['idField' => 'app_id',      'secretField' => 'app_secret',     'secretEnv' => 'WECHAT_OPEN_APP_SECRET'],
        'wechat_mp'   => ['idField' => 'app_id',      'secretField' => 'app_secret',     'secretEnv' => 'WECHAT_MP_APP_SECRET'],
        'qq'          => ['idField' => 'app_id',      'secretField' => 'app_secret',     'secretEnv' => 'QQ_APP_SECRET'],
        'github'      => ['idField' => 'client_id',   'secretField' => 'client_secret',  'secretEnv' => 'GITHUB_CLIENT_SECRET'],
        'dingtalk'    => ['idField' => 'app_key',     'secretField' => 'app_secret',     'secretEnv' => 'DINGTALK_APP_SECRET'],
        'gitee'       => ['idField' => 'client_id',   'secretField' => 'client_secret',  'secretEnv' => 'GITEE_CLIENT_SECRET'],
        'google'      => ['idField' => 'client_id',   'secretField' => 'client_secret',  'secretEnv' => 'GOOGLE_CLIENT_SECRET'],
        'weibo'       => ['idField' => 'app_key',     'secretField' => 'app_secret',     'secretEnv' => 'WEIBO_APP_SECRET'],
    ];

    public function __construct(
        private readonly \think\Config $config,
    ) {
    }

    public function id(): string
    {
        return 'wise-oauth:secret';
    }

    public function package(): string
    {
        return 'wise-oauth';
    }

    public function level(): CheckLevel
    {
        return CheckLevel::ERROR;
    }

    public function check(): CheckResult
    {
        $providers = (array) $this->config->get('wise-oauth.platforms', []);
        $warnings = [];

        foreach (self::PLATFORM_KEYS as $platform => $spec) {
            $cfg = $providers[$platform] ?? [];

            // 未启用的平台跳过检测
            if (!($cfg['enabled'] ?? false)) {
                continue;
            }

            $id = (string) ($cfg[$spec['idField']] ?? '');
            $secret = (string) ($cfg[$spec['secretField']] ?? '');

            if ($secret === '') {
                $warnings[] = "$platform 已启用但缺少 {$spec['secretEnv']}";
            } elseif ($id === '') {
                $warnings[] = "$platform App ID 未配置";
            }
        }

        if (!empty($warnings)) {
            return CheckResult::fail(
                'OAuth 平台密钥缺失: ' . implode('; ', $warnings),
                '请在 .env 中设置对应平台的 APP_SECRET / CLIENT_SECRET'
            );
        }

        return CheckResult::ok();
    }
}
