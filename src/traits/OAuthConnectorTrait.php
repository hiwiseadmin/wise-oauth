<?php
declare(strict_types=1);

namespace wise\oauth\traits;

use wise\support\connector\ConnectorResult;
use wise\support\connector\ConnectorType;

/**
 * OAuth 连接器默认实现 Trait
 *
 * 为 OAuth 平台驱动（继承 AbstractDriver、实现 OAuthConnectorInterface）补齐
 * {@see \wise\support\connector\ConnectorInterface} 的通用方法，使其可直接注册到
 * `ExtPoints::EXTERNAL_CONNECTOR`，由 ConnectorManager 统一发现 / 健康检查 / 配置。
 *
 * 领域方法（getPlatform / getPlatformName / getAuthUrl / getUser / refreshToken）
 * 仍由驱动自身实现；本 trait 负责把它们映射到连接器的 execute() 动态入口。
 *
 * @package wise\oauth\traits
 */
trait OAuthConnectorTrait
{
    public function getId(): string
    {
        return $this->getPlatform();
    }

    public function getName(): string
    {
        return $this->getPlatformName();
    }

    public function getType(): ConnectorType
    {
        return ConnectorType::OAUTH;
    }

    public function getDescription(): string
    {
        return sprintf('OAuth 授权登录平台（%s）', $this->getPlatform());
    }

    /**
     * 能力自描述（供管理后台 / AI 发现）
     *
     * @return array<string, array>
     */
    public function getActions(): array
    {
        return [
            'auth_url'      => ['description' => '生成授权跳转 URL', 'params' => ['state', 'redirect_uri', 'code_challenge', 'code_challenge_method']],
            'get_user'      => ['description' => '授权码换取用户信息', 'params' => ['code', 'state', 'redirect_uri', 'code_verifier']],
            'refresh_token' => ['description' => '刷新 Access Token', 'params' => ['refresh_token']],
        ];
    }

    /**
     * 动态分发：把 action 路由到强类型方法
     */
    public function execute(string $action, array $input, array $context = []): ConnectorResult
    {
        try {
            return match ($action) {
                'auth_url' => ConnectorResult::ok($this->getAuthUrl(
                    (string) ($input['state'] ?? ''),
                    $input['redirect_uri'] ?? null,
                    $input['code_challenge'] ?? null,
                    $input['code_challenge_method'] ?? null
                )),
                'get_user' => ConnectorResult::ok($this->getUser(
                    (string) ($input['code'] ?? ''),
                    $input['state'] ?? null,
                    $input['redirect_uri'] ?? null,
                    $input['code_verifier'] ?? null
                )),
                'refresh_token' => ConnectorResult::ok($this->refreshToken((string) ($input['refresh_token'] ?? ''))),
                default         => ConnectorResult::fail(
                    sprintf('OAuth 连接器 [%s] 不支持操作 [%s]', $this->getPlatform(), $action),
                    'UNSUPPORTED_ACTION'
                ),
            };
        } catch (\Throwable $e) {
            return ConnectorResult::fail($e->getMessage(), 'OAUTH_ERROR');
        }
    }

    /**
     * 健康检查：默认视为可用（平台不可达时由调用方经熔断处理）
     */
    public function healthCheck(): bool
    {
        return true;
    }

    /**
     * 配置 Schema（供管理后台渲染）
     *
     * @return array<int, array>
     */
    public function getConfigSchema(): array
    {
        return [
            ['key' => 'client_id', 'type' => 'text', 'label' => 'Client ID / AppId', 'required' => true],
            ['key' => 'client_secret', 'type' => 'password', 'label' => 'Client Secret / AppSecret', 'required' => true],
            ['key' => 'redirect_uri', 'type' => 'text', 'label' => '回调地址', 'required' => false],
        ];
    }

    /**
     * 注入配置（合并进驱动自身配置）
     */
    public function setConfig(array $config): void
    {
        $this->config = array_merge($this->config, $config);
    }

    public function getConfig(): array
    {
        return $this->config;
    }
}
