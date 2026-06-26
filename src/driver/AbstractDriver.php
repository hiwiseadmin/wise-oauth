<?php
declare(strict_types=1);

namespace wise\oauth\driver;

use wise\oauth\contract\OAuthDriverInterface;
use wise\oauth\exception\OAuthException;
use wise\oauth\service\HttpClient;

/**
 * OAuth 驱动抽象基类
 *
 * 提供通用的 HTTP 客户端、配置访问、回调地址处理等能力。
 * 所有平台驱动继承此类，只需实现协议相关的具体逻辑。
 *
 * 子类需实现：
 * - getPlatform()、getPlatformName()、getDefaultScopes()
 * - getAuthUrl()、getUser()、refreshToken()
 */
abstract class AbstractDriver implements OAuthDriverInterface
{
    /** @var array 平台配置 */
    protected array $config;

    /** @var HttpClient HTTP 客户端 */
    protected HttpClient $httpClient;

    /**
     * @param array          $config     平台配置（从 wise-oauth.php platforms.{platform} 节点）
     * @param HttpClient|null $httpClient 可选的自定义 HTTP 客户端
     */
    public function __construct(array $config = [], ?HttpClient $httpClient = null)
    {
        $this->config = array_merge([
            'client_id'     => '',
            'client_secret' => '',
            'app_id'        => '',
            'app_secret'    => '',
            'app_key'       => '',
            'redirect_uri'  => '',
            'scopes'        => $this->getDefaultScopes(),
        ], $config);

        $this->httpClient = $httpClient ?? new HttpClient();
    }

    // ==================== 辅助方法 ====================

    /**
     * 获取配置中的 App ID
     *
     * @return string
     */
    protected function getAppId(): string
    {
        return $this->config['app_id'] ?: $this->config['client_id'] ?: $this->config['app_key'] ?: '';
    }

    /**
     * 获取配置中的 App Secret
     *
     * @return string
     */
    protected function getAppSecret(): string
    {
        return $this->config['app_secret'] ?: $this->config['client_secret'] ?: '';
    }

    /**
     * 获取配置中的回调地址，支持运行时覆盖
     *
     * @param  string|null $redirectUri
     * @return string
     */
    protected function getRedirectUri(?string $redirectUri = null): string
    {
        $uri = $redirectUri ?? $this->config['redirect_uri'] ?? '';

        if (empty($uri)) {
            throw new OAuthException(
                "OAuth 回调地址未配置，请在 wise-oauth.php 中设置 platforms.{$this->getPlatform()}.redirect_uri"
            );
        }

        return $uri;
    }

    /**
     * 发送 HTTP GET 请求并解析 JSON
     *
     * @param  string $url
     * @param  array  $headers
     * @param  array  $query
     * @return array
     */
    protected function httpGet(string $url, array $headers = [], array $query = []): array
    {
        return $this->httpClient->get($url, $headers, $query);
    }

    /**
     * 发送 HTTP POST 请求并解析 JSON
     *
     * @param  string $url
     * @param  array  $data
     * @param  array  $headers
     * @return array
     */
    protected function httpPost(string $url, array $data = [], array $headers = []): array
    {
        return $this->httpClient->post($url, $data, $headers);
    }

    /**
     * 发送 HTTP POST 请求并返回原始响应
     *
     * @param  string $url
     * @param  array  $data
     * @param  array  $headers
     * @return string
     */
    protected function httpPostRaw(string $url, array $data = [], array $headers = []): string
    {
        return $this->httpClient->postRaw($url, $data, $headers);
    }

    // ==================== Token 刷新默认实现 ====================

    /**
     * 默认 Token 刷新（返回空数组，表示该平台不支持刷新）
     *
     * @param  string $refreshToken
     * @return array
     */
    public function refreshToken(string $refreshToken): array
    {
        return [];
    }
}
