<?php
declare(strict_types=1);

namespace wise\oauth\service;

use think\facade\Cache;
use wise\oauth\exception\OAuthException;
use wise\oauth\exception\ServiceUnavailableException;
use wise\support\circuit\CircuitBreaker;

/**
 * OAuth HTTP 客户端
 *
 * 简单封装 cURL / stream 的 HTTP GET/POST 请求。
 * 专为 OAuth 驱动设计：支持 JSON 响应解析、超时控制、错误处理。
 *
 * 不依赖第三方 HTTP 库，保持包的零外部依赖。
 */
class HttpClient
{
    /** @var int 默认超时（秒） */
    protected int $timeout = 10;

    /** @var int 默认连接超时（秒） */
    protected int $connectTimeout = 5;

    /** @var CircuitBreaker|null 断路器（可选，按 OAuth 平台维度隔离） */
    protected ?CircuitBreaker $breaker = null;

    /** @var array 断路器配置 */
    protected array $breakerConfig = [];

    /**
     * @param array $options 可选配置（breaker_service / breaker_config）
     */
    public function __construct(array $options = [])
    {
        if (empty($options['breaker_service'])) {
            return;
        }

        $this->breakerConfig = $options;
        $cfg = $options['breaker_config'] ?? [];

        // 熔断为可选能力：未显式开启时不构造，避免无谓的缓存依赖
        if (!($cfg['enabled'] ?? true)) {
            return;
        }

        // 缓存 store 可配置；默认使用应用默认 store，绝不硬编码 redis，
        // 否则未安装/未启动 Redis 的环境（包定位为"零外部依赖"）会在每个
        // OAuth 请求上抛缓存连接异常。
        $store = (string) ($cfg['store'] ?? '');

        try {
            $cache = $store !== '' ? Cache::store($store) : Cache::store();
        } catch (\Throwable $e) {
            // 缓存不可用时降级为"无熔断"，不阻断第三方登录主流程
            $this->breaker = null;
            return;
        }

        $this->breaker = new CircuitBreaker(
            $options['breaker_service'],
            $cache,
            [
                'failure_threshold' => $cfg['failure_threshold'] ?? 5,
                'timeout'           => $cfg['timeout'] ?? 30,
                'key_prefix'        => $cfg['key_prefix'] ?? 'wise_oauth:cb',
            ]
        );
    }

    /**
     * 发送 GET 请求并解析 JSON 响应
     *
     * @param  string $url     请求 URL
     * @param  array  $headers 请求头（key => value）
     * @param  array  $query   查询参数（自动拼接到 URL）
     * @return array  JSON 解析后的数组
     *
     * @throws \wise\oauth\exception\OAuthException
     */
    public function get(string $url, array $headers = [], array $query = []): array
    {
        if (!empty($query)) {
            $url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($query);
        }

        return $this->request('GET', $url, [], $headers);
    }

    /**
     * 发送 POST 请求并解析 JSON 响应
     *
     * @param  string $url     请求 URL
     * @param  array  $data    POST 数据（自动编码为 x-www-form-urlencoded 或 JSON）
     * @param  array  $headers 请求头（key => value）
     * @return array  JSON 解析后的数组
     *
     * @throws \wise\oauth\exception\OAuthException
     */
    public function post(string $url, array $data = [], array $headers = []): array
    {
        return $this->request('POST', $url, $data, $headers);
    }

    /**
     * 发送原始响应（不解析 JSON）
     *
     * @param  string $url
     * @param  array  $data
     * @param  array  $headers
     * @return string 原始响应体
     */
    public function postRaw(string $url, array $data = [], array $headers = []): string
    {
        return $this->requestRaw('POST', $url, $data, $headers);
    }

    /**
     * 发送请求并解析 JSON
     *
     * @param  string $method  请求方法
     * @param  string $url     请求 URL
     * @param  array  $data    POST 数据
     * @param  array  $headers 请求头
     * @return array
     *
     * @throws \wise\oauth\exception\OAuthException
     */
    protected function request(string $method, string $url, array $data = [], array $headers = []): array
    {
        $body = $this->requestRaw($method, $url, $data, $headers);

        if (empty($body)) {
            return [];
        }

        $result = json_decode($body, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            // 非 JSON 响应，尝试解析 x-www-form-urlencoded
            parse_str($body, $result);
        }

        return is_array($result) ? $result : [];
    }

    /**
     * 发送请求并返回原始响应
     *
     * @param  string $method
     * @param  string $url
     * @param  array  $data
     * @param  array  $headers
     * @return string
     *
     * @throws \wise\oauth\exception\OAuthException
     */
    protected function requestRaw(string $method, string $url, array $data = [], array $headers = []): string
    {
        $ch = curl_init();

        if ($method === 'GET' && !empty($data)) {
            $url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($data);
        }

        $defaultHeaders = [
            'User-Agent' => 'WiseAdmin-OAuth/1.0',
            'Accept'     => 'application/json',
        ];

        $allHeaders = array_merge($defaultHeaders, $headers);
        $curlHeaders = [];
        foreach ($allHeaders as $key => $value) {
            $curlHeaders[] = "{$key}: {$value}";
        }

        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => $this->connectTimeout,
            CURLOPT_HTTPHEADER     => $curlHeaders,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);

            // 检测是否需要 JSON 编码（Accept: application/json 时发送 JSON）
            $contentType = $allHeaders['Content-Type'] ?? $allHeaders['content-type'] ?? '';
            if (strpos($contentType, 'application/json') !== false) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data, JSON_UNESCAPED_UNICODE));
            } else {
                curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
            }
        }

        // 熔断 guard：断路器 OPEN 时立即抛异常，避免无意义等待
        if ($this->breaker !== null && !$this->breaker->isAvailable()) {
            throw new ServiceUnavailableException(
                retryAfter: (int) ($this->breakerConfig['breaker_config']['timeout'] ?? 30),
                platform: $this->breakerConfig['breaker_service'] ?? ''
            );
        }

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error    = curl_error($ch);
        curl_close($ch);

        if ($response === false || !empty($error)) {
            $this->breaker?->reportFailure();
            throw new OAuthException(
                "HTTP 请求失败：{$error}",
                0,
                null,
                null,
                ['url' => $url, 'method' => $method]
            );
        }

        if ($httpCode >= 400) {
            // 仅 5xx（上游故障）计入熔断，4xx 属调用方问题不计入
            if ($httpCode >= 500) {
                $this->breaker?->reportFailure();
            }
            throw new OAuthException(
                "HTTP 请求返回错误：状态码 {$httpCode}",
                $httpCode,
                null,
                null,
                ['url' => $url, 'method' => $method, 'response' => $response]
            );
        }

        $this->breaker?->reportSuccess();
        return $response;
    }
}
