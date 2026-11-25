<?php
declare(strict_types=1);

namespace wise\oauth\service;

use think\facade\Cache;
use wise\oauth\exception\OAuthException;
use wise\oauth\exception\ServiceUnavailableException;
use wise\support\circuit\CircuitBreaker;
use wise\support\runtime\Runtime;

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

        if (!($cfg['enabled'] ?? true)) {
            return;
        }

        $store = (string) ($cfg['store'] ?? '');

        try {
            $cache = $store !== '' ? Cache::store($store) : Cache::store();
        } catch (\Throwable $e) {
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
            if (preg_match('/^[A-Za-z0-9_.\-%]+=[^\s<>]*/', $body) === 1) {
                parse_str($body, $result);
            } else {
                $result = [];
            }
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
        if (Runtime::inCoroutine()) {
            return $this->requestRawCoroutine($method, $url, $data, $headers);
        }

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

            $contentType = $allHeaders['Content-Type'] ?? $allHeaders['content-type'] ?? '';
            if (strpos($contentType, 'application/json') !== false) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data, JSON_UNESCAPED_UNICODE));
            } else {
                curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
            }
        }

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
                ['url' => $this->redactUrl($url), 'method' => $method]
            );
        }

        if ($httpCode >= 400) {
            if ($httpCode >= 500) {
                $this->breaker?->reportFailure();
            }
            throw new OAuthException(
                "HTTP 请求返回错误：状态码 {$httpCode}",
                $httpCode,
                null,
                null,
                [
                    'url'      => $this->redactUrl($url),
                    'method'   => $method,
                    'response' => $this->redactBody((string) $response),
                ]
            );
        }

        $this->breaker?->reportSuccess();
        return $response;
    }

    /**
     * 协程传输实现（Swoole 环境下替代同步 curl，避免阻塞 worker）
     */
    protected function requestRawCoroutine(string $method, string $url, array $data = [], array $headers = []): string
    {
        if ($this->breaker !== null && !$this->breaker->isAvailable()) {
            throw new ServiceUnavailableException(
                retryAfter: (int) ($this->breakerConfig['breaker_config']['timeout'] ?? 30),
                platform: $this->breakerConfig['breaker_service'] ?? ''
            );
        }

        $parts  = parse_url($url) ?: [];
        $scheme = $parts['scheme'] ?? 'https';
        $host   = (string) ($parts['host'] ?? '');
        $port   = (int) ($parts['port'] ?? ($scheme === 'https' ? 443 : 80));
        $path   = (string) ($parts['path'] ?? '/');

        if ($host === '') {
            throw new OAuthException('HTTP 请求失败：URL 缺少主机名', 0, null, null,
                ['url' => $this->redactUrl($url), 'method' => $method]);
        }

        if (isset($parts['query']) && $parts['query'] !== '') {
            $path .= '?' . $parts['query'];
        }

        $allHeaders = array_merge([
            'User-Agent' => 'WiseAdmin-OAuth/1.0',
            'Accept'     => 'application/json',
        ], $headers);

        $client = new \Swoole\Coroutine\Http\Client($host, $port, $scheme === 'https');
        $client->set([
            'timeout'         => $this->timeout,
            'connect_timeout' => $this->connectTimeout,
            'follow_location' => 3,
        ]);
        $client->setHeaders($allHeaders);

        if ($method === 'GET') {
            if (!empty($data)) {
                $path .= (strpos($path, '?') === false ? '?' : '&') . http_build_query($data);
            }
            $client->get($path);
        } else {
            $contentType = $allHeaders['Content-Type'] ?? $allHeaders['content-type'] ?? '';
            $payload     = strpos((string) $contentType, 'application/json') !== false
                ? (string) json_encode($data, JSON_UNESCAPED_UNICODE)
                : http_build_query($data);
            $client->post($path, $payload);
        }

        $status = (int) $client->statusCode;
        $body   = (string) $client->body;
        $error  = (string) $client->errMsg;
        $client->close();

        if ($status < 0) {
            $this->breaker?->reportFailure();
            throw new OAuthException(
                "HTTP 请求失败：{$error}",
                0,
                null,
                null,
                ['url' => $this->redactUrl($url), 'method' => $method]
            );
        }

        if ($status >= 400) {
            if ($status >= 500) {
                $this->breaker?->reportFailure();
            }
            throw new OAuthException(
                "HTTP 请求返回错误：状态码 {$status}",
                $status,
                null,
                null,
                [
                    'url'      => $this->redactUrl($url),
                    'method'   => $method,
                    'response' => $this->redactBody($body),
                ]
            );
        }

        $this->breaker?->reportSuccess();
        return $body;
    }

    /**
     * URL 脱敏：抹掉 query 中的凭据类参数
     */
    protected function redactUrl(string $url): string
    {
        return (string) preg_replace(
            '/([?&](?:access_token|refresh_token|code|client_secret|secret|appsecret)=)[^&#]*/i',
            '$1***',
            $url
        );
    }

    /**
     * 响应体脱敏：抹掉敏感字段值并截断，避免整段响应体进入日志
     */
    protected function redactBody(string $body): string
    {
        $body = (string) preg_replace(
            '/("?(?:access_token|refresh_token|client_secret|secret|code)"?\s*[:=]\s*"?)[^",&\s}]+/i',
            '$1***',
            $body
        );

        return strlen($body) > 500 ? substr($body, 0, 500) . '...(truncated)' : $body;
    }
}
