<?php
declare(strict_types=1);

namespace wise\oauth\service;

use wise\oauth\exception\OAuthException;

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

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error    = curl_error($ch);
        curl_close($ch);

        if ($response === false || !empty($error)) {
            throw new OAuthException(
                "HTTP 请求失败：{$error}",
                0,
                null,
                null,
                ['url' => $url, 'method' => $method]
            );
        }

        if ($httpCode >= 400) {
            throw new OAuthException(
                "HTTP 请求返回错误：状态码 {$httpCode}",
                $httpCode,
                null,
                null,
                ['url' => $url, 'method' => $method, 'response' => $response]
            );
        }

        return $response;
    }
}
