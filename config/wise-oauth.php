<?php
/**
 * WiseAdmin OAuth 第三方登录 — 默认配置
 *
 * 可通过 config('wise-oauth.xxx') 读取所有配置项。
 * 发布后自动复制到项目 config/ 目录，业务可按需覆盖。
 */
return [
    // ================================================================
    // 用户模型映射
    // ================================================================

    /**
     * 多用户类型映射
     * key: 用户类型标识符
     * value: 用户模型类 (FQCN)
     *
     * Admin 模型需要 use wise\oauth\trait\HasOAuth
     */
    'user_models' => [
        'admin'  => \app\admin\model\Admin::class,
        'member' => \wise\member\model\Member::class,
    ],

    // ================================================================
    // 自动注册
    // ================================================================

    /**
     * 当 OAuth 用户无法匹配到本地用户时，是否自动创建账号
     */
    'auto_register' => true,

    /**
     * 自动注册 Admin 时的默认角色（角色 ID 数组）
     * 空数组表示不分配角色，仅创建基础账号
     */
    'default_admin_roles' => [],

    // ================================================================
    // 自动关联
    // ================================================================

    /**
     * 是否通过邮箱/手机号自动关联已有账号
     *
     * ⚠️ 安全提醒：
     * - email 自动关联：部分 OAuth 平台（如 GitHub）邮箱已验证，相对安全；
     *   但微信/QQ 不提供邮箱，避免开启后误关联。
     * - mobile 自动关联：仅开启支持手机号授权的平台（如微信公众平台）。
     */
    'auto_link' => [
        'email'  => false,
        'mobile' => false,
    ],

    // ================================================================
    // 安全配置
    // ================================================================

    /**
     * State 防 CSRF 令牌有效期（秒）
     */
    'state_ttl' => 600,

    /**
     * PKCE (Proof Key for Code Exchange) 增强
     * 推荐在 SPA / 移动端等无法安全存储 client_secret 的场景下启用
     */
    'pkce_enabled' => false,

    /**
     * Token 加密存储
     * access_token / refresh_token 落库前 AES-256-CBC 加密
     */
    'encrypt_tokens' => true,

    /**
     * 加密密钥
     * null 表示使用 config('app.app_key')
     * 可通过环境变量 OAUTH_ENCRYPT_KEY 覆盖
     */
    'encrypt_key' => null,

    /**
     * 频率限制
     * 基于 IP 维度限制 OAuth 回调请求频率
     */
    'rate_limit' => [
        'enabled'       => true,
        'max_attempts'  => 10,
        'decay_minutes' => 1,
    ],

    // ================================================================
    // 数据表
    // ================================================================

    /**
     * 数据表名（不含前缀）
     */
    'table_names' => [
        'oauth_users' => 'oauth_users',
    ],

    // ================================================================
    // 路由前缀
    // ================================================================

    'route' => [
        'admin_prefix' => 'admin/oauth',
        'api_prefix'   => 'api/oauth',
    ],

    // ================================================================
    // 平台驱动配置
    // ================================================================

    /**
     * OAuth 平台配置
     *
     * 每个平台包含以下字段：
     *   - driver:      驱动类 FQCN（必填）
     *   - app_id:      应用 ID（必填）
     *   - app_secret:  应用密钥（必填）
     *   - redirect_uri: 回调地址（必填）
     *   - scopes:      授权范围（可选，不填用驱动默认值）
     *   - enabled:     是否启用（可选，默认 true）
     *
     * 驱动命名约定：
     *   内置驱动位于 \wise\oauth\driver\ 下，自定义驱动放应用目录。
     */
    'platforms' => [
        // ---- 微信开放平台（扫码登录） ----
        'wechat_open' => [
            'driver'       => \wise\oauth\driver\WechatOpenDriver::class,
            'app_id'       => env('WECHAT_OPEN_APP_ID', ''),
            'app_secret'   => env('WECHAT_OPEN_APP_SECRET', ''),
            'redirect_uri' => '',
            'scopes'       => ['snsapi_login'],
            'enabled'      => false,
        ],

        // ---- 微信公众平台（网页授权） ----
        'wechat_mp' => [
            'driver'       => \wise\oauth\driver\WechatMpDriver::class,
            'app_id'       => env('WECHAT_MP_APP_ID', ''),
            'app_secret'   => env('WECHAT_MP_APP_SECRET', ''),
            'redirect_uri' => '',
            'scopes'       => ['snsapi_userinfo'],
            'enabled'      => false,
        ],

        // ---- QQ 互联 ----
        'qq' => [
            'driver'       => \wise\oauth\driver\QqDriver::class,
            'app_id'       => env('QQ_APP_ID', ''),
            'app_secret'   => env('QQ_APP_SECRET', ''),
            'redirect_uri' => '',
            'enabled'      => false,
        ],

        // ---- GitHub OAuth ----
        'github' => [
            'driver'        => \wise\oauth\driver\GithubDriver::class,
            'client_id'     => env('GITHUB_CLIENT_ID', ''),
            'client_secret' => env('GITHUB_CLIENT_SECRET', ''),
            'redirect_uri'  => '',
            'scopes'        => ['user:email'],
            'enabled'       => false,
        ],

        // ---- 钉钉 ----
        'dingtalk' => [
            'driver'       => \wise\oauth\driver\DingtalkDriver::class,
            'app_key'      => env('DINGTALK_APP_KEY', ''),
            'app_secret'   => env('DINGTALK_APP_SECRET', ''),
            'redirect_uri' => '',
            'enabled'      => false,
        ],

        // ---- 码云 Gitee ----
        'gitee' => [
            'driver'        => \wise\oauth\driver\GiteeDriver::class,
            'client_id'     => env('GITEE_CLIENT_ID', ''),
            'client_secret' => env('GITEE_CLIENT_SECRET', ''),
            'redirect_uri'  => '',
            'enabled'       => false,
        ],

        // ---- Google OAuth ----
        'google' => [
            'driver'        => \wise\oauth\driver\GoogleDriver::class,
            'client_id'     => env('GOOGLE_CLIENT_ID', ''),
            'client_secret' => env('GOOGLE_CLIENT_SECRET', ''),
            'redirect_uri'  => '',
            'enabled'       => false,
        ],

        // ---- 微博 ----
        'weibo' => [
            'driver'       => \wise\oauth\driver\WeiboDriver::class,
            'app_key'      => env('WEIBO_APP_KEY', ''),
            'app_secret'   => env('WEIBO_APP_SECRET', ''),
            'redirect_uri' => '',
            'enabled'      => false,
        ],
    ],
];
