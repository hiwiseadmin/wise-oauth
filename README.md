# wiseadmin/wise-oauth

> 为 ThinkPHP 6/8 提供的第三方 OAuth 登录包——支持微信/QQ/GitHub/钉钉/Google/微博/码云八大平台，自动关联或创建账号，多账号绑定解绑，零外部依赖。

[![PHP Version](https://img.shields.io/badge/PHP-%3E%3D8.1-blue)](https://www.php.net)
[![ThinkPHP](https://img.shields.io/badge/ThinkPHP-%5E6.0%20%7C%7C%20%5E8.0-green)](https://www.thinkphp.cn) 
[![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen)](LICENSE)
[![Packagist](https://img.shields.io/badge/packagist-wiseadmin%2Fwise--oauth-orange)](https://packagist.org/packages/wiseadmin/wise-oauth)

---

## 特性

| 模块 | 说明 |
|------|------|
| **8 个内置平台** | 微信开放平台、微信公众号、QQ 互联、GitHub、钉钉、Google、微博、码云（Gitee） |
| **零外部依赖** | 纯 PHP 实现，仅需 PHP >= 8.0 + ThinkPHP 6/8 |
| **自动登录/注册** | `OAuthUserResolver` 五级匹配链（unionId → openid → email → mobile → 创建新用户） |
| **多账号绑定** | 一个平台账号可绑定多个本地用户，一个本地用户可绑定多个平台 |
| **State/CSRF 防护** | `OAuthStateManager` 内置 CSRF 防护，可选 PKCE（RFC 7636）增强安全性 |
| **Token 加密存储** | `OAuthTokenEncryptor` AES-256-CBC 加密 access_token/refresh_token |
| **HasOAuth Trait** | Admin/Member 挂载即获绑定/解绑/查询能力 |
| **多态绑定表** | `oauth_users` 表（user_type + user_id），不侵入用户原表 |
| **双控制器** | `AdminOAuthController`（Session + redirect） / `ApiOAuthController`（JWT + JSON） |
| **事件驱动** | `OAuthUserLoggedIn` / `OAuthUserRegistered` / `OAuthUserBound` / `OAuthUserUnbound` |
| **Facade 门面** | `OAuth::getAuthUrl()` / `OAuth::handleCallback()` 一行搞定 |

---

## 安装

```bash
composer require wiseadmin/wise-oauth
```

---

## 配置

发布配置和数据库迁移：

```bash
php think vendor:publish
php think migrate:run
```

配置文件 `config/wise-oauth.php`：

```php
return [
    // 平台配置
    'platforms' => [
        'github' => [
            'enabled'       => true,
            'driver'        => \wise\oauth\driver\GithubDriver::class,
            'client_id'     => env('OAUTH_GITHUB_CLIENT_ID'),
            'client_secret' => env('OAUTH_GITHUB_CLIENT_SECRET'),
            'redirect_uri'  => 'https://example.com/oauth/callback/github',
            'scopes'        => ['user:email'],
        ],
        'wechat_open' => [
            'enabled'       => false,
            'driver'        => \wise\oauth\driver\WechatOpenDriver::class,
            'client_id'     => '',
            'client_secret' => '',
            'redirect_uri'  => '',
        ],
        'wechat_mp' => [
            'enabled'       => false,
            'driver'        => \wise\oauth\driver\WechatMpDriver::class,
            'client_id'     => '',
            'client_secret' => '',
            'redirect_uri'  => '',
        ],
        'qq' => [
            'enabled'       => false,
            'driver'        => \wise\oauth\driver\QqDriver::class,
            'client_id'     => '',
            'client_secret' => '',
            'redirect_uri'  => '',
        ],
        'dingtalk' => [
            'enabled'       => false,
            'driver'        => \wise\oauth\driver\DingtalkDriver::class,
            'client_id'     => '',
            'client_secret' => '',
            'redirect_uri'  => '',
        ],
        'gitee' => [
            'enabled'       => false,
            'driver'        => \wise\oauth\driver\GiteeDriver::class,
            'client_id'     => '',
            'client_secret' => '',
            'redirect_uri'  => '',
        ],
        'google' => [
            'enabled'       => false,
            'driver'        => \wise\oauth\driver\GoogleDriver::class,
            'client_id'     => '',
            'client_secret' => '',
            'redirect_uri'  => '',
        ],
        'weibo' => [
            'enabled'       => false,
            'driver'        => \wise\oauth\driver\WeiboDriver::class,
            'client_id'     => '',
            'client_secret' => '',
            'redirect_uri'  => '',
        ],
    ],

    // 自动注册（无匹配本地用户时自动创建）
    'auto_register' => true,

    // 自动关联（email/mobile 匹配时自动绑定）
    'auto_link' => [
        'email'  => false,
        'mobile' => false,
    ],

    // PKCE 增强安全（RFC 7636）
    'pkce_enabled' => false,

    // 频率限制
    'rate_limit' => [
        'enabled'       => false,
        'max_attempts'  => 10,
        'decay_minutes' => 1,
    ],

    // Token 加密
    'token_encryption' => [
        'enabled' => true,
        'key'     => env('OAUTH_ENCRYPT_KEY', ''),
    ],

    // 用户模型映射
    'user_model' => [
        'admin'  => \app\admin\model\Admin::class,
        'member' => \app\api\model\Member::class,
    ],
];
```

---

## 使用指南

### 1. 用户模型接入（HasOAuth Trait）

```php
namespace app\admin\model;

use think\Model;
use wise\oauth\traits\HasOAuth;

class Admin extends Model
{
    use HasOAuth;

    // 可选：覆盖默认 user_type（默认取类名小写）
    public function getOAuthUserType(): string
    {
        return 'admin';
    }
}
```

`HasOAuth` 提供以下方法：

| 方法 | 说明 |
|------|------|
| `getOAuthBindings()` | 获取所有绑定列表 |
| `bindOAuth(OAuthUserInfo $info)` | 绑定平台账号 |
| `unbindOAuth(string $platform)` | 解绑平台账号 |
| `hasOAuthBinding(string $platform)` | 检查绑定状态 |
| `getOAuthUserByPlatform(string $platform)` | 通过平台查询绑定 |

### 2. 获取授权跳转 URL

```php
use wise\oauth\facade\OAuth;

// 获取 GitHub 授权 URL
$authUrl = OAuth::getAuthUrl('github');

// 指定自定义回调地址
$authUrl = OAuth::getAuthUrl('github', 'https://example.com/custom/callback');
```

### 3. 处理 OAuth 回调

```php
// 在回调控制器中
use wise\oauth\facade\OAuth;

public function callback(string $platform)
{
    $code  = request()->get('code');
    $state = request()->get('state');

    try {
        // 获取标准化用户信息
        $userInfo = OAuth::handleCallback($platform, $code, $state);

        // 登录或注册，返回 ['user' => Admin, 'action' => 'login'|'register']
        $result = OAuth::loginOrRegister($userInfo, 'admin');

        // 登录成功，写入 Session
        session('admin_id', $result['user']->id);

        return redirect('/admin/dashboard');
    } catch (\Exception $e) {
        return redirect('/admin/login')->with('error', '登录失败: ' . $e->getMessage());
    }
}
```

### 4. 绑定/解绑账号

```php
use wise\oauth\facade\OAuth;

// 绑定（先获取授权 URL，回调时绑定）
$authUrl = OAuth::getAuthUrl('github');

// 回调中绑定
$userInfo = OAuth::handleCallback('github', $code, $state);
OAuth::bindUser($userId, 'admin', $userInfo);

// 解绑
OAuth::unbindUser($userId, 'admin', 'github');

// 检查绑定状态
$bound = OAuth::hasBinding($userId, 'admin', 'github');

// 获取用户所有绑定
$bindings = OAuth::getUserBindings($userId, 'admin');
```

### 5. 在模型中直接操作

```php
$admin = Admin::find(1);

// 获取绑定列表
$bindings = $admin->getOAuthBindings();
// [['platform' => 'github', 'nickname' => 'octocat', 'avatar' => '...'], ...]

// 检查是否绑定
if ($admin->hasOAuthBinding('github')) {
    echo '已绑定 GitHub';
}

// 解绑
$admin->unbindOAuth('weibo');
```

### 6. OAuthUserInfo 结构

回调返回的标准化用户信息：

```php
use wise\oauth\entity\OAuthUserInfo;

// 属性
$userInfo->platform;      // 平台标识: 'github', 'wechat_open', ...
$userInfo->openid;        // 平台 OpenID
$userInfo->unionId;       // 联合 ID（微信/QQ 等，可能为 null）
$userInfo->nickname;      // 昵称
$userInfo->avatar;        // 头像 URL
$userInfo->email;         // 邮箱（平台授权获取）
$userInfo->mobile;        // 手机号（平台授权获取）
$userInfo->gender;        // 性别
$userInfo->accessToken;   // 访问令牌（加密存储）
$userInfo->refreshToken;  // 刷新令牌（加密存储）
$userInfo->expiresIn;     // 令牌过期时间
$userInfo->raw;           // 原始响应数据
```

### 7. 事件监听

```php
// app/event.php
return [
    'listen' => [
        \wise\oauth\event\OAuthUserRegistered::class => [
            \app\listener\SendWelcomeEmail::class,
            \app\listener\GrantDefaultRole::class,
        ],
        \wise\oauth\event\OAuthUserLoggedIn::class => [
            \app\listener\RecordLoginHistory::class,
        ],
        \wise\oauth\event\OAuthUserBound::class => [
            \app\listener\NotifyBinding::class,
        ],
    ],
];
```

### 8. 自定义驱动

```php
use wise\oauth\driver\AbstractDriver;
use wise\oauth\entity\OAuthUserInfo;

class CustomOAuthDriver extends AbstractDriver
{
    public function getPlatform(): string { return 'custom'; }
    public function getPlatformName(): string { return '自定义平台'; }
    public function getDefaultScopes(): array { return ['read']; }

    public function getAuthUrl(string $state, ?string $redirectUri = null): string
    {
        return 'https://custom-oauth.com/authorize?' . http_build_query([
            'client_id'     => $this->getAppId(),
            'redirect_uri'  => $redirectUri ?? $this->getRedirectUri(),
            'state'         => $state,
        ]);
    }

    public function getUser(string $code, ?string $state = null, ?string $redirectUri = null): OAuthUserInfo
    {
        // 1. 用 code 换取 access_token
        $tokenResponse = $this->httpPost('https://custom-oauth.com/token', [
            'client_id'     => $this->getAppId(),
            'client_secret' => $this->getAppSecret(),
            'code'          => $code,
        ]);

        // 2. 用 access_token 获取用户信息
        $userResponse = $this->httpGet('https://custom-oauth.com/user', [
            'access_token' => $tokenResponse['access_token'],
        ]);

        return new OAuthUserInfo([
            'platform'      => 'custom',
            'openid'        => $userResponse['id'],
            'nickname'      => $userResponse['name'],
            'avatar'        => $userResponse['avatar'],
            'email'         => $userResponse['email'] ?? null,
            'accessToken'   => $tokenResponse['access_token'],
            'refreshToken'  => $tokenResponse['refresh_token'] ?? null,
            'expiresIn'     => $tokenResponse['expires_in'] ?? null,
            'raw'           => $userResponse,
        ]);
    }

    public function refreshToken(string $refreshToken): array
    {
        $response = $this->httpPost('https://custom-oauth.com/token', [
            'grant_type'    => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id'     => $this->getAppId(),
            'client_secret' => $this->getAppSecret(),
        ]);
        return $response;
    }
}
```

---

## 平台配置速查

| 平台 | 标识 | 申请地址 |
|------|------|----------|
| GitHub | `github` | https://github.com/settings/developers |
| 码云 | `gitee` | https://gitee.com/oauth_applications |
| Google | `google` | https://console.cloud.google.com/apis/credentials |
| QQ 互联 | `qq` | https://connect.qq.com |
| 微信开放平台 | `wechat_open` | https://open.weixin.qq.com |
| 微信公众号 | `wechat_mp` | https://mp.weixin.qq.com |
| 钉钉 | `dingtalk` | https://open.dingtalk.com |
| 微博 | `weibo` | https://open.weibo.com |

---

## 目录结构

```
wise-oauth/
├── composer.json
├── config/
│   └── wise-oauth.php              # 配置文件
├── database/
│   └── migrations/                 # 数据库迁移
└── src/
    ├── Service.php                 # 服务提供者
    ├── OAuthManager.php            # 核心编排器
    ├── OAuthStateManager.php       # State/CSRF 管理（含 PKCE）
    ├── OAuthTokenEncryptor.php     # Token 加密器（AES-256-CBC）
    ├── OAuthUserResolver.php       # 用户解析器（五级匹配链）
    ├── contract/
    │   └── OAuthDriverInterface.php # OAuth 驱动接口
    ├── driver/
    │   ├── AbstractDriver.php      # 抽象驱动基类
    │   ├── GithubDriver.php
    │   ├── GiteeDriver.php
    │   ├── GoogleDriver.php
    │   ├── QqDriver.php
    │   ├── WeiboDriver.php
    │   ├── WechatOpenDriver.php
    │   ├── WechatMpDriver.php
    │   └── DingtalkDriver.php
    ├── entity/
    │   └── OAuthUserInfo.php       # 标准化用户信息值对象
    ├── enums/
    │   └── Platform.php            # 平台枚举
    ├── event/
    │   ├── OAuthUserLoggedIn.php
    │   ├── OAuthUserRegistered.php
    │   ├── OAuthUserBound.php
    │   └── OAuthUserUnbound.php
    ├── exception/
    │   ├── OAuthException.php
    │   ├── OAuthDriverNotFoundException.php
    │   └── OAuthBindingException.php
    ├── facade/
    │   └── OAuth.php               # Facade
    ├── model/
    │   └── OAuthUserModel.php      # OAuth 用户绑定模型
    ├── service/
    │   └── HttpClient.php          # HTTP 客户端
    └── trait/
        ├── ServiceTrait.php
        └── HasOAuth.php            # 用户模型 Trait
```

---

## 依赖关系

- **必需**：`topthink/framework`、`wise-support`、`ext-json`
- **迁移**：包内置 `migrate-path`，安装后需执行迁移（第三方账号关联表）

## 许可证

MIT
