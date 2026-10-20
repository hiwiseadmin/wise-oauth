# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed

- `OAuthUserResolver::getUserModelClass()` 未校验模型类是否存在：`config('wise-oauth.user_models.*')` 里写的 `::class` 只是**字符串常量**（不触发自动加载），因此提供该模型的包（如 wise-member）被卸载后不会在配置处报错，而是在 `$class::find()` / `new $class` 时**致命错误**。现改为在实例化前校验，缺失时抛出业务异常 `OAuthException`（可被上层捕获提示），覆盖 `resolveLocalUser` / `resolveLocalUserById` / `findByEmail` / `findByMobile` / `createAdmin` / `createMember` 等调用点
- `OAuthUserModel::user()` 的 morphTo 映射未过滤不存在的模型类：现按 `class_exists` 过滤，避免关联到已卸载包的模型时致命错误

## [1.0.0] - 2024-01-01

### Added
- Initial release

[1.0.0]: https://github.com/wiseadmin/wise-oauth/releases/tag/v1.0.0
