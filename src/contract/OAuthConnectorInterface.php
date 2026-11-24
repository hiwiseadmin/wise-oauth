<?php
declare(strict_types=1);

namespace wise\oauth\contract;

use wise\support\connector\ConnectorInterface;

/**
 * OAuth 连接器契约（领域子接口）
 *
 * 组合连接器通用契约 {@see ConnectorInterface} 与 OAuth 平台契约
 * {@see OAuthDriverInterface}，使第三方登录平台统一纳入连接器体系，
 * 取代原 `oauth.driver` 扩展点。
 *
 * 契约归属说明：本接口依赖 OAuthDriverInterface（位于 wise-oauth），
 * 故定义在 wise-oauth（而非 wise-support），保持 wise-support 为最底层、
 * 不反向依赖业务包。
 *
 * 类型归属：{@see \wise\support\connector\ConnectorType::OAUTH}。
 *
 * @package wise\oauth\contract
 */
interface OAuthConnectorInterface extends ConnectorInterface, OAuthDriverInterface
{
}
