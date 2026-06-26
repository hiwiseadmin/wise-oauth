<?php
declare(strict_types=1);

namespace wise\oauth\command;

use think\console\Command;
use think\console\Input;
use think\console\input\Option;
use think\console\Output;
use wise\oauth\trait\CommandTrait;

/**
 * Publish 命令 — 发布配置文件与数据库迁移
 *
 * 用法：php think wise:oauth:publish [--force]
 */
class Publish extends Command
{
    use CommandTrait;

    protected function configure(): void
    {
        $this->setName('wise:oauth:publish')
            ->setDescription('发布 OAuth 第三方登录配置文件与数据库迁移')
            ->addOption('force', 'f', Option::VALUE_NONE, '强制覆盖已存在的配置文件');
    }

    protected function getPackageConfigName(): string
    {
        return 'wise-oauth';
    }

    protected function execute(Input $input, Output $output): int
    {
        $force = $input->getOption('force');

        $this->printBanner($output, 'wise-oauth');

        // 发布配置文件
        $this->publishConfig($output, $force);

        // 发布迁移文件
        $migrationsPublished = $this->publishMigrations($output);

        $this->printSuccessFooter($output, 'OAuth第三方登录', $migrationsPublished);

        return 0;
    }
}
