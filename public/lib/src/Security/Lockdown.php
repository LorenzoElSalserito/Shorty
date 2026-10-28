<?php

declare(strict_types=1);

namespace Shorty\Security;

/**
 * Kill switches controlled by files uploadable via FTP:
 *   runtime/LOCKDOWN       -> no new links, no challenges
 *   runtime/FULL_LOCKDOWN  -> additionally no outbound navigation
 */
final class Lockdown
{
    public function __construct(private readonly string $runtimeDir)
    {
    }

    public function full(): bool
    {
        return file_exists($this->runtimeDir . '/FULL_LOCKDOWN');
    }

    public function creation(): bool
    {
        return $this->full() || file_exists($this->runtimeDir . '/LOCKDOWN');
    }
}
