<?php

declare(strict_types=1);

namespace Shorty\Http;

/**
 * Expected, client-facing failure: HTTP status + stable error code + safe message.
 * Never carries internal details.
 */
final class ApiError extends \RuntimeException
{
    public function __construct(
        public readonly int $status,
        public readonly string $errorCode,
        string $message,
        public readonly ?string $reason = null,
    ) {
        parent::__construct($message);
    }
}
