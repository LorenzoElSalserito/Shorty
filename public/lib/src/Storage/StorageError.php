<?php

declare(strict_types=1);

namespace Shorty\Storage;

/** Storage cannot be read or written safely: callers must fail closed. */
final class StorageError extends \RuntimeException
{
}
