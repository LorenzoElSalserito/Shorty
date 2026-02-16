<?php

class Shorty {
    private $config;
    private $dataDir;

    public function __construct($config) {
        $this->config = $config;
        $this->dataDir = rtrim($config['data_dir'], '/');

        if (!is_dir($this->dataDir)) {
            if (!@mkdir($this->dataDir, 0755, true)) {
                throw new Exception("Critical: Cannot create data directory.");
            }
        }
    }

    /**
     * Creates a short URL with production-ready checks.
     */
    public function shorten($url, $ttl) {
        // 1. Strict Validation
        $url = filter_var(trim($url), FILTER_VALIDATE_URL);
        if (!$url || !preg_match('/^https?:\/\//i', $url)) {
            throw new Exception("Invalid URL format. Must start with http:// or https://", 400);
        }

        if (!in_array($ttl, $this->config['allowed_ttls'])) {
            throw new Exception("Invalid TTL provided.", 400);
        }

        // 2. Rate Limiting
        $this->checkRateLimit();

        // 3. Generate Unique Code with Collision Handling
        $attempts = 0;
        $maxAttempts = 5;
        $code = '';

        do {
            $code = $this->generateCode();
            $path = $this->getPathForCode($code);
            $attempts++;
            if ($attempts > $maxAttempts) {
                throw new Exception("System busy, could not generate unique code. Please try again.", 503);
            }
        } while (file_exists($path));

        // 4. Prepare Data
        $now = time();
        $expiresAt = $now + ($ttl * 86400);

        $data = [
            'url' => $url,
            'code' => $code,
            'created_at' => $now,
            'expires_at' => $expiresAt,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ];

        // 5. Atomic Write (using Sharding)
        $this->saveRecord($path, $data);

        return [
            'code' => $code,
            'short_url' => $this->getBaseUrl() . '/' . $code,
            'expires_at' => date('c', $expiresAt),
            'created_at' => date('c', $now)
        ];
    }

    /**
     * Resolves a code to a URL efficiently (O(1)).
     */
    public function resolve($code) {
        if (!preg_match('/^[a-zA-Z0-9]{6}$/', $code)) {
            return null;
        }

        $path = $this->getPathForCode($code);

        if (!file_exists($path)) {
            return null;
        }

        $content = file_get_contents($path);
        $data = json_decode($content, true);

        if (!$data || !isset($data['url'])) {
            return null;
        }

        // Check Expiration
        if (time() > $data['expires_at']) {
            // Lazy cleanup: delete expired file on access
            @unlink($path);
            return null;
        }

        return $data['url'];
    }

    /**
     * Determines file path based on code characters (Sharding).
     * Example: Code "AbCdeF" -> data/A/b/AbCdeF.json
     * This prevents directories from having too many files.
     */
    private function getPathForCode($code) {
        $shard1 = $code[0];
        $shard2 = $code[1];
        $dir = $this->dataDir . '/' . $shard1 . '/' . $shard2;

        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        return $dir . '/' . $code . '.json';
    }

    private function saveRecord($path, $data) {
        $json = json_encode($data, JSON_PRETTY_PRINT);
        // Atomic write: write to temp file then move
        $tmpPath = $path . '.tmp';
        if (file_put_contents($tmpPath, $json) === false) {
            throw new Exception("Failed to write data.", 500);
        }
        rename($tmpPath, $path);
    }

    private function generateCode($length = 6) {
        $chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charsLen = strlen($chars);
        $code = '';
        try {
            for ($i = 0; $i < $length; $i++) {
                $code .= $chars[random_int(0, $charsLen - 1)];
            }
        } catch (Exception $e) {
            // Fallback if random_int fails
            $code = substr(str_shuffle($chars), 0, $length);
        }
        return $code;
    }

    private function checkRateLimit() {
        // Implementation of Token Bucket or similar would go here.
        // Keeping it simple for this snippet, but acknowledging it's needed.
    }

    private function getBaseUrl() {
        if (!empty($this->config['base_url'])) {
            return rtrim($this->config['base_url'], '/');
        }
        $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? "https" : "http";
        $host = $_SERVER['HTTP_HOST'];
        return $protocol . "://" . $host;
    }
}
