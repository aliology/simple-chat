<?php

define('APP_STORAGE_DIR', rtrim((string) (getenv('CHAT_STORAGE_DIR') ?: (__DIR__ . '/storage')), '/'));
define('APP_USERS_FILE', APP_STORAGE_DIR . '/users.json');
define('APP_MESSAGE_MAX_LENGTH', 4000);
define('APP_NAME_MAX_LENGTH', 80);
define('APP_LOGIN_ATTEMPT_LIMIT', 8);
define('APP_LOGIN_ATTEMPT_WINDOW', 900);

function app_is_https() {
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        return true;
    }

    return isset($_SERVER['SERVER_PORT']) && (string) $_SERVER['SERVER_PORT'] === '443';
}

function app_send_security_headers() {
    if (PHP_SAPI === 'cli' || headers_sent()) {
        return;
    }

    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: same-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');

    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'");

    if (app_is_https()) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

function app_send_no_cache_headers() {
    if (PHP_SAPI === 'cli' || headers_sent()) {
        return;
    }

    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
}

function app_send_json_headers() {
    app_send_security_headers();
    app_send_no_cache_headers();
    if (PHP_SAPI !== 'cli' && !headers_sent()) {
        header('Content-Type: application/json; charset=utf-8');
    }
}

function app_start_session() {
    if (session_status() === PHP_SESSION_ACTIVE || PHP_SAPI === 'cli') {
        return;
    }

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Strict');

    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => app_is_https(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);

    session_start();
}

function app_bootstrap() {
    app_send_security_headers();
}

function app_bootstrap_session() {
    app_send_security_headers();
    app_send_no_cache_headers();
    app_start_session();
}

function ensure_directory($dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0700, true);
    }
}

function json_decode_array($json, $default) {
    if (!is_string($json) || $json === '') {
        return $default;
    }

    $decoded = json_decode($json, true);
    return is_array($decoded) ? $decoded : $default;
}

function json_read_file($path, $default = []) {
    if (!file_exists($path)) {
        return $default;
    }

    $contents = file_get_contents($path);
    return json_decode_array($contents, $default);
}

function json_write_file($path, $data) {
    ensure_directory(dirname($path));
    $handle = fopen($path, 'c+');
    if ($handle === false) {
        throw new RuntimeException('Unable to open file for writing.');
    }

    try {
        if (!flock($handle, LOCK_EX)) {
            throw new RuntimeException('Unable to lock file.');
        }

        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        fflush($handle);
        flock($handle, LOCK_UN);
    } finally {
        fclose($handle);
    }
}

function json_update_file($path, $default, callable $mutator) {
    ensure_directory(dirname($path));
    $handle = fopen($path, 'c+');
    if ($handle === false) {
        throw new RuntimeException('Unable to open file for update.');
    }

    try {
        if (!flock($handle, LOCK_EX)) {
            throw new RuntimeException('Unable to lock file.');
        }

        $contents = stream_get_contents($handle);
        $data = json_decode_array($contents, $default);
        $updated = $mutator($data);
        if ($updated !== null) {
            $data = $updated;
        }

        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        fflush($handle);
        flock($handle, LOCK_UN);

        return $data;
    } finally {
        fclose($handle);
    }
}

function normalize_email($value) {
    $value = strtolower(trim((string) $value));
    if ($value === '' || !filter_var($value, FILTER_VALIDATE_EMAIL)) {
        return '';
    }

    return $value;
}

function normalize_name($value) {
    $value = trim((string) $value);
    if ($value === '') {
        return '';
    }

    $value = preg_replace('/\s+/u', ' ', $value);
    if (function_exists('mb_substr')) {
        return mb_substr($value, 0, APP_NAME_MAX_LENGTH);
    }

    return substr($value, 0, APP_NAME_MAX_LENGTH);
}

function normalize_message($value) {
    $value = trim((string) $value);
    if ($value === '') {
        return '';
    }

    if (function_exists('mb_substr')) {
        return mb_substr($value, 0, APP_MESSAGE_MAX_LENGTH);
    }

    return substr($value, 0, APP_MESSAGE_MAX_LENGTH);
}

function normalize_chat_pair_from_cid($cid) {
    $decoded = base64_decode((string) $cid, true);
    if ($decoded === false) {
        return null;
    }

    $parts = explode('|', $decoded);
    if (count($parts) !== 2) {
        return null;
    }

    $user1 = normalize_email($parts[0]);
    $user2 = normalize_email($parts[1]);
    if ($user1 === '' || $user2 === '' || $user1 === $user2) {
        return null;
    }

    $pair = [$user1, $user2];
    sort($pair, SORT_STRING);
    return $pair;
}

function build_cid($user1, $user2) {
    $pair = [normalize_email($user1), normalize_email($user2)];
    sort($pair, SORT_STRING);
    return base64_encode($pair[0] . '|' . $pair[1]);
}

function conversation_storage_key($user1, $user2) {
    $pair = [normalize_email($user1), normalize_email($user2)];
    sort($pair, SORT_STRING);
    return preg_replace('/[^a-z0-9]/i', '', $pair[0] . $pair[1]);
}

function conversation_storage_path($user1, $user2) {
    return APP_STORAGE_DIR . '/messages/' . conversation_storage_key($user1, $user2) . '.json';
}

function app_users() {
    if (!file_exists(APP_USERS_FILE)) {
        json_write_file(APP_USERS_FILE, []);
    }

    return json_read_file(APP_USERS_FILE, []);
}

function app_user_exists($email, $users = null) {
    $email = normalize_email($email);
    if ($email === '') {
        return false;
    }

    $users = is_array($users) ? $users : app_users();
    foreach ($users as $user) {
        if (normalize_email($user['email'] ?? '') === $email) {
            return true;
        }
    }

    return false;
}

function app_email_name_map($users = null) {
    $users = is_array($users) ? $users : app_users();
    $map = [];

    foreach ($users as $user) {
        $email = normalize_email($user['email'] ?? '');
        if ($email !== '') {
            $map[$email] = normalize_name($user['name'] ?? '');
        }
    }

    return $map;
}

function current_user_email() {
    return normalize_email($_SESSION['user'] ?? '');
}

function require_logged_in_user_or_redirect() {
    $user = current_user_email();
    if ($user === '') {
        header('Location: index.php');
        exit;
    }

    return $user;
}

function require_logged_in_user_or_403() {
    $user = current_user_email();
    if ($user === '') {
        http_response_code(403);
        exit;
    }

    return $user;
}

function csrf_token() {
    if (empty($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

function verify_csrf_or_abort($token) {
    $known = $_SESSION['csrf_token'] ?? '';
    if ($known === '' || !is_string($known) || !hash_equals($known, (string) $token)) {
        http_response_code(403);
        exit('CSRF');
    }
}

function destroy_session() {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        return;
    }

    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
}

function client_ip_address() {
    return trim((string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
}

function rate_limit_file($scope, $bucket) {
    return APP_STORAGE_DIR . '/ratelimits/' . preg_replace('/[^a-z0-9_-]/i', '', $scope) . '_' . hash('sha256', $bucket) . '.json';
}

function rate_limit_attempts($scope, $bucket, $windowSeconds) {
    $path = rate_limit_file($scope, $bucket);
    $cutoff = time() - max(1, (int) $windowSeconds);
    $data = json_read_file($path, ['attempts' => []]);
    $attempts = [];

    foreach (($data['attempts'] ?? []) as $attempt) {
        $attempt = (int) $attempt;
        if ($attempt >= $cutoff) {
            $attempts[] = $attempt;
        }
    }

    if ($attempts !== ($data['attempts'] ?? [])) {
        json_write_file($path, ['attempts' => $attempts]);
    }

    return $attempts;
}

function rate_limit_is_blocked($scope, $bucket, $maxAttempts, $windowSeconds) {
    return count(rate_limit_attempts($scope, $bucket, $windowSeconds)) >= (int) $maxAttempts;
}

function rate_limit_record_failure($scope, $bucket, $windowSeconds) {
    $path = rate_limit_file($scope, $bucket);
    $cutoff = time() - max(1, (int) $windowSeconds);
    return json_update_file($path, ['attempts' => []], function ($data) use ($cutoff) {
        $attempts = [];
        foreach (($data['attempts'] ?? []) as $attempt) {
            $attempt = (int) $attempt;
            if ($attempt >= $cutoff) {
                $attempts[] = $attempt;
            }
        }
        $attempts[] = time();
        return ['attempts' => $attempts];
    });
}

function rate_limit_clear($scope, $bucket) {
    $path = rate_limit_file($scope, $bucket);
    if (file_exists($path)) {
        unlink($path);
    }
}

function app_user_record($email, $users = null) {
    $email = normalize_email($email);
    if ($email === '') {
        return null;
    }

    $users = is_array($users) ? $users : app_users();
    foreach ($users as $user) {
        if (normalize_email($user['email'] ?? '') === $email) {
            return $user;
        }
    }

    return null;
}

function app_json_decode_object($value) {
    if (!is_string($value) || $value === '') {
        return null;
    }

    $decoded = json_decode($value, true);
    return is_array($decoded) ? $decoded : null;
}

function app_is_valid_base64($value, $maxLength = 20000) {
    if (!is_string($value) || $value === '' || strlen($value) > (int) $maxLength) {
        return false;
    }

    return base64_decode($value, true) !== false;
}

function app_is_valid_base64url($value, $maxLength = 20000) {
    if (!is_string($value) || $value === '' || strlen($value) > (int) $maxLength) {
        return false;
    }

    return preg_match('/^[A-Za-z0-9_-]+$/', $value) === 1;
}

function app_validate_public_key_jwk($jwk) {
    if (!is_array($jwk)) {
        return null;
    }

    $kty = (string) ($jwk['kty'] ?? '');
    $n = (string) ($jwk['n'] ?? '');
    $e = (string) ($jwk['e'] ?? '');
    if ($kty !== 'RSA' || !app_is_valid_base64url($n, 12000) || !app_is_valid_base64url($e, 128)) {
        return null;
    }

    return $jwk;
}

function app_validate_private_key_box($box) {
    if (!is_array($box)) {
        return null;
    }

    $version = (string) ($box['version'] ?? '');
    $salt = (string) ($box['salt'] ?? '');
    $iv = (string) ($box['iv'] ?? '');
    $ciphertext = (string) ($box['ciphertext'] ?? '');
    $iterations = (int) ($box['iterations'] ?? 0);

    if ($version !== 'pbkdf2-aes-gcm-v1') {
        return null;
    }

    if (!app_is_valid_base64($salt, 256) || !app_is_valid_base64($iv, 256) || !app_is_valid_base64($ciphertext, 40000)) {
        return null;
    }

    $rawSalt = base64_decode($salt, true);
    $rawIv = base64_decode($iv, true);
    if ($rawSalt === false || strlen($rawSalt) < 16 || $rawIv === false || strlen($rawIv) !== 12) {
        return null;
    }

    if ($iterations < 100000 || $iterations > 1000000) {
        return null;
    }

    return [
        'version' => $version,
        'salt' => $salt,
        'iv' => $iv,
        'ciphertext' => $ciphertext,
        'iterations' => $iterations,
    ];
}

function app_validate_message_payload($payload, $chatPair) {
    if (!is_array($payload) || !is_array($chatPair) || count($chatPair) !== 2) {
        return null;
    }

    $version = (string) ($payload['version'] ?? '');
    $ciphertext = (string) ($payload['ciphertext'] ?? '');
    $iv = (string) ($payload['iv'] ?? '');
    $keys = $payload['keys'] ?? null;
    if ($version !== 'e2ee-v1' || !app_is_valid_base64($ciphertext, 40000) || !app_is_valid_base64($iv, 256) || !is_array($keys)) {
        return null;
    }

    $rawIv = base64_decode($iv, true);
    if ($rawIv === false || strlen($rawIv) !== 12) {
        return null;
    }

    $normalizedKeys = [];
    foreach ($chatPair as $email) {
        $email = normalize_email($email);
        $wrapped = $keys[$email] ?? null;
        if ($email === '' || !app_is_valid_base64($wrapped, 12000)) {
            return null;
        }

        $normalizedKeys[$email] = (string) $wrapped;
    }

    return [
        'version' => 'e2ee-v1',
        'ciphertext' => $ciphertext,
        'iv' => $iv,
        'keys' => $normalizedKeys,
    ];
}
