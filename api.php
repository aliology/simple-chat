<?php
require_once __DIR__ . '/bootstrap.php';

app_bootstrap_session();
$myEmail = require_logged_in_user_or_403();
$action = $_POST['action'] ?? $_GET['action'] ?? '';
$users = app_users();

if ($action === 'store_keys') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        exit('METHOD');
    }

    verify_csrf_or_abort($_POST['csrf_token'] ?? '');

    $publicKey = app_validate_public_key_jwk(app_json_decode_object($_POST['public_key'] ?? ''));
    $privateKeyBox = app_validate_private_key_box(app_json_decode_object($_POST['private_key_box'] ?? ''));
    if ($publicKey === null || $privateKeyBox === null) {
        http_response_code(400);
        exit('KEYS');
    }

    $status = 'missing';
    json_update_file(APP_USERS_FILE, [], function ($storedUsers) use ($myEmail, $publicKey, $privateKeyBox, &$status) {
        $storedUsers = is_array($storedUsers) ? $storedUsers : [];
        foreach ($storedUsers as &$user) {
            if (normalize_email($user['email'] ?? '') !== $myEmail) {
                continue;
            }

            $status = 'found';
            $existingPublic = app_validate_public_key_jwk($user['public_key'] ?? null);
            $existingBox = app_validate_private_key_box($user['private_key_box'] ?? null);
            if ($existingPublic !== null || $existingBox !== null) {
                if ($existingPublic === $publicKey && $existingBox === $privateKeyBox) {
                    $status = 'ok';
                    return $storedUsers;
                }

                $status = 'exists';
                return $storedUsers;
            }

            $user['crypto_version'] = 'e2ee-rsa-oaep-aes-gcm-v1';
            $user['public_key'] = $publicKey;
            $user['private_key_box'] = $privateKeyBox;
            $status = 'ok';
            return $storedUsers;
        }
        unset($user);

        return $storedUsers;
    });

    if ($status === 'missing') {
        http_response_code(404);
        exit('USER');
    }

    if ($status === 'exists') {
        http_response_code(409);
        exit('EXISTS');
    }

    exit('OK');
}

if ($action === 'replace_keys') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        exit('METHOD');
    }

    verify_csrf_or_abort($_POST['csrf_token'] ?? '');

    $publicKey = app_validate_public_key_jwk(app_json_decode_object($_POST['public_key'] ?? ''));
    $privateKeyBox = app_validate_private_key_box(app_json_decode_object($_POST['private_key_box'] ?? ''));
    if ($publicKey === null || $privateKeyBox === null) {
        http_response_code(400);
        exit('KEYS');
    }

    $updated = false;
    json_update_file(APP_USERS_FILE, [], function ($storedUsers) use ($myEmail, $publicKey, $privateKeyBox, &$updated) {
        $storedUsers = is_array($storedUsers) ? $storedUsers : [];
        foreach ($storedUsers as &$user) {
            if (normalize_email($user['email'] ?? '') !== $myEmail) {
                continue;
            }

            $user['crypto_version'] = 'e2ee-rsa-oaep-aes-gcm-v1';
            $user['public_key'] = $publicKey;
            $user['private_key_box'] = $privateKeyBox;
            $updated = true;
            return $storedUsers;
        }
        unset($user);

        return $storedUsers;
    });

    if (!$updated) {
        http_response_code(404);
        exit('USER');
    }

    exit('OK');
}

if ($action === 'verify_password') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        exit('METHOD');
    }

    verify_csrf_or_abort($_POST['csrf_token'] ?? '');

    $password = (string) ($_POST['password'] ?? '');
    $user = app_user_record($myEmail, $users);
    if (!is_array($user) || !isset($user['password']) || !is_string($user['password'])) {
        http_response_code(404);
        exit('USER');
    }

    if ($password === '' || !password_verify($password, $user['password'])) {
        http_response_code(403);
        exit('PASSWORD');
    }

    exit('OK');
}

if ($action === 'send') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        exit('METHOD');
    }

    verify_csrf_or_abort($_POST['csrf_token'] ?? '');
    $chatPair = normalize_chat_pair_from_cid($_POST['cid'] ?? '');
    if ($chatPair === null || !in_array($myEmail, $chatPair, true)) {
        http_response_code(403);
        exit('DENIED');
    }

    if (!app_user_exists($chatPair[0], $users) || !app_user_exists($chatPair[1], $users)) {
        http_response_code(404);
        exit('CHAT');
    }

    $payload = app_validate_message_payload(app_json_decode_object($_POST['payload'] ?? ''), $chatPair);
    if ($payload === null) {
        http_response_code(400);
        exit('PAYLOAD');
    }

    $timestamp = time();
    $filename = conversation_storage_path($chatPair[0], $chatPair[1]);
    json_update_file($filename, [], function ($messages) use ($myEmail, $payload, $timestamp) {
        $messages = is_array($messages) ? $messages : [];
        $messages[] = [
            'from' => $myEmail,
            'version' => $payload['version'],
            'ciphertext' => $payload['ciphertext'],
            'iv' => $payload['iv'],
            'keys' => $payload['keys'],
            'time' => $timestamp,
        ];

        return $messages;
    });

    $recentDir = APP_STORAGE_DIR . '/recent/';
    ensure_directory($recentDir);
    $otherEmail = ($myEmail === $chatPair[0]) ? $chatPair[1] : $chatPair[0];

    foreach ([[$myEmail, $otherEmail], [$otherEmail, $myEmail]] as $recentPair) {
        $recentFile = $recentDir . md5($recentPair[0]) . '.json';
        json_update_file($recentFile, [], function ($recentChats) use ($recentPair) {
            $recentChats = is_array($recentChats) ? $recentChats : [];
            $recentChats = array_values(array_filter($recentChats, function ($email) use ($recentPair) {
                return normalize_email($email) !== $recentPair[1];
            }));
            array_unshift($recentChats, $recentPair[1]);

            return array_slice($recentChats, 0, 10);
        });
    }

    exit('OK');
}

if ($action === 'fetch') {
    app_send_json_headers();
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
        http_response_code(405);
        echo json_encode([]);
        exit;
    }

    $chatPair = normalize_chat_pair_from_cid($_GET['cid'] ?? '');
    if ($chatPair === null || !in_array($myEmail, $chatPair, true)) {
        http_response_code(403);
        echo json_encode([]);
        exit;
    }

    if (!app_user_exists($chatPair[0], $users) || !app_user_exists($chatPair[1], $users)) {
        http_response_code(404);
        echo json_encode([]);
        exit;
    }

    $lastTime = isset($_GET['last']) ? max(0, (int) $_GET['last']) : 0;
    $messages = json_read_file(conversation_storage_path($chatPair[0], $chatPair[1]), []);
    $result = [];

    foreach ($messages as $msg) {
        $messageTime = isset($msg['time']) ? (int) $msg['time'] : 0;
        if ($messageTime <= $lastTime) {
            continue;
        }

        $payload = app_validate_message_payload([
            'version' => $msg['version'] ?? '',
            'ciphertext' => $msg['ciphertext'] ?? '',
            'iv' => $msg['iv'] ?? '',
            'keys' => $msg['keys'] ?? null,
        ], $chatPair);
        if ($payload === null) {
            continue;
        }

        $result[] = [
            'from' => normalize_email($msg['from'] ?? ''),
            'time' => $messageTime,
            'version' => $payload['version'],
            'ciphertext' => $payload['ciphertext'],
            'iv' => $payload['iv'],
            'keys' => $payload['keys'],
        ];
    }

    $readFile = APP_STORAGE_DIR . '/read/' . md5($myEmail) . '.json';
    $cidValue = $chatPair[0] . '|' . $chatPair[1];
    $latestSeenTime = $lastTime;
    foreach ($result as $row) {
        if ($row['time'] > $latestSeenTime) {
            $latestSeenTime = $row['time'];
        }
    }
    if ($latestSeenTime > 0) {
        json_update_file($readFile, [], function ($readMap) use ($cidValue, $latestSeenTime) {
            $readMap = is_array($readMap) ? $readMap : [];
            $readMap[$cidValue] = $latestSeenTime;
            return $readMap;
        });
    }

    echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

if ($action === 'search') {
    app_send_json_headers();
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
        http_response_code(405);
        echo json_encode([]);
        exit;
    }

    $q = normalize_email($_GET['q'] ?? '');
    $result = [];
    if ($q !== '' && $q !== $myEmail && app_user_exists($q, $users)) {
        $result[] = $q;
    }

    echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

http_response_code(400);
exit('ACTION');
