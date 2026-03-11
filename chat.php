<?php
require_once __DIR__ . '/bootstrap.php';

app_bootstrap_session();
$myEmail = require_logged_in_user_or_redirect();
$chatPair = normalize_chat_pair_from_cid($_GET['cid'] ?? '');
if ($chatPair === null) die('چت یافت نشد.');
list($user1, $user2) = $chatPair;
$otherUser = ($myEmail === $user1) ? $user2 : (($myEmail === $user2) ? $user1 : '');
if ($otherUser === '') die('چت نامعتبر است.');

$users = app_users();
if (!app_user_exists($user1, $users) || !app_user_exists($user2, $users)) {
    die('کاربر مورد نظر یافت نشد.');
}
$myUser = app_user_record($myEmail, $users);
$otherUserRecord = app_user_record($otherUser, $users);
$emailMap = array_intersect_key(app_email_name_map($users), array_flip([$user1, $user2]));
$otherLabel = $emailMap[$otherUser] ?: $otherUser;

$readDir = APP_STORAGE_DIR . '/read/';
ensure_directory($readDir);
$readFile = $readDir . md5($myEmail) . '.json';
$readMap = json_read_file($readFile, []);
$messages = json_read_file(conversation_storage_path($myEmail, $otherUser), []);
$readMap[$chatPair[0] . '|' . $chatPair[1]] = !empty($messages) ? (int)(end($messages)['time'] ?? 0) : 0;
json_write_file($readFile, $readMap);
?>
<!DOCTYPE html>
<html lang="fa">
<head>
    <meta charset="utf-8">
    <title>چت با <?=htmlspecialchars($otherLabel)?></title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="assets/styles.css?v=<?=filemtime(__DIR__.'/assets/styles.css')?>">
</head>
<body>
<div class="chat-container">
    <div class="top-bar" style="display: flex; flex-direction: column; align-items: center; text-align: center;">
        <a href="home.php" style="color:#fff; text-decoration: none; font-size: 1rem; margin-bottom: 5px;">
            &#8592; بازگشت به لیست گفتگوها
        </a>
        <span style="font-size: 1.1rem;">چت با <?=htmlspecialchars($otherLabel)?></span>
        <span id="crypto-status" style="font-size:0.9rem; margin-top:6px; opacity:0.95;">در حال آماده‌سازی رمزنگاری...</span>
    </div>
    <div class="chat-box" id="chat-box"></div>
    <form id="chat-form" autocomplete="off" style="margin-bottom: 0; text-align:right;">
        <div id="chat-bar">
            <textarea id="msg" placeholder="پیام خود را بنویسید..." required rows="1"></textarea>
            <button type="submit" id="send-btn" title="ارسال پیام">
                <svg viewBox="0 0 24 24">
                    <g transform="scale(-1,1) translate(-24,0)">
                        <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/>
                    </g>
                </svg>
            </button>
        </div>
    </form>
</div>
<script>
window.CHAT_CID = "<?=htmlspecialchars(build_cid($user1, $user2))?>";
window.MY_EMAIL = "<?=htmlspecialchars($myEmail)?>";
window.OTHER_EMAIL = "<?=htmlspecialchars($otherUser)?>";
window.CSRF_TOKEN = "<?=htmlspecialchars(csrf_token())?>";
window.EMAIL_NAME_MAP = <?=json_encode($emailMap, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG)?>;
window.CURRENT_USER_CRYPTO = <?=json_encode([
    'email' => $myEmail,
    'cryptoVersion' => is_array($myUser) ? ($myUser['crypto_version'] ?? null) : null,
    'publicKey' => is_array($myUser) ? ($myUser['public_key'] ?? null) : null,
    'privateKeyBox' => is_array($myUser) ? ($myUser['private_key_box'] ?? null) : null,
], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG)?>;
window.OTHER_PUBLIC_KEY = <?=json_encode(is_array($otherUserRecord) ? ($otherUserRecord['public_key'] ?? null) : null, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG)?>;
</script>
<script src="assets/crypto.js?v=<?=filemtime(__DIR__.'/assets/crypto.js')?>"></script>
<script src="assets/app.js?v=<?=filemtime(__DIR__.'/assets/app.js')?>"></script>
</body>
</html>
