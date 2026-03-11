<?php
require_once __DIR__ . '/bootstrap.php';

app_bootstrap_session();
$myEmail = current_user_email();
if ($myEmail === '') {
    http_response_code(403);
    exit;
}
$users = app_users();

// Build email => name map
$emailMap = app_email_name_map($users);

$recentChats = [];
$recentFile = APP_STORAGE_DIR . '/recent/' . md5($myEmail) . '.json';
if (file_exists($recentFile)) {
    $recentChats = json_read_file($recentFile, []);
}
$recentDir = APP_STORAGE_DIR . '/recent/';
if (is_dir($recentDir)) {
    foreach (glob($recentDir . '*.json') as $file) {
        $other = basename($file, '.json');
        if ($other === md5($myEmail)) continue;
        foreach (json_read_file($file, []) as $u) {
            if (normalize_email($u) === $myEmail) {
                $userEmail = '';
                foreach ($users as $user) {
                    $candidate = normalize_email($user['email'] ?? '');
                    if ($candidate !== '' && md5($candidate) === $other) {
                        $userEmail = $candidate;
                        break;
                    }
                }
                if ($userEmail && !in_array($userEmail, $recentChats)) {
                    $recentChats[] = $userEmail;
                }
            }
        }
    }
}
$recentChats = array_unique($recentChats);

$readDir = APP_STORAGE_DIR . '/read/';
$readFile = $readDir . md5($myEmail) . '.json';
$readMap = [];
if (file_exists($readFile)) {
    $readMap = json_read_file($readFile, []);
}
?>

<?php if (!empty($recentChats)): ?>
    <div style="margin: 18px 0 0 0; text-align: center;">
        <b class="recent-chats">گفتگوهای اخیر شما:</b>
        <ul class="user-list">
            <?php foreach ($recentChats as $recent): 
                $cidVal = normalize_chat_pair_from_cid(build_cid($myEmail, $recent));
                if ($cidVal === null) continue;
                $cidString = $cidVal[0] . '|' . $cidVal[1];
                $cid = urlencode(build_cid($myEmail, $recent));
                $label = $emailMap[$recent] ?: $recent;
                $filename = conversation_storage_path($myEmail, $recent);
                $messages = json_read_file($filename, []);
                $lastRead = $readMap[$cidString] ?? 0;
                $unreadCount = 0;
                foreach ((is_array($messages) ? $messages : []) as $m) {
                    if ($m['from'] === $recent && $m['time'] > $lastRead) $unreadCount++;
                }
            ?>
            <li style="position:relative;">
                <a href='chat.php?cid=<?=htmlspecialchars($cid)?>' class="start-chat-btn" style="padding:10px 0; margin:8px 0 0 0; font-size:1rem; width:80%; display:inline-block; position:relative;">
                    شروع چت با <?=htmlspecialchars($label)?>
                    <?php if ($unreadCount > 0): ?>
                        <span class="unread-badge"><?=$unreadCount?></span>
                    <?php endif; ?>
                </a>
            </li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>
