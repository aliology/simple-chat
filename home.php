<?php
require_once __DIR__ . '/bootstrap.php';

app_bootstrap_session();
$myEmail = require_logged_in_user_or_redirect();
$users = app_users();
$search = normalize_email($_GET['search'] ?? '');
$foundUser = null;

$emailMap = app_email_name_map($users);
$myUser = app_user_record($myEmail, $users);

if ($search) {
    foreach ($users as $user) {
        $userEmail = normalize_email($user['email'] ?? '');
        if ($userEmail !== $myEmail && $userEmail === $search) {
            $foundUser = $userEmail;
            break;
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['logout'])) {
    verify_csrf_or_abort($_POST['csrf_token'] ?? '');
    destroy_session();
    header('Location: index.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="fa" class="home-page">
<head>
    <meta charset="utf-8">
    <title>صفحه اصلی چت</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="assets/styles.css?v=<?=filemtime(__DIR__.'/assets/styles.css')?>">
</head>
<body class="home-page">
<div id="particles-js"></div>

<div class="top-bar">
    <span>وارد شده با: <?=htmlspecialchars($emailMap[$myEmail] ?: $myEmail)?></span>
    <span id="crypto-status" style="font-size:0.9rem; opacity:0.95;">در حال آماده‌سازی رمزنگاری...</span>
    <form method="POST" id="logout-form" style="margin:0;">
        <input type="hidden" name="csrf_token" value="<?=htmlspecialchars(csrf_token())?>">
        <button type="submit" name="logout" value="1" style="background:none; border:none; color:#fff; cursor:pointer; font:inherit; padding:0;">خروج</button>
    </form>
</div>

<h2 style="text-align:right;">یافتن کاربر برای چت (ایمیل دقیق را وارد کنید)</h2>
<form method="GET" class="search-form">
    <input type="text" name="search" value="<?=htmlspecialchars($search)?>" placeholder="ایمیل مخاطب مورد نظر را وارد کنید">
    <button type="submit">جستجو</button>
</form>

<div id="recent-chats-section">
    <?php include 'recent_chats.php'; ?>
</div>

<?php if ($search): ?>
    <?php if ($foundUser): 
        $cid = urlencode(build_cid($myEmail, $foundUser));
        $label = $emailMap[$foundUser] ?: $foundUser;
        ?>
        <a href='chat.php?cid=<?=htmlspecialchars($cid)?>' class="glass-btn">شروع چت با <?=htmlspecialchars($label)?></a>
    <?php else: ?>
        <div class="error" style="margin-top: 24px;">هیچ کاربری با این ایمیل یافت نشد.</div>
    <?php endif; ?>
<?php endif; ?>

<script>
window.CSRF_TOKEN = "<?=htmlspecialchars(csrf_token())?>";
window.CURRENT_USER_CRYPTO = <?=json_encode([
    'email' => $myEmail,
    'cryptoVersion' => is_array($myUser) ? ($myUser['crypto_version'] ?? null) : null,
    'publicKey' => is_array($myUser) ? ($myUser['public_key'] ?? null) : null,
    'privateKeyBox' => is_array($myUser) ? ($myUser['private_key_box'] ?? null) : null,
], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG)?>;
</script>
<script src="assets/crypto.js?v=<?=filemtime(__DIR__.'/assets/crypto.js')?>"></script>
<script>
setInterval(function() {
    fetch('recent_chats.php')
        .then(res => res.text())
        .then(html => {
            document.getElementById('recent-chats-section').innerHTML = html;
        });
}, 4000);
</script>

<script src="https://cdn.jsdelivr.net/npm/particles.js@2.0.0/particles.min.js"></script>
<script>
    var particlesInteractive = !(window.matchMedia && window.matchMedia('(pointer: coarse)').matches);

    particlesJS("particles-js", {
      particles: {
        number: { value: 50 },
        color: { value: "#f3e8ff" },
        shape: { type: "circle" },
        opacity: { value: 0.4 },
        size: { value: 3 },
        line_linked: {
          enable: true, distance: 150,
          color: "#e9d5ff", opacity: 0.3, width: 1
        },
        move: { enable: true, speed: 1, random: true, out_mode: "out" }
      },
      interactivity: {
        detect_on: "canvas",
        events: { onhover: { enable: particlesInteractive, mode: "repulse" }, resize: true },
        modes: { repulse: { distance: 80, duration: 0.4 } }
      },
      retina_detect: true
    });
</script>

</body>
</html>
