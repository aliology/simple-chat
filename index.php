<?php
require_once __DIR__ . '/bootstrap.php';

app_bootstrap_session();

$error = '';
$name = '';
$email = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf_or_abort($_POST['csrf_token'] ?? '');

    $users = app_users();
    $rawEmail = strtolower(trim((string) ($_POST['email'] ?? '')));
    $email = normalize_email($_POST['email'] ?? '');
    $password = (string) ($_POST['password'] ?? '');
    $name = normalize_name($_POST['name'] ?? '');
    $loginBucket = $rawEmail . '|' . client_ip_address();

    if (!$email || !$password) {
        $error = 'لطفاً همه فیلدها را پر کنید.';
    } elseif (strlen($password) > 255) {
        $error = 'رمز عبور نامعتبر است.';
    } elseif (rate_limit_is_blocked('login', $loginBucket, APP_LOGIN_ATTEMPT_LIMIT, APP_LOGIN_ATTEMPT_WINDOW)) {
        $error = 'تعداد تلاش‌های ورود بیش از حد مجاز است. چند دقیقه دیگر دوباره تلاش کنید.';
    } else {
        $found = false;
        foreach ($users as &$user) {
            if (normalize_email($user['email'] ?? '') === $email) {
                $found = &$user;
                break;
            }
        }
        unset($user);
        if ($found) {
            if (password_verify($password, $found['password'])) {
                session_regenerate_id(true);
                $_SESSION['user'] = $email;
                $needsWrite = false;
                if (password_needs_rehash($found['password'], PASSWORD_DEFAULT)) {
                    foreach ($users as &$storedUser) {
                        if (normalize_email($storedUser['email'] ?? '') === $email) {
                            $storedUser['password'] = password_hash($password, PASSWORD_DEFAULT);
                            $needsWrite = true;
                            break;
                        }
                    }
                    unset($storedUser);
                }
                if ($name !== '' && (!isset($found['name']) || $found['name'] !== $name)) {
                    foreach ($users as &$storedUser) {
                        if (normalize_email($storedUser['email'] ?? '') === $email) {
                            $storedUser['name'] = $name;
                            $needsWrite = true;
                            break;
                        }
                    }
                    unset($storedUser);
                }
                if ($needsWrite) {
                    json_write_file(APP_USERS_FILE, $users);
                }
                rate_limit_clear('login', $loginBucket);
                header('Location: home.php'); exit;
            } else {
                rate_limit_record_failure('login', $loginBucket, APP_LOGIN_ATTEMPT_WINDOW);
                $error = 'رمز عبور اشتباه است.';
            }
        } else {
            $newUser = ['email' => $email, 'password' => password_hash($password, PASSWORD_DEFAULT)];
            if ($name !== '') $newUser['name'] = $name;
            $users[] = $newUser;
            json_write_file(APP_USERS_FILE, $users);
            rate_limit_clear('login', $loginBucket);
            session_regenerate_id(true);
            $_SESSION['user'] = $email;
            header('Location: home.php'); exit;
        }
    }
} elseif (isset($_SESSION['user'])) {
    $users = app_users();
    $email = current_user_email();
    foreach ($users as $user) {
        if (normalize_email($user['email'] ?? '') === $email) {
            $name = normalize_name($user['name'] ?? '');
            break;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl" class="login-page">
<head>
    <meta charset="utf-8">
    <title>ورود / ثبت‌نام چت</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="assets/styles.css?v=<?=filemtime(__DIR__.'/assets/styles.css')?>">
</head>
<body class="flex items-center justify-center min-h-screen login-page">
    <div id="particles-js"></div>
    <div class="login-box">
        <h2>ورود / ثبت‌نام</h2>
        <?php if ($error): ?><div class="error"><?=htmlspecialchars($error)?></div><?php endif; ?>
        <form method="POST" id="auth-form">
            <input type="hidden" name="csrf_token" value="<?=htmlspecialchars(csrf_token())?>">
            <input type="email" name="email" placeholder="ایمیل" required value="<?=htmlspecialchars($email)?>">
            <input type="password" name="password" placeholder="رمز عبور" required>
            <input type="text" name="name" placeholder="نام (اختیاری)" value="<?=htmlspecialchars($name)?>">
            <button type="submit">ورود / ثبت‌نام / بروزرسانی نام</button>
        </form>
        <ul class="helper-text better-list">
            <li>ثبت‌نام فقط با ایمیل انجام می‌شود و نیازی به تأیید ایمیل نیست.</li>
            <li>با اولین ورود، حساب کاربری با همان ایمیل ساخته می‌شود. اگر قبلاً ثبت‌نام کرده‌اید، وارد خواهید شد.</li>
            <li>در صورت تمایل می‌توانید نام خود را وارد یا تغییر دهید؛ این نام به جای ایمیل نمایش داده خواهد شد.</li>
            <li>پس از اولین ورود موفق، مرورگر شما کلیدهای رمزنگاری گفتگو را می‌سازد و کلید خصوصی را به صورت رمز‌شده با رمز عبور شما روی سرور ذخیره می‌کند.</li>
            <li>پس از ورود، برای شروع چت کافیست ایمیل فرد مورد نظر را در کادر جستجو وارد و جستجو کنید. اگر کاربر وجود داشت، دکمه "شروع چت" نمایش داده می‌شود.</li>
            <li>با توجه به عدم تایید ایمیل امکان بازیابی یا تغییر رمز عبور وجود ندارد؛ لطفاً رمز عبور خود را به خاطر بسپارید.</li>
            <li>ایمیل کاربران در فایل کاربران ذخیره می‌شود و متن پیام‌ها در مرورگر رمز می‌شوند؛ با این حال یک مدیر سرور بدخواه همچنان می‌تواند با تغییر کد سمت کاربر به اطلاعات دسترسی پیدا کند.</li>
            <li>پیام‌ها به صورت خودکار حذف نمی‌شوند. اگر به حذف دوره‌ای نیاز دارید، باید آن را جداگانه پیاده‌سازی کنید.</li>
        </ul>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/particles.js@2.0.0/particles.min.js"></script>
    <script src="assets/crypto.js?v=<?=filemtime(__DIR__.'/assets/crypto.js')?>"></script>
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
