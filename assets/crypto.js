(() => {
    'use strict';

    const PRIVATE_JWK_KEY = 'chat_unlocked_private_jwk';
    const PRIVATE_EMAIL_KEY = 'chat_unlocked_private_email';
    const PENDING_AUTH_KEY = 'chat_pending_auth';
    const PBKDF2_ITERATIONS = 210000;
    const PRIVATE_BOX_VERSION = 'pbkdf2-aes-gcm-v1';
    const MESSAGE_VERSION = 'e2ee-v1';
    const USER_CRYPTO_VERSION = 'e2ee-rsa-oaep-aes-gcm-v1';
    const textEncoder = new TextEncoder();
    const textDecoder = new TextDecoder();

    let readyPromise = null;

    function normalizeEmail(value) {
        return String(value || '').trim().toLowerCase();
    }

    function supportsRequiredCrypto() {
        return !!(window.crypto && window.crypto.subtle && window.TextEncoder && window.TextDecoder);
    }

    function statusNode() {
        return document.getElementById('crypto-status');
    }

    function setStatus(message, isError) {
        const node = statusNode();
        if (!node) {
            return;
        }

        node.textContent = message || '';
        node.style.color = isError ? '#ffd7d7' : '#f3f4f6';
    }

    function readSession(key) {
        try {
            return window.sessionStorage.getItem(key);
        } catch (error) {
            return null;
        }
    }

    function writeSession(key, value) {
        try {
            window.sessionStorage.setItem(key, value);
        } catch (error) {
            // Ignore storage failures and continue with in-memory state only.
        }
    }

    function removeSession(key) {
        try {
            window.sessionStorage.removeItem(key);
        } catch (error) {
            // Ignore storage failures.
        }
    }

    function clearSessionSecrets() {
        removeSession(PRIVATE_JWK_KEY);
        removeSession(PRIVATE_EMAIL_KEY);
        removeSession(PENDING_AUTH_KEY);
    }

    function savePendingPassword(email, password) {
        if (!email || !password) {
            return;
        }

        writeSession(PENDING_AUTH_KEY, JSON.stringify({
            email: normalizeEmail(email),
            password: String(password)
        }));
    }

    function takePendingPassword(email) {
        const raw = readSession(PENDING_AUTH_KEY);
        if (!raw) {
            return '';
        }

        try {
            const parsed = JSON.parse(raw);
            if (normalizeEmail(parsed.email) === normalizeEmail(email) && typeof parsed.password === 'string') {
                removeSession(PENDING_AUTH_KEY);
                return parsed.password;
            }
        } catch (error) {
            // Ignore malformed session data.
        }

        return '';
    }

    function saveUnlockedPrivateJwk(email, jwk) {
        if (!email || !jwk) {
            return;
        }

        writeSession(PRIVATE_EMAIL_KEY, normalizeEmail(email));
        writeSession(PRIVATE_JWK_KEY, JSON.stringify(jwk));
    }

    function loadUnlockedPrivateJwk(email) {
        const savedEmail = normalizeEmail(readSession(PRIVATE_EMAIL_KEY));
        const rawJwk = readSession(PRIVATE_JWK_KEY);
        if (!rawJwk || savedEmail !== normalizeEmail(email)) {
            return null;
        }

        try {
            return JSON.parse(rawJwk);
        } catch (error) {
            return null;
        }
    }

    function bytesToBase64(bytes) {
        let binary = '';
        const chunkSize = 0x8000;
        for (let index = 0; index < bytes.length; index += chunkSize) {
            const slice = bytes.subarray(index, Math.min(index + chunkSize, bytes.length));
            binary += String.fromCharCode.apply(null, slice);
        }
        return window.btoa(binary);
    }

    function base64ToBytes(value) {
        const binary = window.atob(String(value || ''));
        const bytes = new Uint8Array(binary.length);
        for (let index = 0; index < binary.length; index += 1) {
            bytes[index] = binary.charCodeAt(index);
        }
        return bytes;
    }

    async function derivePasswordKey(password, salt, usages) {
        const baseKey = await window.crypto.subtle.importKey(
            'raw',
            textEncoder.encode(String(password)),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        return window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: PBKDF2_ITERATIONS,
                hash: 'SHA-256'
            },
            baseKey,
            {
                name: 'AES-GCM',
                length: 256
            },
            false,
            usages
        );
    }

    async function importPublicKey(jwk) {
        return window.crypto.subtle.importKey(
            'jwk',
            jwk,
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256'
            },
            true,
            ['encrypt']
        );
    }

    async function importPrivateKey(jwk) {
        return window.crypto.subtle.importKey(
            'jwk',
            jwk,
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256'
            },
            true,
            ['decrypt']
        );
    }

    async function createPrivateKeyBox(password, privateJwk) {
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const wrappingKey = await derivePasswordKey(password, salt, ['encrypt']);
        const ciphertext = new Uint8Array(await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            wrappingKey,
            textEncoder.encode(JSON.stringify(privateJwk))
        ));

        return {
            version: PRIVATE_BOX_VERSION,
            salt: bytesToBase64(salt),
            iv: bytesToBase64(iv),
            ciphertext: bytesToBase64(ciphertext),
            iterations: PBKDF2_ITERATIONS
        };
    }

    async function openPrivateKeyBox(password, box) {
        const wrappingKey = await derivePasswordKey(password, base64ToBytes(box.salt), ['decrypt']);
        const plaintext = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: base64ToBytes(box.iv)
            },
            wrappingKey,
            base64ToBytes(box.ciphertext)
        );

        return JSON.parse(textDecoder.decode(plaintext));
    }

    async function generateUserKeys(password) {
        const pair = await window.crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            true,
            ['encrypt', 'decrypt']
        );

        const publicJwk = await window.crypto.subtle.exportKey('jwk', pair.publicKey);
        const privateJwk = await window.crypto.subtle.exportKey('jwk', pair.privateKey);
        const privateKeyBox = await createPrivateKeyBox(password, privateJwk);

        return {
            publicJwk: publicJwk,
            privateJwk: privateJwk,
            privateKeyBox: privateKeyBox,
            publicKey: pair.publicKey,
            privateKey: pair.privateKey
        };
    }

    async function postKeyMaterial(publicKey, privateKeyBox) {
        const response = await window.fetch('api.php', {
            method: 'POST',
            body: new URLSearchParams({
                action: 'store_keys',
                csrf_token: window.CSRF_TOKEN || '',
                public_key: JSON.stringify(publicKey),
                private_key_box: JSON.stringify(privateKeyBox)
            })
        });

        if (!response.ok) {
            throw new Error('ذخیره کلیدهای رمزنگاری روی سرور انجام نشد.');
        }
    }

    async function ensureCurrentUserReady() {
        if (readyPromise) {
            return readyPromise;
        }

        readyPromise = (async () => {
            if (!supportsRequiredCrypto()) {
                throw new Error('مرورگر شما از رمزنگاری لازم برای این چت پشتیبانی نمی‌کند.');
            }

            const currentUser = window.CURRENT_USER_CRYPTO || null;
            const email = normalizeEmail(currentUser && currentUser.email);
            if (!currentUser || !email) {
                throw new Error('اطلاعات کاربر برای راه‌اندازی رمزنگاری در دسترس نیست.');
            }

            let privateJwk = loadUnlockedPrivateJwk(email);
            const hasStoredKeys = !!(currentUser.publicKey && currentUser.privateKeyBox);

            if (!hasStoredKeys) {
                setStatus('در حال ساخت کلیدهای رمزنگاری گفتگوها...');
                let password = takePendingPassword(email);
                if (!password) {
                    password = window.prompt('برای فعال‌سازی رمزنگاری گفتگوها، رمز عبور حساب را دوباره وارد کنید:') || '';
                }
                if (!password) {
                    throw new Error('برای فعال‌سازی رمزنگاری باید رمز عبور حساب را وارد کنید.');
                }

                const generated = await generateUserKeys(password);
                await postKeyMaterial(generated.publicJwk, generated.privateKeyBox);

                currentUser.publicKey = generated.publicJwk;
                currentUser.privateKeyBox = generated.privateKeyBox;
                currentUser.cryptoVersion = USER_CRYPTO_VERSION;
                privateJwk = generated.privateJwk;
                saveUnlockedPrivateJwk(email, privateJwk);
                setStatus('رمزنگاری مرورگر برای این حساب فعال شد.', false);

                return {
                    email: email,
                    publicKey: generated.publicKey,
                    privateKey: generated.privateKey,
                    publicJwk: generated.publicJwk,
                    privateJwk: generated.privateJwk
                };
            }

            if (!privateJwk) {
                setStatus('در حال باز کردن کلید خصوصی گفتگوها...');
                let password = takePendingPassword(email);
                if (!password) {
                    password = window.prompt('برای باز کردن گفتگوهای رمزنگاری‌شده، رمز عبور حساب را وارد کنید:') || '';
                }
                if (!password) {
                    throw new Error('برای باز کردن گفتگوها باید رمز عبور حساب را وارد کنید.');
                }

                try {
                    privateJwk = await openPrivateKeyBox(password, currentUser.privateKeyBox);
                } catch (error) {
                    throw new Error('رمز عبور برای باز کردن کلید خصوصی صحیح نیست.');
                }

                saveUnlockedPrivateJwk(email, privateJwk);
            }

            setStatus('رمزنگاری مرورگر فعال است.', false);
            return {
                email: email,
                publicKey: await importPublicKey(currentUser.publicKey),
                privateKey: await importPrivateKey(privateJwk),
                publicJwk: currentUser.publicKey,
                privateJwk: privateJwk
            };
        })().catch((error) => {
            readyPromise = null;
            setStatus(error.message || 'راه‌اندازی رمزنگاری انجام نشد.', true);
            throw error;
        });

        return readyPromise;
    }

    async function encryptMessageFor(otherEmail, otherPublicJwk, plaintext) {
        const ready = await ensureCurrentUserReady();
        const normalizedOtherEmail = normalizeEmail(otherEmail);
        if (!normalizedOtherEmail || !otherPublicJwk) {
            throw new Error('کلید عمومی مخاطب هنوز در دسترس نیست.');
        }

        const otherPublicKey = await importPublicKey(otherPublicJwk);
        const contentKey = await window.crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true,
            ['encrypt', 'decrypt']
        );
        const rawContentKey = new Uint8Array(await window.crypto.subtle.exportKey('raw', contentKey));
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = new Uint8Array(await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            contentKey,
            textEncoder.encode(String(plaintext))
        ));

        const wrappedForMe = new Uint8Array(await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, ready.publicKey, rawContentKey));
        const wrappedForOther = new Uint8Array(await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, otherPublicKey, rawContentKey));

        return {
            version: MESSAGE_VERSION,
            ciphertext: bytesToBase64(ciphertext),
            iv: bytesToBase64(iv),
            keys: {
                [ready.email]: bytesToBase64(wrappedForMe),
                [normalizedOtherEmail]: bytesToBase64(wrappedForOther)
            }
        };
    }

    async function decryptMessage(messageRow) {
        const ready = await ensureCurrentUserReady();
        const wrappedKey = messageRow && messageRow.keys ? messageRow.keys[ready.email] : null;
        if (!wrappedKey) {
            return 'کلید این پیام برای حساب شما موجود نیست.';
        }

        try {
            const rawContentKey = await window.crypto.subtle.decrypt(
                { name: 'RSA-OAEP' },
                ready.privateKey,
                base64ToBytes(wrappedKey)
            );
            const contentKey = await window.crypto.subtle.importKey(
                'raw',
                rawContentKey,
                { name: 'AES-GCM' },
                false,
                ['decrypt']
            );
            const plaintext = await window.crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: base64ToBytes(messageRow.iv)
                },
                contentKey,
                base64ToBytes(messageRow.ciphertext)
            );

            return textDecoder.decode(plaintext);
        } catch (error) {
            return 'پیام رمزگشایی نشد';
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        const authForm = document.getElementById('auth-form');
        if (authForm) {
            authForm.addEventListener('submit', () => {
                const emailField = authForm.querySelector('input[name="email"]');
                const passwordField = authForm.querySelector('input[name="password"]');
                savePendingPassword(emailField ? emailField.value : '', passwordField ? passwordField.value : '');
            });
        }

        const logoutForm = document.getElementById('logout-form');
        if (logoutForm) {
            logoutForm.addEventListener('submit', () => {
                clearSessionSecrets();
            });
        }

        if (window.CURRENT_USER_CRYPTO && window.CURRENT_USER_CRYPTO.email) {
            ensureCurrentUserReady().catch(() => {
                // The page-specific scripts handle the surfaced error state.
            });
        }
    });

    window.ChatCrypto = {
        clearSessionSecrets: clearSessionSecrets,
        decryptMessage: decryptMessage,
        encryptMessageFor: encryptMessageFor,
        ensureCurrentUserReady: ensureCurrentUserReady,
        hasPeerPublicKey: function(otherPublicJwk) {
            return !!otherPublicJwk;
        },
        setStatus: setStatus,
        supportsRequiredCrypto: supportsRequiredCrypto
    };
})();
