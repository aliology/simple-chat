document.addEventListener('DOMContentLoaded', function() {
    const chatBox = document.getElementById('chat-box');
    const form = document.getElementById('chat-form');
    const msgInput = document.getElementById('msg');
    const sendButton = document.getElementById('send-btn');

    if (!chatBox || !form || !msgInput || !sendButton) {
        return;
    }

    if (window.Notification && Notification.permission !== 'granted') {
        Notification.requestPermission();
    }

    let chatWindowFocused = true;
    let lastMsgTime = 0;
    let keepAutoScroll = true;
    let chatReady = false;

    window.addEventListener('focus', function() {
        chatWindowFocused = true;
    });
    window.addEventListener('blur', function() {
        chatWindowFocused = false;
    });

    function isAtBottom() {
        return chatBox.scrollHeight - chatBox.scrollTop - chatBox.clientHeight < 10;
    }

    function setComposerEnabled(enabled, placeholder) {
        msgInput.disabled = !enabled;
        sendButton.disabled = !enabled;
        if (placeholder) {
            msgInput.placeholder = placeholder;
        }
    }

    function appendSystemMessage(text) {
        const wrapper = document.createElement('div');
        wrapper.className = 'theirs';
        wrapper.textContent = text;
        chatBox.appendChild(wrapper);
        chatBox.scrollTop = chatBox.scrollHeight;
    }

    chatBox.addEventListener('scroll', function() {
        keepAutoScroll = isAtBottom();
    });

    function appendMessages(msgs, forceScroll) {
        let added = false;
        for (const m of msgs) {
            if (typeof m.time === 'undefined') {
                continue;
            }
            if (m.time > lastMsgTime) {
                const mine = m.from === window.MY_EMAIL;
                let displayName;
                if (mine) {
                    displayName = 'من';
                } else if (window.EMAIL_NAME_MAP && window.EMAIL_NAME_MAP[m.from]) {
                    displayName = window.EMAIL_NAME_MAP[m.from];
                } else {
                    displayName = m.from;
                }

                const wrapper = document.createElement('div');
                wrapper.className = mine ? 'mine' : 'theirs';

                const nameNode = document.createElement('b');
                nameNode.textContent = displayName + ':';
                wrapper.appendChild(nameNode);
                wrapper.appendChild(document.createTextNode(' ' + (m.text || '') + ' '));

                chatBox.appendChild(wrapper);
                lastMsgTime = m.time;
                added = true;
            }
        }
        if ((forceScroll && added) || (keepAutoScroll && added)) {
            chatBox.scrollTop = chatBox.scrollHeight;
        }
    }

    async function decryptRows(rows) {
        const decrypted = [];
        for (const row of rows) {
            const text = await window.ChatCrypto.decryptMessage(row);
            decrypted.push({
                from: row.from,
                time: row.time,
                text: text
            });
        }
        return decrypted;
    }

    async function loadAllMessages(forceScroll) {
        const response = await fetch('api.php?action=fetch&cid=' + encodeURIComponent(window.CHAT_CID));
        const rows = await response.json();
        const messages = await decryptRows(rows);
        chatBox.innerHTML = '';
        lastMsgTime = 0;
        appendMessages(messages, forceScroll);
    }

    async function pollNewMessages() {
        const response = await fetch('api.php?action=fetch&cid=' + encodeURIComponent(window.CHAT_CID) + '&last=' + lastMsgTime);
        const rows = await response.json();
        const messages = await decryptRows(rows);

        let notify = false;
        let notifyMsg = '';
        let notifySender = '';

        messages.forEach(function(message) {
            if (message.from !== window.MY_EMAIL && !chatWindowFocused) {
                notify = true;
                notifyMsg = message.text;
                notifySender = window.EMAIL_NAME_MAP[message.from] || message.from;
            }
        });

        appendMessages(messages, false);

        if (notify && window.Notification && Notification.permission === 'granted') {
            new Notification('پیام جدید', {
                body: notifySender + ': ' + notifyMsg,
                icon: 'assets/chat-icon.png'
            });
        }
    }

    function autoResize() {
        msgInput.style.height = 'auto';
        msgInput.style.height = msgInput.scrollHeight + 'px';
    }

    msgInput.addEventListener('input', autoResize);

    msgInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
        }
    });

    form.onsubmit = async function(e) {
        e.preventDefault();
        if (!chatReady || !msgInput.value.trim()) {
            return;
        }

        try {
            const payload = await window.ChatCrypto.encryptMessageFor(window.OTHER_EMAIL, window.OTHER_PUBLIC_KEY, msgInput.value.trim());
            const response = await fetch('api.php', {
                method: 'POST',
                body: new URLSearchParams({
                    action: 'send',
                    cid: window.CHAT_CID,
                    payload: JSON.stringify(payload),
                    csrf_token: window.CSRF_TOKEN || ''
                })
            });
            if (!response.ok) {
                throw new Error('ارسال پیام انجام نشد.');
            }

            msgInput.value = '';
            autoResize();
            await loadAllMessages(true);
        } catch (error) {
            window.ChatCrypto.setStatus(error.message || 'ارسال پیام انجام نشد.', true);
        }
    };

    async function initializeChat() {
        if (!window.ChatCrypto || !window.ChatCrypto.supportsRequiredCrypto()) {
            setComposerEnabled(false, 'مرورگر شما از رمزنگاری لازم پشتیبانی نمی‌کند.');
            appendSystemMessage('مرورگر شما از رمزنگاری لازم برای این چت پشتیبانی نمی‌کند.');
            return;
        }

        setComposerEnabled(false, 'در حال آماده‌سازی رمزنگاری...');

        try {
            await window.ChatCrypto.ensureCurrentUserReady();
        } catch (error) {
            setComposerEnabled(false, 'برای باز کردن چت باید رمز عبور را وارد کنید.');
            appendSystemMessage(error.message || 'راه‌اندازی رمزنگاری انجام نشد.');
            return;
        }

        if (!window.ChatCrypto.hasPeerPublicKey(window.OTHER_PUBLIC_KEY)) {
            setComposerEnabled(false, 'این مخاطب هنوز کلید عمومی خود را ایجاد نکرده است.');
            appendSystemMessage('این مخاطب هنوز یک بار وارد حساب خود نشده تا کلید رمزنگاری مرورگر ایجاد شود.');
            try {
                await loadAllMessages(true);
            } catch (error) {
                window.ChatCrypto.setStatus('بارگذاری پیام‌ها انجام نشد.', true);
            }
            return;
        }

        setComposerEnabled(true, 'پیام خود را بنویسید...');
        chatReady = true;

        try {
            await loadAllMessages(true);
        } catch (error) {
            window.ChatCrypto.setStatus('بارگذاری پیام‌ها انجام نشد.', true);
        }

        setInterval(function() {
            pollNewMessages().catch(function() {
                window.ChatCrypto.setStatus('به‌روزرسانی پیام‌ها انجام نشد.', true);
            });
        }, 2000);
    }

    autoResize();
    initializeChat();
});
