# Simple PHP Chat

A lightweight, self-hosted one-on-one chat application written in plain PHP with browser-side message encryption. The server stores ciphertext, encrypted private keys, and public keys.

## Features

- One-on-one private messaging between registered users
- Browser-side encryption for message bodies using Web Crypto
- Per-user public/private key pairs with password-encrypted private keys
- CSRF protection on all state-changing requests
- Rate-limited login to prevent brute-force attacks
- Session-secured with HttpOnly, SameSite=Strict cookies
- No database required — file-based storage
- RTL (Persian/Farsi) UI out of the box

## Requirements

- PHP 7.4 or higher
- A modern browser with Web Crypto support
- Apache web server with `.htaccess` support enabled (`AllowOverride All`)  
  *(or configure equivalent deny rules in Nginx — see below)*

## Installation

1. **Upload** all files to your web server's document root (or a subdirectory).

2. **Verify permissions** on the `storage/` directory. It must be writable by the web server process:
   ```
   chmod 700 storage/
   ```

3. Open the app in a browser. The first time you enter an email and password, an account is created automatically.

4. On first successful login, the browser generates the user's encryption key pair. The private key is encrypted locally with the account password before it is uploaded to the server.

## Third-party assets

The current UI loads these assets from third-party CDNs at runtime:

- Google Fonts (`Vazirmatn`)
- jsDelivr (`particles.js`)

If you do not want browsers to contact third-party services, self-host these assets locally before deployment.

## Storage

All data is stored under `storage/`:

| Path | Contents |
|---|---|
| `storage/users.json` | Registered users, bcrypt-hashed passwords, public keys, and password-encrypted private keys |
| `storage/messages/` | Ciphertext-only message files (one per conversation) |
| `storage/recent/` | Recent conversation lists per user |
| `storage/read/` | Last-read timestamps for unread badges |
| `storage/ratelimits/` | Login rate-limit counters |

The `storage/.htaccess` file blocks direct HTTP access to this directory on Apache. **Back up and never expose the storage directory publicly.**

## Nginx configuration

If you use Nginx, add this block to your server config to deny access to the storage directory (`.htaccess` is Apache-only):

```nginx
location ^~ /storage/ {
    deny all;
    return 403;
}
```

## Configuration reference

| Environment variable | Description |
|---|---|
| `CHAT_STORAGE_DIR` | Absolute path to the storage directory (default: `<app-root>/storage`) |

## Security notes

- There is no email verification. Anyone who knows a user's email can register before them and claim the account. Only deploy this for a closed group of known users.
- There is no password recovery. Users must remember their password.
- Emails are still stored in plaintext in `storage/users.json`.
- Message bodies are encrypted in the browser, and the server stores only ciphertext plus wrapped message keys.
- User private keys are encrypted locally with the user's password before they are stored on the server.
- This design protects stored chat files from simple server-side file inspection, but it does **not** protect against a malicious server administrator who can change the JavaScript delivered to users or capture credentials during login.
- Always run this application over HTTPS. The `Strict-Transport-Security` header is set automatically when HTTPS is detected.

## License

MIT
