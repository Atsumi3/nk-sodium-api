const express = require('express');
const sodium = require('libsodium-wrappers');

const app = express();
app.use(express.json());

(async () => {
    // libsodium の初期化を待つ
    await sodium.ready;

    // サーバ起動時にランダムなシークレットキーを生成
    // ※実運用の場合はキー管理に注意してください
    const key = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES);

    // 暗号化エンドポイント
    app.post('/encrypt', (req, res) => {
        const { message } = req.body;
        if (!message) {
            return res.status(400).json({ error: 'No message provided' });
        }
        const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
        const ciphertext = sodium.crypto_secretbox_easy(message, nonce, key);
        res.json({
            nonce: Buffer.from(nonce).toString('base64'),
            ciphertext: Buffer.from(ciphertext).toString('base64')
        });
    });

    // 復号エンドポイント
    app.post('/decrypt', (req, res) => {
        const { nonce, ciphertext } = req.body;
        if (!nonce || !ciphertext) {
            return res.status(400).json({ error: 'Nonce or ciphertext not provided' });
        }
        try {
            const nonceBuf = Buffer.from(nonce, 'base64');
            const ciphertextBuf = Buffer.from(ciphertext, 'base64');
            const decrypted = sodium.crypto_secretbox_open_easy(ciphertextBuf, nonceBuf, key);
            res.json({ message: Buffer.from(decrypted).toString() });
        } catch (error) {
            res.status(400).json({ error: 'Decryption failed' });
        }
    });

    // サーバ起動
    app.listen(3000, () => {
        console.log('Sodium API running on port 3000');
    });
})();
