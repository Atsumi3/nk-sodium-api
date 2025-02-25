const express = require('express');
const sodium = require('libsodium-wrappers');

const app = express();
app.use(express.json());

(async () => {
    await sodium.ready;

    /**
     * POST /encrypt
     * リクエストボディで { text, publicKey } を受け取り、
     * crypto_box_seal を用いて暗号化し、結果を base64 エンコードで返す。
     *
     * - text: 暗号化対象の平文
     * - publicKey: 公開鍵（base64 エンコード済み）
     */
    app.post('/encrypt', (req, res) => {
        const { text, publicKey } = req.body;
        if (!text || !publicKey) {
            return res.status(400).json({ error: 'No text or publicKey provided' });
        }

        try {
            // 公開鍵は base64 で受け取っているため、デコードして Uint8Array に変換
            const publicKeyBuf = Buffer.from(publicKey, 'base64');

            // 平文を Uint8Array に変換
            const message = sodium.from_string(text);

            // crypto_box_seal で暗号化（復号には対応する秘密鍵が必要）
            const ciphertext = sodium.crypto_box_seal(message, publicKeyBuf);

            // 暗号化結果を base64 エンコードして返却
            res.json({ encrypted: Buffer.from(ciphertext).toString('base64') });
        } catch (error) {
            res.status(500).json({ error: 'Encryption failed: ' + error.message });
        }
    });

    // ※ crypto_box_seal は一方向のシールボックス方式のため、ここでの復号エンドポイントは通常不要です。

    app.listen(3000, () => {
        console.log('Sodium API running on port 3000');
    });
})();
