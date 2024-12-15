const express = require('express');
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const SECRET = 'topsecret';

app.use(express.json())
app.use(require('cors')())

// Signature validation function
function isValidSignature(requestBody, receivedSignature) {
    const expectedSignature = crypto
        .createHmac('sha256', SECRET)
        .update(JSON.stringify(requestBody))
        .digest('hex');

    console.error("Bad webhook signature. Received " + receivedSignature)
    console.error("Expected " + expectedSignature)

    return crypto.timingSafeEqual(
        Buffer.from(expectedSignature, 'utf8'),
        Buffer.from(receivedSignature, 'utf8')
    );
}

app.post('/', (req, res) => {
    const receivedSignature = req.headers['x-flagsmith-signature'];
    if (!receivedSignature || !isValidSignature(req.body, receivedSignature)) {
        return res.status(401).send('Invalid signature');
    }
    console.log('Webhook received:', req.body.toString());
    res.status(200).send('Webhook processed');
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
