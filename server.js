import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 8000;

app.use(cors());
app.use(express.json());

// Data directory setup
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR);
}

// Helper: Get sharded path
function getPathForCode(code) {
    if (!code || code.length < 2) return null;
    const shard1 = code[0];
    const shard2 = code[1];
    const dir = path.join(DATA_DIR, shard1, shard2);
    
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    return path.join(dir, `${code}.json`);
}

function generateCode(length = 6) {
    const chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let code = '';
    for (let i = 0; i < length; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
}

// API Endpoint
app.post('/api.php', (req, res) => {
    // Simulate network delay for Splash Screen demo
    setTimeout(() => {
        try {
            const { url, ttl_days } = req.body;

            if (!url) return res.status(400).json({ message: 'URL is required' });

            // Collision handling loop
            let code, filePath;
            let attempts = 0;
            do {
                code = generateCode();
                filePath = getPathForCode(code);
                attempts++;
                if (attempts > 10) return res.status(503).json({ message: 'Server busy' });
            } while (fs.existsSync(filePath));

            const now = Date.now();
            const expiresAt = now + (ttl_days * 24 * 60 * 60 * 1000);

            const record = {
                url,
                code,
                created_at: now,
                expires_at: expiresAt
            };

            fs.writeFileSync(filePath, JSON.stringify(record, null, 2));

            const protocol = req.protocol;
            const host = req.get('host');
            const shortUrl = `${protocol}://${host}/${code}`;

            res.json({
                code,
                short_url: shortUrl,
                expires_at: new Date(expiresAt).toISOString(),
                created_at: new Date(now).toISOString()
            });

        } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'Internal Server Error' });
        }
    }, 1500); // Artificial delay of 1.5s
});

// Redirect Endpoint
app.get('/:code', (req, res) => {
    const { code } = req.params;
    const filePath = getPathForCode(code);

    if (filePath && fs.existsSync(filePath)) {
        try {
            const record = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            if (Date.now() > record.expires_at) {
                // Lazy delete
                fs.unlinkSync(filePath);
                return res.status(404).send('Link expired');
            }
            return res.redirect(record.url);
        } catch (e) {
            return res.status(500).send('Error reading link');
        }
    }

    res.status(404).send('Link not found');
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
