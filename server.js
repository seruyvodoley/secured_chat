const express = require('express');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const pool = require('./db');
const cookieParser = require('cookie-parser'); // Подключаем cookie-parser
const fs = require('fs');
const https = require('https');
const crypto = require('crypto'); // Для безопасной генерации больших чиселс

// Загрузка SSL-сертификатов
const sslOptions = {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.cert'),
};

// Загрузка переменных окружения
dotenv.config();

const authRouter = require('./routes/auth');

const app = express();
app.use((req, res, next) => {
    console.log('Setting security headers');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'no-referrer-when-downgrade');
    next();
});


const httpsServer = https.createServer(sslOptions, app);
const io = new Server(httpsServer);

const userKeys = {}; // { username: sharedSecret }

app.use(express.json());
app.use(express.static('public'));
app.use(cookieParser()); // Добавляем middleware для обработки куков
app.use('/auth', authRouter); // Маршруты авторизации


io.on('connection', (socket) => {
    console.log(`New client connected: ${socket.id}`);
    if (userKeys[socket.username]) {
        console.log(`Duplicate connection detected for user: ${socket.username}`);
        socket.disconnect();
        return;
    }

    socket.emit('all-keys', userKeys); 

    const generateBigPrime = (length) => {
        while (true) {
            const primeCandidate = crypto.randomInt(10 ** (length - 1), 10 ** length);
            if (isPrime(primeCandidate)) return primeCandidate;
        }
    };

    const isPrime = (num) => {
        if (num <= 1) return false;
        if (num <= 3) return true;
        if (num % 2 === 0 || num % 3 === 0) return false;
        for (let i = 5; i * i <= num; i += 6) {
            if (num % i === 0 || num % (i + 2) === 0) return false;
        }
        return true;
    };

    const p = generateBigPrime(10);
    const g = crypto.randomInt(2, p - 1); // Генератор меньше `p`
    const privateKey = crypto.randomInt(10 ** 5, 10 ** 6); // Приватный ключ
    const publicKey = BigInt(g) ** BigInt(privateKey) % BigInt(p); // Открытый ключ
    socket.emit('dh-params', { p, g, serverPublicKey: publicKey.toString() });

    let isAuthenticated = false;

    socket.on('dh-key-exchange', (clientPublicKey) => {
        if (socket.sharedSecret) {
            return;
        }
        const sharedSecret = BigInt(clientPublicKey) ** BigInt(privateKey) % BigInt(p);
        socket.sharedSecret = sharedSecret.toString(); // Общий секрет в строке
        socket.emit('dh-complete');
    });

    socket.on('authenticate', (encryptedData) => {
        if (isAuthenticated) {
            return;
        }
        try {
            console.log('Encrypted data:', encryptedData);
            const decryptedData = decryptMessage(encryptedData, socket.sharedSecret);
            console.log('Decrypted data:', decryptedData); // Логируем расшифрованные данные
    
            const { username, password } = JSON.parse(decryptedData);
            console.log('Decrypted username:', username);
            console.log('Decrypted password:', password);
    
            pool.query('SELECT * FROM users WHERE username = $1', [username], async (err, result) => {
                if (err) {
                    console.error('Database error:', err);
                    socket.emit('auth-failure', { message: 'Authentication failed' });
                    return;
                }
    
                const user = result.rows[0];
                if (!user) {
                    console.log('User not found');
                    socket.emit('auth-failure', { message: 'Invalid username or password' });
                    return;
                }
    
                const passwordMatch = await bcrypt.compare(password, user.password_hash);
                console.log('Password match:', passwordMatch);
                if (!passwordMatch) {
                    socket.emit('auth-failure', { message: 'Invalid username or password' });
                    return;
                }
    
                isAuthenticated = true;
                socket.username = username;
                userKeys[username] = socket.sharedSecret;
                socket.emit('auth-success', { message: 'Authentication successful'});
                io.emit('update-keys', { username, sharedSecret: socket.sharedSecret });
                const messageId = Math.random().toString(36).substring(2);
                // Дополнительные действия, например, обновление ключей
                io.emit('message', {
                    username: 'System',
                    message: `${socket.username} has joined the chat!`,
                    messageId  // Добавляем уникальный ID
                });
            });
        } catch (err) {
            console.error('Decryption error:', err);
            socket.emit('auth-failure', { message: 'Decryption failed' });
        }
    });

    // Обработка входящих сообщений
    socket.on('message', (encryptedMessage) => {
        const messageId = Math.random().toString(36).substring(2);
        console.log(`Message received from ${socket.id}:`, encryptedMessage);
        console.log('Received message from:', socket.username);
    
        // Отправляем всем кроме отправителя
            io.emit('message', {
            username: socket.username,
            message: encryptedMessage,
            messageId,  // Добавляем уникальный ID
        });
    });
    
    socket.on('disconnect', () => {
        const username = socket.username; 
        if (username) {
            io.emit('user-disconnected', { username }); // Уведомляем всех
            console.log(`${username} disconnected`);
        }
    });
    
    
});

// Функция для дешифрования сообщения
function decryptMessage(encryptedMessage, sharedSecret) {
    return String.fromCharCode(...encryptedMessage.map(char => char ^ sharedSecret));
}



app.post('/login', (req, res, socket) => {
    const { username, password } = req.body;

    pool.query('SELECT * FROM users WHERE username = $1', [username], async (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        const user = result.rows[0];
        if (!user) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const token = jwt.sign({ socket: socket.id, ip: req.ip }, process.env.JWT_SECRET, { expiresIn: '1h' });
        console.log(req.ip)
        res.cookie('token', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 3600000 // 1 час
        });
        console.log(`coockies sent to client`)
        res.json({ message: 'Login successful' });
    });
});
app.post('/logout', (req, res) => {
    res.clearCookie('token', { httpOnly: true, secure: true, sameSite: 'strict' });
    res.json({ message: 'Logged out successfully' });
            const username = socket.username;
        if (username) {
            io.emit('user-disconnected', { username }); // Уведомляем всех
            console.log(`${username} disconnected`);
        }
});



const PORT = process.env.PORT || 3050;
httpsServer.listen(PORT, () => {
    console.log(`Secure server running on https://localhost:${PORT}`);
});