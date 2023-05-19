const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Метод для генерації хешу пароля
async function hashPassword(password) {
    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(password, salt);
    return hashedPassword;
}

// Метод для перевірки пароля
async function verifyPassword(password, hashedPassword) {
    return await bcrypt.compare(password, hashedPassword);
}

// Метод для генерації JWT токена
function generateToken(userId) {
    const secretKey = 'your_secret_key'; // Замініть на свій секретний ключ
    const expiresIn = '1h';

    const token = jwt.sign({ userId }, secretKey, { expiresIn });
    return token;
}

// Маршрут для реєстрації нового користувача
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Генерація хешу пароля
    const hashedPassword = await hashPassword(password);

    // Збереження користувача в базі даних (в цьому прикладі просто виводимо хеш пароля)
    console.log(`Username: ${username}`);
    console.log(`Hashed Password: ${hashedPassword}`);

    res.status(201).send('User registered successfully.');
});

// Маршрут для авторизації користувача
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Перевірка користувача в базі даних (в цьому прикладі просто виконуємо перевірку пароля)
    const isValidPassword = await verifyPassword(password, hashedPasswordFromDatabase); // Потрібно отримати хеш пароля з бази даних

    if (isValidPassword) {
        // Генерація JWT токена
        const token = generateToken(userId); // Потрібно отримати ID користувача з бази даних

        res.json({ token });
    } else {
        res.status(401).send('Invalid username or password.');
    }
});

// Захищений маршрут, що потребує авторизації
app.get('/protected', (req, res) => {
    // Перевірка наявності та валідація JWT токена
    const token = req.headers.authorization;

    if (!token) {
        return res.status(401).send('Access denied. No token provided.');
    }

    try {
        const decoded = jwt.verify(token, 'your_secret_key'); // Замініть на свій секретний ключ
        // Виконайте потрібні дії з валідним JWT токеном (наприклад, отримайте ID користувача та відобразіть захищені дані)

        res.send('Protected data');
    } catch (error) {
        res.status(400).send('Invalid token.');
    }
});

// Порт сервера
const port = 3000;

// Запуск сервера
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
