const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const {MongoClient} = require('mongodb');
require("dotenv").config();

// Порт сервера
const port = process.env.PORT;
const app = express();
app.use(express.json());

const uri = process.env.MONGO_URL;
const client = new MongoClient(uri, {useNewUrlParser: true, useUnifiedTopology: true});

// Middleware to establish MongoDB connection
app.use(async (req, res, next) => {
    try {
        await client.connect();
        console.log('Connected to MongoDB');
        req.dbClient = client;
        next();
    } catch (error) {
        console.error('Error connecting to MongoDB', error);
        res.status(500).send('Internal Server Error');
    }
});


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
    const secretKey = process.env.SECRET_KEY; // Замініть на свій секретний ключ
    const expiresIn = '1h';

    const token = jwt.sign({userId}, secretKey, {expiresIn});
    return token;
}

// Маршрут для реєстрації нового користувача
app.post('/register', async (req, res) => {
    const {username, password} = req.body;

    // Генерація хешу пароля
    const hashedPassword = await hashPassword(password);

    // Збереження користувача в базі даних (в цьому прикладі просто виводимо хеш пароля)
    try {
        const db = req.dbClient.db('Authorizations');
        const collection = db.collection('users');
        const result = await collection.insertOne({username, hashedPassword});
        res.status(201).send(`User registered successfully. [ insertedId = ${result.insertedId} ]`);
    } catch (error){
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// Маршрут для авторизації користувача
app.post('/login', async (req, res) => {
    const {username, password} = req.body;
    // Перевірка користувача в базі даних
    const db = req.dbClient.db('Authorizations');
    const collection = db.collection('users');
    const dbResponse = await collection.findOne({username:username});
    const hashedPasswordFromDatabase = dbResponse ? dbResponse.hashedPassword : null;
    const userId = dbResponse ? dbResponse._id : null;
    const isValidPassword = await verifyPassword(password, hashedPasswordFromDatabase); // Потрібно отримати хеш пароля з бази даних
    if (isValidPassword) {
        // Генерація JWT токена
        const token = generateToken(userId); // Потрібно отримати ID користувача з бази даних
        res.json({token});
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
        const decoded = jwt.verify(token, process.env.SECRET_KEY);
        // Виконайте потрібні дії з валідним JWT токеном (наприклад, отримайте ID користувача та відобразіть захищені дані)

        res.send('Protected data');
    } catch (error) {
        res.status(400).send('Invalid token.');
    }
});

// Close the MongoDB connection when the application is shutting down
process.on('SIGINT', async () => {
    try {
        await client.close();
        console.log('MongoDB connection closed');
        process.exit(0);
    } catch (error) {
        console.error('Error closing MongoDB connection', error);
        process.exit(1);
    }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});