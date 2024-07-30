const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'hospital_db'
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to database');
});

const jwtSecret = 'your_jwt_secret';

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 login requests per windowMs
    message: 'Too many login attempts from this IP, please try again later'
});

app.post('/api/login', loginLimiter, (req, res) => {
    const { username, password } = req.body;
    db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) throw err;
        if (results.length === 0) return res.status(401).send('Invalid username or password');
        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).send('Invalid username or password');
        const token = jwt.sign({ id: user.id }, jwtSecret, { expiresIn: '1h' });
        res.json({ token });
    });
});

const authenticateJWT = (req, res, next) => {
    const token = req.header('Authorization').split(' ')[1];
    if (!token) return res.status(401).send('Access Denied');
    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.status(403).send('Invalid token');
        req.user = user;
        next();
    });
};

const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 60, // limit each IP to 60 requests per windowMs
    message: 'Too many requests from this IP, please try again later'
});

app.use('/api/', apiLimiter);

app.get('/api/patients', authenticateJWT, (req, res) => {
    db.query('SELECT * FROM patients', (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

app.get('/api/patients/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM patients WHERE id = ?', [id], (err, result) => {
        if (err) throw err;
        if (result.length === 0) return res.status(404).send('Patient not found');
        res.json(result[0]);
    });
});

app.post('/api/patients', authenticateJWT, (req, res) => {
    const { name, dob, address, phone } = req.body;
    db.query('INSERT INTO patients (name, dob, address, phone) VALUES (?, ?, ?, ?)', [name, dob, address, phone], (err, result) => {
        if (err) throw err;
        res.json({ message: 'Patient created successfully' });
    });
});

app.put('/api/patients/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    const { name, dob, address, phone } = req.body;
    db.query('UPDATE patients SET name = ?, dob = ?, address = ?, phone = ? WHERE id = ?', [name, dob, address, phone, id], (err, result) => {
        if (err) throw err;
        res.json({ message: 'Patient updated successfully' });
    });
});

app.delete('/api/patients/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    db.query('DELETE FROM patients WHERE id = ?', [id], (err, result) => {
        if (err) throw err;
        res.json({ message: 'Patient deleted successfully' });
    });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
