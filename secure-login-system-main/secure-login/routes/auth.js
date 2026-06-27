const express = require('express');
const bcrypt = require('bcrypt');
const pool = require('../db');
const { body, validationResult } = require('express-validator');

const router = express.Router();

// Register Page
router.get('/register', (req, res) => {
    res.render('register');
});

// Login Page
router.get('/login', (req, res) => {
    res.render('login');
});

// Register Route
router.post(
    '/register',
    [
        body('username').trim().isLength({ min: 3 }),
        body('email').isEmail(),
        body('password').isLength({ min: 8 })
    ],
    async (req, res) => {

        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.send('Invalid Input');
        }

        const { username, email, password } = req.body;

        try {

            const hashedPassword = await bcrypt.hash(password, 10);

            pool.query(
                'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                [username, email, hashedPassword],
                (err, result) => {

                    if (err) {
                        console.log('Database Error:', err);
                        return res.send('Registration Failed');
                    }

                    console.log('User Registered Successfully');
                    res.redirect('/login');
                }
            );

        } catch (err) {

            console.log(err);
            res.send('Registration Failed');

        }
    }
);

// Login Route
router.post('/login', (req, res) => {

    const { email, password } = req.body;

    pool.query(
        'SELECT * FROM users WHERE email = ?',
        [email],
        async (err, results) => {

            if (err) {
                console.log(err);
                return res.send('Login Failed');
            }

            if (results.length === 0) {
                return res.send('User Not Found');
            }

            const user = results[0];

            const match = await bcrypt.compare(
                password,
                user.password
            );

            if (!match) {
                return res.send('Incorrect Password');
            }

            req.session.userId = user.id;
            req.session.username = user.username;

            res.redirect('/dashboard');
        }
    );
});

module.exports = router;