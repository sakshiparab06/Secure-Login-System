require("dotenv").config();

const express = require("express");
const bcrypt = require("bcrypt");
const session = require("express-session");
const db = require("./db");
const { body, validationResult } = require("express-validator");

const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// Session
app.use(
    session({
        secret: process.env.SESSION_SECRET || "mySuperSecretKey123",
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: false,
            maxAge: 24 * 60 * 60 * 1000
        }
    })
);

// View Engine
app.set("view engine", "ejs");

// Home
app.get("/", (req, res) => {
    res.redirect("/login");
});

// Register Page
app.get("/register", (req, res) => {
    res.render("register");
});

// Register User
app.post(
    "/register",
    [
        body("username").notEmpty().withMessage("Username required"),
        body("email").isEmail().withMessage("Invalid email"),
        body("password")
            .isLength({ min: 6 })
            .withMessage("Password must be at least 6 characters")
    ],
    async (req, res) => {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).send(errors.array());
        }

        const { username, email, password } = req.body;

        try {
            const hashedPassword = await bcrypt.hash(password, 10);

            db.query(
                "INSERT INTO users(username,email,password) VALUES(?,?,?)",
                [username, email, hashedPassword],
                (err) => {
                    if (err) {
                        console.log(err);
                        return res.send("Email already exists.");
                    }

                    res.redirect("/login");
                }
            );
        } catch (error) {
            console.log(error);
            res.status(500).send("Server Error");
        }
    }
);

// Login Page
app.get("/login", (req, res) => {
    res.render("login");
});

// Login User
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    db.query(
        "SELECT * FROM users WHERE email=?",
        [email],
        async (err, result) => {
            if (err) {
                console.log(err);
                return res.send("Database Error");
            }

            if (!result || result.length === 0) {
                return res.send("User Not Found");
            }

            const user = result[0];

            const match = await bcrypt.compare(password, user.password);

            if (!match) {
                return res.send("Wrong Password");
            }

            req.session.userId = user.id;
            req.session.username = user.username;

            res.redirect("/dashboard");
        }
    );
});

// Dashboard
app.get("/dashboard", (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/login");
    }

    res.render("dashboard", {
        username: req.session.username
    });
});

// Logout
app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.send("Logout Failed");
        }

        res.redirect("/login");
    });
});

// Test Route
app.get("/test", (req, res) => {
    res.send("Server is Working!");
});

// Start Server
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server Running on Port ${PORT}`);
});