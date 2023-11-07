const express = require("express");
const bcrypt = require("bcrypt");
const DB = require("../DB");
const router = express();
const { body, validationResult } = require("express-validator");

router.post(
  "/signup",
  [
    body("username").notEmpty().withMessage("Username is required"),
    body("email").notEmpty().isEmail().withMessage("Valid email is required"),
    body("password").notEmpty().withMessage("Password is required"),
    body("confirmPassword")
      .notEmpty()
      .withMessage("Confirm Password is required"),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { username, email, password, confirmPassword } = req.body;
    if (password !== confirmPassword)
      return res.status(400).json({ error: "Passwords are not matching!" });
    DB.query(
      "SELECT * FROM users WHERE email = ?",
      [email],
      (error, results) => {
        if (error) {
          return res.status(500).json({ message: "Internal Server Error" });
        }

        if (results.length > 0) {
          return res
            .status(400)
            .json({ message: "Email is already registered" });
        }

        bcrypt.hash(password, 10, (err, hashedPassword) => {
          if (err) {
            return res.status(500).json({ error: "Internal Server Error" });
          }

          DB.query(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            [username, email, hashedPassword],
            (err) => {
              if (err) {
                return res
                  .status(500)
                  .json({ message: "Internal Server Error" });
              }

              res.status(201).json({ message: "User registered successfully" });
            },
          );
        });
      },
    );
  },
);

router.post(
  "/login",
  [
    body("email").notEmpty().isEmail().withMessage("Valid email is required"),
    body("password").notEmpty().withMessage("Password is required"),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { email, password } = req.body;

    DB.query(
      "SELECT * FROM users WHERE email = ?",
      [email],
      (error, results) => {
        if (error) {
          return res.status(500).json({ message: "Internal Server Error" });
        }

        if (results.length === 0) {
          return res.status(401).json({ message: "Invalid credentials" });
        }

        const user = results[0];
        bcrypt.compare(password, user.password, (err, passwordMatch) => {
          if (err) {
            return res.status(500).json({ message: "Internal Server Error" });
          }

          if (!passwordMatch) {
            return res.status(401).json({ message: "Invalid credentials" });
          }
          res.json({ message: "Login successful" });
        });
      },
    );
  },
);

module.exports = router;
