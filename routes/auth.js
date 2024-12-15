const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const authenticateToken = require("../middlewares/authorize");

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;

// In-memory user storage (replace with a database in production)
const users = [];

// Register Route
router.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }

  const hashedPassword = hashPassword(password);

  users.push({ username, password: hashedPassword });

  res.status(201).json({ message: "User registered successfully" });
});

// Login Route
router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find((user) => user.username === username);

  if (!user || !(hashPassword(password) == user.password)) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "1h" });

  res.json({ token });
});

// Protected Route Example
router.get("/protected", authenticateToken, (req, res) => {
    res.json({ message: "Protected content"});
});

function hashPassword(password) {
    // Create a SHA-256 hash
    const hash = crypto.createHash("sha256");

    // Update the hash with the password
    hash.update(password);

    // Convert the hash to a hexadecimal string
    return hash.digest("hex");
}

module.exports = router; 
