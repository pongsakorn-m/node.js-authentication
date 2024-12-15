const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET;

// Authorization Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ message: "Authorization header is missing" });
    }

    const token = authHeader.split(" ")[1];

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
        return res.status(403).json({ message: "Invalid or expired token" });
        }

        req.user = user; // Attach the user payload to the request object
        next();
    });
};

module.exports = authenticateToken;