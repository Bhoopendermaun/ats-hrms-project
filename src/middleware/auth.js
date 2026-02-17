import jwt from 'jsonwebtoken';
import 'dotenv/config';

export const authenticate = (req, res, next) => {
  // 1. Get token from header
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  // 2. AC #1: Return 401 if token is missing
  if (!token) {
    return res.status(401).json({ error: "Authentication required" });
  }

  try {
    // 3. Verify the token using your secret
    const secret = process.env.JWT_SECRET || 'dev_backup_secret';
    const decoded = jwt.verify(token, secret);
    
    // 4. Attach user to request for the RBAC middleware to use
    req.user = decoded;
    next();
  } catch (err) {
    // AC #2: Return 401 for invalid/expired tokens
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};
