import express from 'express';
// Fixed paths to look up one directory to find middleware
import { authenticate } from '../middleware/auth.js';
import { authorize } from '../middleware/rbac.js';

const router = express.Router();

// 1. The "Protected" route
// Now correctly exports the route logic to be tracked by the main app coverage
router.get('/protected', authenticate, (req, res) => {
  res.status(200).json({ message: "You are authenticated!" });
});

// 2. The "Admin" route
router.get('/admin-only', authenticate, authorize('admin:all'), (req, res) => {
  res.status(200).json({ message: "Welcome, Admin!" });
});

export default router;
