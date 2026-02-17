import express from 'express';
import { authenticate } from './middleware/auth.js';
import { authorize } from './middleware/rbac.js';

const app = express();
app.use(express.json());

// 1. The "Protected" route (Tests 401)
app.get('/api/protected', authenticate, (req, res) => {
  res.status(200).json({ message: "You are authenticated!" });
});

// 2. The "Admin" route (Tests 403)
app.get('/api/admin-only', authenticate, authorize('admin:all'), (req, res) => {
  res.status(200).json({ message: "Welcome, Admin!" });
});

app.listen(3000, () => console.log('Server running on port 3000'));
