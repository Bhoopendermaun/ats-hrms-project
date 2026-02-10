import express from 'express';
import { authorize } from '../middleware/rbac.js';

const router = express.Router();

// AC #1: All protected endpoints require authentication
// (Assuming your auth middleware attaches the user to req.user)

// Endpoint for all authenticated users
router.get('/profile', (req, res) => {
  res.json({ message: "Profile data", user: req.user });
});

// AC #3: Permission checks align with matrix (e.g., only Admin can delete)
router.delete('/manage-users/:id', 
  authorize('delete:all'), 
  (req, res) => {
    res.json({ message: `User ${req.params.id} deleted successfully.` });
});

export default router;
