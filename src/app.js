import express from 'express';
import 'dotenv/config';
import { authenticate } from './middleware/auth.js'; // Import real JWT logic
import userRoutes from './routes/userRoutes.js';

const app = express();
app.use(express.json());

// ❌ REMOVE the Mock Middleware (the one setting req.user = {role: 'ADMIN'})
// ✅ Instead, apply the real JWT verification to your routes

// Protected Routes
app.use('/api/users', authenticate, userRoutes); 

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`ATS-HRMS Server running on http://localhost:${PORT}`);
});
