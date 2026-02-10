import express from 'express';
import userRoutes from './routes/userRoutes.js';

const app = express();
app.use(express.json());

// Mock Middleware to simulate a logged-in user for testing
// In production, this would be your JWT/OAuth verification logic
app.use((req, res, next) => {
    // For testing: change role to 'USER' to see the 403 in action
    req.user = { id: '1', role: 'ADMIN' }; 
    next();
});

// Link the routes you just created
app.use('/api/users', userRoutes);

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`ATS-HRMS Server running on http://localhost:${PORT}`);
});
