import express from 'express';
import 'dotenv/config';
import { authenticate } from './middleware/auth.js';
import userRoutes from './routes/userRoutes.js';
import adminRoutes from './routes/adminRoutes.js';
import indexRoutes from './routes/index.js';
import oauthRoutes from './routes/oauthRoutes.js';
import swaggerUi from 'swagger-ui-express';
import yaml from 'yamljs';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const swaggerDocument = yaml.load(join(__dirname, '../docs/openapi/oauth.yaml'));

const app = express();
app.use(express.json());
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

/**
 * 1. Coverage-Specific Routes
 */
/* istanbul ignore next */
if (process.env.NODE_ENV === 'test') {
    const errorTask = (req, res, next) => {
        next(new Error('Test Internal Server Error'));
    };

    app.get('/api/test/error', errorTask);
    app.get('/force-error',  errorTask);
}

/**
 * 2. Main API Routes
 */
app.use('/api', indexRoutes);
app.use('/api/oauth', oauthRoutes);
app.use('/api/users', authenticate, userRoutes);
app.use('/api/admin', authenticate, adminRoutes);

/**
 * 3. Global 404 Handler
 */
app.use((req, res) => {
    res.status(404).json({ error: "Not Found" });
});

/**
 * 4. Global Error Handler
 */
app.use((err, req, res, next) => {
    /* istanbul ignore next */
    if (process.env.NODE_ENV !== 'production') {
        console.error(err.stack);
    }

    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        return res.status(400).json({ error: "Invalid JSON" });
    }

    res.status(500).json({ error: "Internal Server Error" });
});

/**
 * 5. Server Initialization
 */
const PORT = process.env.PORT || 3000;

/* istanbul ignore next */
if (process.env.NODE_ENV !== 'test') {
    app.listen(PORT, () => {
        console.log(`Server running on ${PORT}`);
    });
}

export default app;
