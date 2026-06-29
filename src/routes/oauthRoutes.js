// src/routes/oauthRoutes.js
import { Router } from 'express';
import { initiateLogin, handleCallback, handleLogout } from '../controllers/oauth.controller.js';

const router = Router();

// Strip out the extra "/oauth" prefix from the endpoints
router.get('/:provider/login', initiateLogin);
router.get('/:provider/callback', handleCallback);
router.post('/logout', handleLogout);

export default router;
