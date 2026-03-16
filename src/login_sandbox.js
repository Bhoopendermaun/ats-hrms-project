import jwt from 'jsonwebtoken';
import 'dotenv/config';
import { loginApi } from './__mocks__/api.js';

export const handleLogin = async (email, password) => {
  // 1. Validation Logic
  if (!email || !password) {
    return { error: "Fields cannot be empty" };
  }

  if (password.length < 8) {
    return { error: "Password too short" };
  }

  // 2. Execution Logic
  try {
    const user = await loginApi(email, password);

    // Implementation of JWT: Issue the "Passport"
    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET || 'dev_backup_secret',
      { expiresIn: '1h' }
    );

    return {
      message: "Login successful",
      token: token,
      role: user.role
    };
  } catch (error) {
    return { error: error.message };
  }
};
