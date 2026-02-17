import jwt from 'jsonwebtoken';
import 'dotenv/config';
import { loginApi } from './__mocks__/api.js';

export const handleLogin = async (email, password) => {
  if (!email || !password) {
    return { error: "Fields cannot be empty" };
  }

  try {
    // 1. Authenticate the user via your API/Database logic
    const user = await loginApi(email, password);

    // 2. Implementation of JWT: Issue the "Passport"
    // We embed the role so the RBAC middleware can read it later
    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET || 'dev_backup_secret',
      { expiresIn: '1h' }
    );

    // 3. Return the token to the client
    return {
      message: "Login successful",
      token: token,
      role: user.role
    };
  } catch (error) {
    // AC Requirement: Consistent error handling
    return { error: error.message };
  }
};
