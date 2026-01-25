import { loginApi } from './__mocks__/api';

export const handleLogin = async (email, password) => {
  if (!email || !password) {
    return "Fields cannot be empty";
  }
  try {
    const response = await loginApi(email, password);
    return response.message;
  } catch (error) {
    return error.message;
  }
};
