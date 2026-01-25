// src/__mocks__/api.js
export const loginApi = (email, password) => {
  // This is a placeholder that the test will replace
  return Promise.resolve({ status: 200, message: "Real API" });
};
