import { jest } from '@jest/globals';

// 1. Setup the Mock Module
jest.unstable_mockModule('../__mocks__/api.js', () => ({
  loginApi: jest.fn((email, password) => {
    if (email === "admin@kali.org" && password === "P@ssword123") {
      return Promise.resolve({ id: '1', role: 'ADMIN' });
    }
    throw new Error("Invalid Credentials");
  })
}));

const { loginApi } = await import('../__mocks__/api.js');
const { handleLogin } = await import('../login.js');

describe("Login Logic & RBAC Bridge", () => {
  
  test("Path 1: Success - Uses JWT_SECRET from process.env", async () => {
    process.env.JWT_SECRET = 'test_secret';
    const result = await handleLogin("admin@kali.org", "P@ssword123");
    expect(result.message).toBe("Login successful");
  });

  test("Path 2: Success - Falls back to dev_backup_secret (Final Branch Fix)", async () => {
    // This forces the || 'dev_backup_secret' branch to execute
    const originalSecret = process.env.JWT_SECRET;
    delete process.env.JWT_SECRET; 
    
    const result = await handleLogin("admin@kali.org", "P@ssword123");
    expect(result.message).toBe("Login successful");
    
    process.env.JWT_SECRET = originalSecret; // Restore it for other tests
  });

  test("Path 3: Validation - Empty fields", async () => {
    const result = await handleLogin("", "");
    expect(result.error).toBe("Fields cannot be empty");
  });  

  test("Path 4: Catch block with Error message", async () => {
    loginApi.mockRejectedValueOnce(new Error("Database Error"));
    const result = await handleLogin("admin@kali.org", "P@ssword123");
    expect(result.error).toBe("Database Error");
  });

  test("Path 5: Catch block with empty object (Edge Case)", async () => {
    loginApi.mockRejectedValueOnce({}); 
    const result = await handleLogin("admin@kali.org", "P@ssword123");
    expect(result).toHaveProperty("error");
  });
});
