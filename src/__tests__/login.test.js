import { jest } from '@jest/globals';

// 1. Define the mock to return an OBJECT (matching your new login logic)
jest.unstable_mockModule('../__mocks__/api.js', () => ({
  loginApi: jest.fn((email, password) => {
    if (email === "admin@kali.org" && password === "P@ssword123") {
      return Promise.resolve({ id: '1', role: 'ADMIN' }); // Return user data
    }
    throw new Error("Invalid Credentials");
  })
}));

const { handleLogin } = await import('../login.js');

describe("Login UI Critical Paths", () => {
  test("Path 1: Success with seed data", async () => {
    const result = await handleLogin("admin@kali.org", "P@ssword123");
    
    // Check the object properties now, not just a string
    expect(result.message).toBe("Login successful");
    expect(result.token).toBeDefined();
    expect(result.role).toBe("ADMIN");
  });

  test("Path 2: Failure with wrong password", async () => {
    const result = await handleLogin("admin@kali.org", "wrong");
    // Your code returns { error: "..." } now
    expect(result.error).toBe("Invalid Credentials");
  });

  test("Path 3: Validation - Empty fields", async () => {
    const result = await handleLogin("", "somePassword");
    expect(result.error).toBe("Fields cannot be empty");
  });  

  test("Path 4: Validation - Empty password only", async () => {
    const result = await handleLogin("admin@kali.org", "");
    expect(result.error).toBe("Fields cannot be empty");
  });

  test("Path 5: Both fields empty", async () => {
    const result = await handleLogin("", "");
    expect(result.error).toBe("Fields cannot be empty");
  });
test("Path 6: Unexpected Server Error", async () => {
  // Tell the mock to throw a total tantrum
  const { loginApi } = await import('../__mocks__/api.js');
  loginApi.mockRejectedValueOnce(new Error("Database connection failed"));

  const result = await handleLogin("admin@kali.org", "P@ssword123");
  expect(result.error).toBe("Database connection failed");
});
});
