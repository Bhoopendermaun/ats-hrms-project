import { jest } from '@jest/globals';

// 1. Define the mock FIRST
jest.unstable_mockModule('../__mocks__/api.js', () => ({
  loginApi: jest.fn((email, password) => {
    if (email === "admin@kali.org" && password === "P@ssword123") {
      return Promise.resolve({ message: "Success" });
    }
    return Promise.reject({ message: "Invalid Credentials" });
  })
}));

// 2. Dynamically import the code we want to test
const { handleLogin } = await import('../login.js');

describe("Login UI Critical Paths", () => {
  test("Path 1: Success with seed data", async () => {
    const result = await handleLogin("admin@kali.org", "P@ssword123");
    expect(result).toBe("Success");
  });

  test("Path 2: Failure with wrong password", async () => {
    const result = await handleLogin("admin@kali.org", "wrong");
    expect(result).toBe("Invalid Credentials");
  });

  test("Path 3: Validation - Empty fields", async () => {
    const result = await handleLogin("", "somePassword");
    expect(result).toBe("Fields cannot be empty");
  
  });  
    test("Path 4: Validation - Empty password only", async () => {
    const result = await handleLogin("admin@kali.org", "");
    expect(result).toBe("Fields cannot be empty");
  });

  test("Path 5: Both fields empty", async () => {
    const result = await handleLogin("", "");
    expect(result).toBe("Fields cannot be empty");
  });
});
