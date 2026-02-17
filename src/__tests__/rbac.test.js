import { authorize } from '../middleware/rbac.js';
import { jest } from '@jest/globals';

describe('RBAC Middleware Enforcement', () => {
  let mockReq;
  let mockRes;
  let nextFunction;

  beforeEach(() => {
    mockReq = {};
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    nextFunction = jest.fn();
  });

  test('AC #1 & #2: Should return 401 if no user is present', () => {
    const middleware = authorize('read:any');
    middleware(mockReq, mockRes, nextFunction);
    expect(mockRes.status).toHaveBeenCalledWith(401);
  });

  test('AC #2 & #5: Should return 403 and generic error if role is insufficient', () => {
    mockReq.user = { role: 'USER' };
    const middleware = authorize('admin:delete');
    middleware(mockReq, mockRes, nextFunction);
    expect(mockRes.status).toHaveBeenCalledWith(403);
    expect(mockRes.json).toHaveBeenCalledWith({ error: 'Access denied' });
  });

test('AC #3: Should call next() for ADMIN role (full access)', async () => {
  const mockReq = { 
    user: { id: '1', role: 'ADMIN' } // Role must be uppercase to match matrix
  };
  const mockRes = { 
    status: jest.fn().mockReturnThis(), 
    json: jest.fn() 
  };
  const nextFunction = jest.fn();

  // Use a permission that ADMIN explicitly has, or 'all:all'
  const middleware = authorize('all:all'); 
  
  middleware(mockReq, mockRes, nextFunction);

  expect(nextFunction).toHaveBeenCalled();
});
});
