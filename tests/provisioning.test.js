import { provisionUser } from '../src/provisioning.js';

describe('ATS User Provisioning & Profile Mapping', () => {
  let mockDb;
  const config = { 
    allowedDomains: ['hrms-agency.com'], 
    defaultRole: 'Candidate' 
  };

  beforeEach(() => {
    mockDb = [
      { id: '1', email: 'recruiter@hrms-agency.com', providerId: 'sub-123', role: 'Recruiter' }
    ];
  });

  test('New User: should provision with "Candidate" role and isNewUser=true', () => {
    const claims = { email: 'john@hrms-agency.com', name: 'John Doe', sub: 'sub-456', hd: 'hrms-agency.com', email_verified: true };
    const user = provisionUser(claims, mockDb, config);
    expect(user.role).toBe('Candidate');
    expect(user.isNewUser).toBe(true);
  });

  test('Existing User: should match by providerId and set isNewUser=false', () => {
    const claims = { email: 'recruiter@hrms-agency.com', name: 'Recruiter Updated', sub: 'sub-123', hd: 'hrms-agency.com', email_verified: true };
    const user = provisionUser(claims, mockDb, config);
    expect(user.id).toBe('1');
    expect(user.isNewUser).toBe(false);
  });

  test('Reliability: should match by email if providerId is different', () => {
    const claims = { email: 'recruiter@hrms-agency.com', sub: 'new-sub-id', hd: 'hrms-agency.com', email_verified: true };
    const user = provisionUser(claims, mockDb, config);
    expect(user.id).toBe('1');
  });

  test('Security: should throw error if domain is unauthorized', () => {
    const claims = { email: 'hacker@external.com', hd: 'external.com', email_verified: true };
    expect(() => provisionUser(claims, mockDb, config)).toThrow("Domain not authorized");
  });

  test('Security: should throw error if email is not verified', () => {
    const claims = { email: 'unverified@hrms-agency.com', hd: 'hrms-agency.com', email_verified: false };
    expect(() => provisionUser(claims, mockDb, config)).toThrow("Email must be verified by OAuth provider");
  });

  test('Branch Coverage: should handle missing config by using default empty object', () => {
    const claims = { email: 'new@hrms-agency.com', sub: 'sub-999', hd: 'hrms-agency.com', email_verified: true };
    const user = provisionUser(claims, mockDb); 
    expect(user.role).toBe('Candidate');
  });

  test('Reliability: should match by providerId even if email has changed', () => {
    const claims = { 
      email: 'DIFFERENT_EMAIL@hrms-agency.com',
      name: 'Recruiter Name', 
      sub: 'sub-123',
      hd: 'hrms-agency.com', 
      email_verified: true 
    };
    const user = provisionUser(claims, mockDb, config);
    expect(user.id).toBe('1'); 
    expect(user.isNewUser).toBe(false);
  });
});
