import { auditService } from '../src/services/auditService.js';
import { jest } from '@jest/globals';

describe('Audit Service', () => {
  test('Requirement #4: Should create a valid audit entry with who, when, and what', () => {
    // 1. Setup Spy on console.log to prevent polluting test output
    const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
    
    const actorId = 'admin-123';
    const targetId = 'user-456';
    const action = 'ROLE_UPDATE';
    const details = 'Changed role from USER to MANAGER';

    // 2. Execute - Use the imported auditService object
    // Assuming your service maps (actorId, targetId, action, details) 
    // to an internal log method.
    const result = auditService.logAuditTrail(actorId, targetId, action, details);

    // 3. Assertions (The "Mutant Killers")
    expect(result).toBeDefined();
    expect(result.actorId).toBe(actorId);
    expect(result.targetId).toBe(targetId);
    expect(result.action).toBe(action);
    expect(result.details).toBe(details);
    expect(new Date(result.timestamp).getTime()).not.toBeNaN(); // Validates timestamp logic
    
    // 4. Verify Side Effects
    // Ensures the system actually outputs the log for external log aggregators
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('[AUDIT_LOG]')
    );

    // Cleanup
    consoleSpy.mockRestore();
  });
});
