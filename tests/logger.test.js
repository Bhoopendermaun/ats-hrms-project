import { jest } from '@jest/globals';

// 1. Mock the fs module BEFORE any other logic
jest.unstable_mockModule('fs', () => ({
  default: {
    existsSync: jest.fn(),
    readFileSync: jest.fn(),
    writeFileSync: jest.fn(),
  }
}));

// 2. Import the mocked fs and the function AFTER the mock is registered
const { default: mockedFs } = await import('fs');
const { default: logger, logSecurityEvent } = await import('../logger.js');

describe('Logger Utility - 100% Coverage', () => {
    let consoleSpy, errorSpy;

    beforeEach(() => {
        jest.clearAllMocks();
        // Silence console to keep test output clean
        consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
        errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    afterEach(() => {
        consoleSpy.mockRestore();
        errorSpy.mockRestore();
    });

    it('should hit Lines 14-15 (Read/Parse Error)', () => {
        mockedFs.existsSync.mockReturnValue(true);
        mockedFs.readFileSync.mockImplementation(() => { 
            throw new Error('Read Fail'); 
        });

        logSecurityEvent('ERR_TEST', 'user', 'ADMIN', 'SUCCESS', '127.0.0.1');
        
        expect(errorSpy).toHaveBeenCalledWith(
            expect.stringContaining('Audit Log Error (Read)'),
            'Read Fail'
        );
    });

    it('should hit Line 33 (Write Error)', () => {
        mockedFs.existsSync.mockReturnValue(false);
        mockedFs.writeFileSync.mockImplementation(() => { 
            throw new Error('Write Fail'); 
        });

        logSecurityEvent('WRITE_FAIL', 'user', 'ADMIN', 'FAIL', '127.0.0.1');

        expect(errorSpy).toHaveBeenCalledWith(
            expect.stringContaining('Audit Log Error (Write)'),
            'Write Fail'
        );
    });

    it('should cover Line 26 branch (Default vs Provided IP)', () => {
        mockedFs.existsSync.mockReturnValue(false);

        // Path A: Provided IP
        logSecurityEvent('TEST', 'user', 'ADMIN', 'SUCCESS', '192.168.1.50');
        // This is the 1st call, so we check index [0]
        let call1 = JSON.parse(mockedFs.writeFileSync.mock.calls[0][1]);
        expect(call1[0].ip_address).toBe('192.168.1.50');

        // Path B: Default IP (undefined)
        logSecurityEvent('TEST', 'user', 'ADMIN', 'SUCCESS', undefined);
        // This is the 2nd call, so we check index [1]
        let call2 = JSON.parse(mockedFs.writeFileSync.mock.calls[1][1]);
        // Note: writtenData in the file starts fresh because existsSync is false
        expect(call2[0].ip_address).toBe('127.0.0.1'); 
    });

    it('should append to existing logs if file exists', () => {
        mockedFs.existsSync.mockReturnValue(true);
        mockedFs.readFileSync.mockReturnValue(JSON.stringify([{ id: 'OLD' }]));

        logSecurityEvent('APPEND', 'user', 'USER', 'SUCCESS', '127.0.0.1');

        const writtenData = JSON.parse(mockedFs.writeFileSync.mock.calls[0][1]);
        expect(writtenData.length).toBe(2);
        expect(writtenData[0].id).toBe('OLD');
    });
    test('should call console.log for info messages', () => {
       const spy = jest.spyOn(console, 'log').mockImplementation(() => {});
       logger.info('test info message');
       expect(spy).toHaveBeenCalledWith('[INFO] test info message');
       spy.mockRestore();
    });

    test('should call console.error for error messages', () => {
       const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
       logger.error('test error message');
       expect(spy).toHaveBeenCalledWith('[ERROR] test error message');
       spy.mockRestore();
   });
});
