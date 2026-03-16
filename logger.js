import fs from 'fs';
import path from 'path';

const logPath = path.join(process.cwd(), 'audit_log.json');

export const logSecurityEvent = (eventType, identity, role, status, ip) => {
    try {
        const fileContent = fs.readFileSync(logPath, 'utf8');
        const logs = JSON.parse(fileContent);

        const newEntry = {
            id: `EVT-${Date.now()}`,
            timestamp: new Date().toLocaleString(),
            event_type: eventType,
            user: identity,
            role: role,
            status: status,
            ip_address: ip || '127.0.0.1'
        };

        logs.push(newEntry);
        fs.writeFileSync(logPath, JSON.stringify(logs, null, 2));

        // CORRECTED LINE BELOW:
        console.log(`🛡️  Audit Logged: [${eventType}] - ${identity} | IP: ${ip}`);

    } catch (err) {
        console.error("❌ Audit Log Error:", err.message);
    }
};
