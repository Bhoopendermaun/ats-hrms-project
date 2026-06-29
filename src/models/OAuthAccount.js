// Relational schema configuration or MongoDB Model equivalent
// Maps external provider identities cleanly to internal user structures
export const OAuthAccountSchema = {
    userId: { type: 'UUID', required: true, ref: 'User' },
    provider: { type: 'String', required: true }, // e.g., 'google', 'github'
    providerUserId: { type: 'String', required: true }, // The immutable 'sub' or 'id' claim from IdP
    providerEmail: { type: 'String', required: true },
    linkedAt: { type: 'Date', default: () => new Date() }
};
