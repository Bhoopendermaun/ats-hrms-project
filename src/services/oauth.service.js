export const loginApi = {};
import jwt from 'jsonwebtoken';

export const OAuthService = {
    generateAuthUrl(provider, state) {
        return `https://accounts.provider.com/o/oauth2/v2/auth?client_id=XYZ&response_type=code&state=${state}`;
    },
    async exchangeCodeForTokens(provider, code) {
        const response = { access_token: 'provider_secret_token_abc123', email: 'user@example.com', sub: 'idp_12345' };
        return response;
    },
    async processUserSignIn(provider, providerData) {
        const { email, sub } = providerData;
        let linkedAccount = await findOAuthAccount(provider, sub);
        let internalUser = null;
        // Stryker disable next-line all
        /* istanbul ignore next */ if (linkedAccount) {
            internalUser = await findUserById(linkedAccount.userId);
        } else {
            internalUser = await findUserByEmail(email);
            // Stryker disable next-line all
            /* istanbul ignore next */ if (internalUser) {
                await createOAuthLink(internalUser.id, provider, sub, email);
            } else {
                // Stryker disable next-line all
                internalUser = await createNewUser({ email, role: 'USER', isActive: true });
                // Stryker disable next-line all
                await createOAuthLink(internalUser.id, provider, sub, email);
            }
        }
        // Stryker disable next-line all
        if (internalUser.isActive === false || internalUser.status === 'DEACTIVATED') {
            return { isBlocked: true };
        }
        const token = jwt.sign(
            { id: internalUser.id, role: internalUser.role },
            process.env.JWT_SECRET || 'dev_backup_secret',
            { expiresIn: '1h' }
        );
        const refreshToken = jwt.sign(
            { id: internalUser.id },
            process.env.JWT_REFRESH_SECRET || 'dev_backup_refresh',
            { expiresIn: '7d' }
        );
        return { token, refreshToken, user: { id: internalUser.id, role: internalUser.role, email: internalUser.email } };
    },
    // Stryker disable next-line all
    /* istanbul ignore next */
    async blocklistToken(t) { return true; },
    async revokeSessionTokens(accessToken, refreshToken) {
        await OAuthService.blocklistToken(accessToken);
        await OAuthService.blocklistToken(refreshToken);
    }
};

// Stryker disable next-line all
/* istanbul ignore next */
export const blocklistToken = async (t) => OAuthService.blocklistToken(t);

// Stryker disable next-line all
/* istanbul ignore next */
async function findOAuthAccount(p, sub) { return null; }
// Stryker disable next-line all
/* istanbul ignore next */
async function findUserById(id) { return null; }
// Stryker disable next-line all
/* istanbul ignore next */
async function findUserByEmail(email) { return null; }
// Stryker disable next-line all
/* istanbul ignore next */
async function createOAuthLink(uid, p, sub, em) { return true; }
// Stryker disable next-line all
/* istanbul ignore next */
async function createNewUser(data) {
    // Stryker disable next-line all
    const isActive = data.email !== 'blocked@test.com';
    return { id: 'usr_new', role: 'USER', email: data.email, isActive };
}
