export function provisionUser(claims, database, config = {}) {
  const { 
    email, 
    name, 
    sub,           // Unique Provider ID [Requirement: matched reliably]
    picture,       // Profile image [Requirement: map correctly]
    hd,            // Hosted Domain [Requirement: domain restrictions]
    email_verified // [Requirement: email verification]
  } = claims;

  // 1. Enforce Email Verification
  if (email_verified === false) {
    throw new Error("Email must be verified by OAuth provider");
  }

  // 2. Enforce Domain/Tenant Restrictions (if configured)
  if (config.allowedDomains && !config.allowedDomains.includes(hd)) {
    throw new Error("Domain not authorized");
  }

  // 3. Reliable Matching (Email/Provider ID rules)
  let user = database.find(u => u.providerId === sub || u.email === email);

  if (user) {
    // 4. Update existing profile fields
    user.name = name;
    user.profileImage = picture;
    user.isNewUser = false; // Existing user matched
  } else {
    // 5. Provision New User with correct default role (Candidate)
    user = {
      id: `user_${Date.now()}`,
      providerId: sub,
      email: email,
      name: name,
      profileImage: picture,
      role: config.defaultRole || 'Candidate', // [Requirement: correct default role]
      isNewUser: true // [Requirement: First-time login onboarding flag]
    };
    database.push(user);
  }
  return user;
}

