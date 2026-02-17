#!/bin/bash
API_URL="http://localhost:3000/api/users"

echo "-----------------------------------------------"
echo "🔍 STARTING SECURITY AUDIT: JWT & RBAC"
echo "-----------------------------------------------"

# Test 1: No Token -> Should trigger 'authenticate' middleware in app.js
echo "[+] Test 1: Accessing /profile WITHOUT JWT..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/profile")
if [ "$STATUS" == "401" ]; then 
    echo "✅ PASS: Received 401 Unauthorized"
else 
    echo "❌ FAIL: Received $STATUS (Expected 401)"
fi

# Test 2: Forbidden Role -> Should trigger 'authorize' middleware in userRoutes.js
echo -e "\n[+] Test 2: Accessing /manage-users with FAKE_USER_TOKEN..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer FAKE_TOKEN" "$API_URL/manage-users/123")
if [ "$STATUS" == "403" ]; then 
    echo "✅ PASS: Received 403 Forbidden"
else 
    echo "❌ FAIL: Received $STATUS (Expected 403)"
fi

echo -e "\n-----------------------------------------------"
echo "🏁 AUDIT COMPLETE"
