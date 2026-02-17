#!/bin/bash
# Using the exact IP that worked in your manual curl
BASE_URL="http://127.0.0.1:3000/api/users"

echo "-----------------------------------------------"
echo "🔍 STARTING SECURITY AUDIT: JWT & RBAC"
echo "-----------------------------------------------"

# Test 1
echo "[+] Test 1: Accessing /profile WITHOUT JWT..."
# Added -L to follow redirects and ensured the URL is quoted
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/profile")

if [ "$STATUS" == "401" ]; then 
    echo "✅ PASS: Received 401 Unauthorized"
else 
    echo "❌ FAIL: Received $STATUS (Expected 401)"
fi

# Test 2
echo -e "\n[+] Test 2: Accessing /manage-users with FAKE_TOKEN..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer FAKE" "$BASE_URL/manage-users/123")

if [ "$STATUS" == "403" ] || [ "$STATUS" == "401" ]; then 
    echo "✅ PASS: Received $STATUS (Security Gate Active)"
else 
    echo "❌ FAIL: Received $STATUS (Expected 403/401)"
fi

echo -e "\n-----------------------------------------------"
echo "🏁 AUDIT COMPLETE"
