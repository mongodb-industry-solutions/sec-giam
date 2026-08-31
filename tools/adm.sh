#!/bin/bash
# ============================================================
#  GitHub Key & Auth Manager
# ============================================================

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()     { echo -e "${GREEN}[ok]${NC}     $1"; }
warn()   { echo -e "${YELLOW}[warn]${NC}   $1"; }
fail()   { echo -e "${RED}[error]${NC}  $1"; }
action() { echo "[action] $1"; }
chk()    { echo "[check]  $1"; }
run()    { echo "[cmd]    $*"; "$@"; }

get_repo_name() {
    local INPUT="$1"
    if [ -n "$INPUT" ]; then echo "$INPUT"; return 0; fi
    local URL
    URL=$(git remote get-url origin 2>/dev/null)
    if [ -z "$URL" ]; then
        fail "Could not detect repo from git remote. Specify owner/repo manually."
        return 1
    fi
    echo "$URL" | sed 's|git@github\.com:||;s|https://github\.com/||;s|\.git$||;s|/$||'
}

# ---- Dependency checks -------------------------------------

ensure_ssh_keygen() {
    chk "OpenSSH Client (ssh-keygen)..."
    if command -v ssh-keygen &>/dev/null; then
        ok "ssh-keygen is available."
        return
    fi
    action "Installing OpenSSH..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        run brew install openssh
    elif command -v apt-get &>/dev/null; then
        run sudo apt-get install -y openssh-client
    elif command -v yum &>/dev/null; then
        run sudo yum install -y openssh
    else
        fail "Cannot install ssh-keygen automatically."
        echo "  > Install OpenSSH manually and re-run this script."
        exit 1
    fi
    command -v ssh-keygen &>/dev/null && ok "ssh-keygen installed." || { fail "Failed to install ssh-keygen."; exit 1; }
}

ensure_gh() {
    chk "GitHub CLI (gh)..."
    if command -v gh &>/dev/null; then
        ok "gh is available: $(gh --version | head -1)"
        return
    fi
    action "Installing GitHub CLI..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        run brew install gh
    elif command -v apt-get &>/dev/null; then
        run curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
            | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg 2>/dev/null
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] \
https://cli.github.com/packages stable main" \
            | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
        run sudo apt-get update -q && sudo apt-get install -y gh
    elif command -v dnf &>/dev/null; then
        run sudo dnf install -y gh
    else
        fail "Cannot install GitHub CLI automatically."
        echo "  > Install manually from: https://cli.github.com"
        exit 1
    fi
    command -v gh &>/dev/null && ok "GitHub CLI installed: $(gh --version | head -1)" || { fail "Failed to install GitHub CLI."; exit 1; }
}

ensure_ssh_dir() {
    chk "~/.ssh directory..."
    SSH_DIR="$HOME/.ssh"
    if [ ! -d "$SSH_DIR" ]; then
        action "Creating ~/.ssh directory..."
        run mkdir -p "$SSH_DIR"
        run chmod 700 "$SSH_DIR"
        ok "~/.ssh created."
    else
        ok "~/.ssh directory exists."
    fi
}

# ---- Option 1: Create SSH key ------------------------------

create_ssh_key() {
    SSH_DIR="$HOME/.ssh"
    echo ""
    read -rp "GitHub Email: " EMAIL

    DEFAULT_KEY="id_rsa_github"
    read -rp "SSH key file name (default: $DEFAULT_KEY): " KEY_INPUT
    KEY_FILE="${KEY_INPUT:-$DEFAULT_KEY}"

    DEFAULT_HOST="github.com"
    read -rp "SSH config host alias (default: $DEFAULT_HOST): " HOST_INPUT
    HOST_ALIAS="${HOST_INPUT:-$DEFAULT_HOST}"

    DEFAULT_LABEL="$KEY_FILE"
    read -rp "Key label shown in GitHub (default: $DEFAULT_LABEL): " LABEL_INPUT
    KEY_LABEL="${LABEL_INPUT:-$DEFAULT_LABEL}"

    KEY_PATH="$SSH_DIR/$KEY_FILE"
    echo ""
    action "Generating SSH key '$KEY_FILE' for $EMAIL..."
    run ssh-keygen -t rsa -b 4096 -C "$EMAIL" -f "$KEY_PATH" -N ""

    if [ ! -f "${KEY_PATH}.pub" ]; then
        fail "Key generation failed - ${KEY_PATH}.pub not found."
        return
    fi

    # Update ~/.ssh/config
    CONFIG="$SSH_DIR/config"
    BLOCK="
Host $HOST_ALIAS
  HostName github.com
  User git
  IdentityFile ~/.ssh/$KEY_FILE
  IdentitiesOnly yes"

    if [ -f "$CONFIG" ]; then
        if grep -q "^Host $HOST_ALIAS$" "$CONFIG"; then
            warn "Host '$HOST_ALIAS' already exists in $CONFIG - skipping config update."
        else
            echo "$BLOCK" >> "$CONFIG"
            ok "SSH config updated: $CONFIG"
        fi
    else
        echo "$BLOCK" > "$CONFIG"
        chmod 600 "$CONFIG"
        ok "SSH config created: $CONFIG"
    fi

    echo ""
    echo "Public key ($KEY_LABEL):"
    echo "----------------------------------------"
    cat "${KEY_PATH}.pub"
    echo "----------------------------------------"
    echo ""
    echo "Next steps:"
    echo "  1. Go to https://github.com/settings/keys"
    echo "  2. Click 'New SSH Key', set title to '$KEY_LABEL', paste the key above."
    echo "  3. If using GitHub org SSO, authorize the key for your organization."
    echo ""
    echo "Test your connection with:"
    echo "  ssh -T git@$HOST_ALIAS"
    echo "  ssh -i ~/.ssh/$KEY_FILE -T git@github.com"
}

# ---- Option 2: Authenticate with GitHub CLI ----------------

github_auth() {
    echo ""
    chk "GitHub CLI authentication status..."
    if gh auth status &>/dev/null; then
        ok "Already authenticated with GitHub:"
        gh auth status
        return
    fi
    action "Starting GitHub CLI authentication via browser (OAuth)..."
    echo "  > A code will appear — open https://github.com/login/device and paste it."
    echo "  > If your org has app restrictions, approve 'GitHub CLI' access when prompted."
    echo ""
    run gh auth login --web --git-protocol ssh --scopes repo,read:org,workflow
    if gh auth status &>/dev/null; then
        ok "Authentication successful."
        echo ""
        gh auth status
    else
        fail "Authentication failed. Try: gh auth login --web --scopes repo,read:org,workflow"
    fi
}

# ---- Option 3: Logout / switch user ------------------------

github_logout() {
    echo ""
    chk "GitHub CLI authentication status..."
    if ! gh auth status &>/dev/null; then
        warn "No active GitHub CLI session found. Nothing to log out from."
        return
    fi
    gh auth status
    echo ""
    read -rp "Log out from GitHub CLI? This will remove the stored token. (y/N): " CONFIRM
    if [[ "${CONFIRM,,}" != "y" ]]; then
        echo "Logout cancelled."
        return
    fi
    run gh auth logout
    gh auth status &>/dev/null \
        && fail "Logout failed. Try running: gh auth logout" \
        || ok "Logged out successfully. Run option 2 to authenticate as a different user."
}

# ---- Option 4: List SSH keys -------------------------------

list_ssh_keys() {
    SSH_DIR="$HOME/.ssh"
    CONFIG="$SSH_DIR/config"
    echo ""
    echo "SSH keys found in $SSH_DIR :"
    echo "------------------------------------------------------------"

    shopt -s nullglob
    PUB_KEYS=("$SSH_DIR"/*.pub)
    shopt -u nullglob

    if [ ${#PUB_KEYS[@]} -eq 0 ]; then
        warn "No public keys found in $SSH_DIR."
        return
    fi

    for pub in "${PUB_KEYS[@]}"; do
        KEY_NAME=$(basename "$pub" .pub)
        echo "[cmd]    ssh-keygen -lf $pub"
        FINGERPRINT=$(ssh-keygen -lf "$pub" 2>/dev/null)
        IN_CONFIG="no"
        [ -f "$CONFIG" ] && grep -q "IdentityFile.*$KEY_NAME" "$CONFIG" && IN_CONFIG="yes"
        echo ""
        echo "  Key      : $KEY_NAME"
        echo "  File     : $pub"
        echo "  In config: $IN_CONFIG"
        echo "  Details  : $FINGERPRINT"
    done

    echo ""
    echo "------------------------------------------------------------"
    echo "SSH config: $CONFIG"
    if [ -f "$CONFIG" ]; then
        cat "$CONFIG"
    else
        warn "No SSH config file found."
    fi
}

# ---- Option 5: Set global GitHub login via SSH key ---------

# Interactive key picker for Linux/macOS terminals.
# Before calling, populate the PICKER_KEYS and PICKER_FPS arrays.
# The selected key name is stored in PICKER_RESULT ("" = Esc / skip).
PICKER_KEYS=()
PICKER_FPS=()
PICKER_RESULT=""

interactive_key_picker() {
    local TITLE="${1:-Select SSH key  (arrow keys + Enter, Esc = skip)}"
    local total=${#PICKER_KEYS[@]}
    local selected=0
    PICKER_RESULT=""

    [ "$total" -eq 0 ] && return 1

    tput civis 2>/dev/null   # hide cursor

    # Header printed once — never redrawn, no flicker
    printf "\n\033[36m  %s\033[0m\n\n" "$TITLE"

    local lines=$(( total * 2 ))   # lines the items section occupies

    # Redraw items from current cursor position, then step cursor back up
    # using relative movement so scroll state never causes drift
    _picker_redraw() {
        local i
        for ((i=0; i<total; i++)); do
            if [ "$i" -eq "$selected" ]; then
                printf "\033[30;46m  [ %-40s ]  \033[0m\n" "${PICKER_KEYS[$i]}"
                printf "\033[36m    %s\033[0m\n"            "${PICKER_FPS[$i]}"
            else
                printf "\033[90m    %-42s\033[0m\n" "${PICKER_KEYS[$i]}"
                printf "\033[90m    %s\033[0m\n"    "${PICKER_FPS[$i]}"
            fi
        done
        printf "\033[%dA" "$lines"   # cursor up: back to items top for next redraw
    }

    _picker_redraw

    local key
    while true; do
        IFS= read -rs -n1 key </dev/tty
        if [[ "$key" == $'\x1b' ]]; then
            IFS= read -rs -n2 -t 0.1 key2 </dev/tty
            key="${key}${key2}"
        fi
        case "$key" in
            $'\x1b[A')                       # Up arrow
                if [ "$selected" -gt 0 ]; then
                    selected=$((selected - 1))
                    _picker_redraw
                fi ;;
            $'\x1b[B')                       # Down arrow
                if [ "$selected" -lt $((total - 1)) ]; then
                    selected=$((selected + 1))
                    _picker_redraw
                fi ;;
            ''|$'\x0a'|$'\x0d')             # Enter
                PICKER_RESULT="${PICKER_KEYS[$selected]}"
                printf "\033[%dB\n" "$lines"   # cursor down past items, then blank line
                break ;;
            $'\x1b')                         # Lone Escape
                PICKER_RESULT=""
                printf "\033[%dB\n" "$lines"
                break ;;
        esac
    done

    tput cnorm 2>/dev/null
}

set_global_ssh_login() {
    echo ""
    SSH_DIR="$HOME/.ssh"

    shopt -s nullglob
    PUB_KEYS=("$SSH_DIR"/*.pub)
    shopt -u nullglob

    if [ ${#PUB_KEYS[@]} -eq 0 ]; then
        warn "No public keys found in $SSH_DIR."
        echo "  > Run option 1 to generate a key first, then come back here."
        return
    fi

    # Build arrays once; reuse for every picker call
    KEY_NAMES=()
    KEY_FPS=()
    for pub in "${PUB_KEYS[@]}"; do
        KEY_NAMES+=("$(basename "$pub" .pub)")
        KEY_FPS+=("$(ssh-keygen -lf "$pub" 2>/dev/null)")
    done

    # ── Transport key (core.sshCommand) ──────────────────────────────────────
    printf "\033[36m  --- Transport key (git push / pull / fetch) ---\033[0m\n\n"
    PICKER_KEYS=("${KEY_NAMES[@]}")
    PICKER_FPS=("${KEY_FPS[@]}")
    interactive_key_picker "Transport key for git SSH operations  (Esc = skip)"
    TRANSPORT_KEY="$PICKER_RESULT"
    echo ""

    if [ -n "$TRANSPORT_KEY" ]; then
        TRANSPORT_PATH="$SSH_DIR/$TRANSPORT_KEY"
        action "Setting global git SSH command to use key '$TRANSPORT_KEY'..."
        run git config --global core.sshCommand "ssh -i \"$TRANSPORT_PATH\" -o IdentitiesOnly=yes"
        ok "git config --global core.sshCommand updated."
        echo ""
        echo "  Verify : git config --global core.sshCommand"
        echo "  Test   : ssh -i \"$TRANSPORT_PATH\" -T git@github.com"
        echo ""
    fi

    # ── Signed commits (gpg.format ssh) ──────────────────────────────────────
    echo "------------------------------------------------------------"
    printf "\033[36m Signed commits (optional)\033[0m\n"
    echo "------------------------------------------------------------"
    echo "  Sets gpg.format=ssh + user.signingkey + commit.gpgsign=true"
    echo "  so VSCode and other tools sign commits automatically."
    echo ""

    SIGN_KEY=""
    if [ -n "$TRANSPORT_KEY" ]; then
        read -rp "Use the same key '$TRANSPORT_KEY' for signed commits? (Y/n): " USE_SAME
        if [[ "${USE_SAME,,}" == "" || "${USE_SAME,,}" == "y" ]]; then
            SIGN_KEY="$TRANSPORT_KEY"
        else
            echo ""
            PICKER_KEYS=("${KEY_NAMES[@]}")
            PICKER_FPS=("${KEY_FPS[@]}")
            interactive_key_picker "Signing key for commits  (Esc = skip)"
            SIGN_KEY="$PICKER_RESULT"
            echo ""
        fi
    else
        read -rp "Enable signed commits? (y/N): " ENABLE_SIGN
        if [[ "${ENABLE_SIGN,,}" == "y" ]]; then
            echo ""
            PICKER_KEYS=("${KEY_NAMES[@]}")
            PICKER_FPS=("${KEY_FPS[@]}")
            interactive_key_picker "Signing key for commits  (Esc = skip)"
            SIGN_KEY="$PICKER_RESULT"
            echo ""
        fi
    fi

    if [ -n "$SIGN_KEY" ]; then
        SIGN_PUB_PATH="$SSH_DIR/$SIGN_KEY.pub"
        action "Configuring signed commits with key '$SIGN_KEY'..."
        run git config --global gpg.format ssh
        run git config --global user.signingkey "$SIGN_PUB_PATH"
        run git config --global commit.gpgsign true
        ok "Signed commits enabled."
        echo ""
        echo "  Verify : git config --global --list | grep -E 'gpg|sign'"
        echo "  Note   : Register the public key on GitHub as a Signing Key at"
        echo "           https://github.com/settings/keys  (type: Signing Key)"
        echo ""
    fi

    # ── GitHub CLI auth ───────────────────────────────────────────────────────
    chk "GitHub CLI authentication status..."
    if gh auth status &>/dev/null; then
        ok "Already authenticated:"
        gh auth status
        echo ""
        read -rp "Re-authenticate to ensure SSH git-protocol is set? (y/N): " REAUTH
        if [[ "${REAUTH,,}" != "y" ]]; then
            [ -n "$TRANSPORT_KEY" ] && ok "Global SSH key configured. All git SSH operations will use '$TRANSPORT_KEY'."
            return
        fi
        action "Logging out first to allow fresh SSH-protocol login..."
        run gh auth logout
    fi

    action "Starting GitHub CLI login with SSH git-protocol..."
    echo "  > A browser window will open - authorize the GitHub CLI app."
    echo ""
    run gh auth login --web --git-protocol ssh --scopes repo,read:org,workflow
    if gh auth status &>/dev/null; then
        ok "GitHub CLI authenticated with SSH protocol."
        echo ""
        gh auth status
        [ -n "$TRANSPORT_KEY" ] && echo "" && ok "Global SSH key '$TRANSPORT_KEY' + gh SSH protocol configured."
    else
        fail "Authentication failed. Try: gh auth login --git-protocol ssh --scopes repo,read:org,workflow"
    fi
}

# ---- Option 6: View git signing / SSH transport config -----

show_signing_config() {
    echo ""
    printf "\033[36m  Git signing / SSH transport config (global)\033[0m\n"
    echo "  --------------------------------------------"
    echo ""

    for entry in \
        "gpg.format:gpg.format       " \
        "user.signingkey:user.signingkey  " \
        "commit.gpgsign:commit.gpgsign   " \
        "core.sshCommand:core.sshCommand  "; do
        KEY="${entry%%:*}"
        LABEL="${entry#*:}"
        VAL=$(git config --global "$KEY" 2>/dev/null)
        if [ -n "$VAL" ]; then
            printf "\033[32m  [ok]  %s = %s\033[0m\n" "$LABEL" "$VAL"
        else
            printf "\033[90m  [--]  %s   (not set)\033[0m\n" "$LABEL"
        fi
    done

    echo ""
    printf "\033[36m  Full signing-related entries:\033[0m\n"
    echo "[cmd]    git config --global --list | grep -E 'gpg|sign|ssh'"
    RESULT=$(git config --global --list 2>/dev/null | grep -E "gpg|sign|ssh")
    if [ -n "$RESULT" ]; then
        echo "$RESULT" | while IFS= read -r line; do
            printf "\033[36m  %s\033[0m\n" "$line"
        done
    else
        warn "No signing-related entries found in global git config."
        echo "  > Run option 5 to configure SSH signing and transport."
    fi
    echo ""
}

# ---- Option 7: List pull requests --------------------------

list_prs() {
    echo ""
    chk "GitHub CLI authentication..."
    if ! gh auth status &>/dev/null; then
        fail "Not authenticated with GitHub CLI. Run option 2 first."
        return
    fi
    ok "Authenticated."

    read -rp "Repository owner/repo (leave empty to use current directory): " REPO_INPUT
    read -rp "Base branch to filter (default: staging): " BASE_INPUT
    BASE="${BASE_INPUT:-staging}"

    echo ""
    if [ -n "$REPO_INPUT" ]; then
        echo "Pull requests targeting '$BASE' in $REPO_INPUT:"
        echo "[cmd]    gh pr list --repo $REPO_INPUT --base $BASE"
        gh pr list --repo "$REPO_INPUT" --base "$BASE"
    else
        echo "Pull requests targeting '$BASE' in current repo:"
        echo "[cmd]    gh pr list --base $BASE"
        gh pr list --base "$BASE"
    fi
}

# ---- Option 7: Merge a pull request ------------------------

merge_pr() {
    echo ""
    chk "GitHub CLI authentication..."
    if ! gh auth status &>/dev/null; then
        fail "Not authenticated with GitHub CLI. Run option 2 first."
        return
    fi
    ok "Authenticated."

    chk "Token scopes (repo scope required to merge)..."
    SCOPES=$(gh auth status 2>&1 | grep "Token scopes")
    if ! echo "$SCOPES" | grep -qw "repo"; then
        warn "Token is missing the 'repo' scope. Attempting to refresh..."
        run gh auth refresh --scopes repo,read:org
        if [ $? -ne 0 ]; then
            fail "Could not refresh token scopes. Try running: gh auth refresh --scopes repo,read:org"
            return
        fi
        ok "Token scopes refreshed."
    else
        ok "Token scopes OK: $SCOPES"
    fi

    read -rp "Repository owner/repo (leave empty to use current directory): " REPO_INPUT
    read -rp "Base branch (default: staging): " BASE_INPUT
    BASE="${BASE_INPUT:-staging}"
    REPO_FLAG=()
    [ -n "$REPO_INPUT" ] && REPO_FLAG=("--repo" "$REPO_INPUT")

    echo ""
    echo "Open pull requests targeting '$BASE':"
    echo "------------------------------------------------------------"
    run gh pr list "${REPO_FLAG[@]}" --base "$BASE" --state open
    echo "------------------------------------------------------------"
    echo ""

    read -rp "PR number to merge (leave empty to cancel): " PR_NUMBER
    if [ -z "$PR_NUMBER" ]; then
        echo "Cancelled."
        return
    fi

    echo ""
    echo "Merge strategy:"
    echo "  1. merge   - standard merge commit (default)"
    echo "  2. squash  - squash all commits into one"
    echo "  3. rebase  - rebase commits onto base branch"
    read -rp "Strategy (default: 1): " STRAT_INPUT
    case "$STRAT_INPUT" in
        2) STRATEGY="--squash" ;;
        3) STRATEGY="--rebase" ;;
        *) STRATEGY="--merge" ;;
    esac

    echo ""
    echo "Branch protection (pick one - these flags are mutually exclusive):"
    echo "  1. --admin  - bypass ALL requirements now: reviews, CI, branch rules (default)"
    echo "  2. --auto   - queue merge: auto-merges once CI and reviews pass (does NOT skip checks)"
    echo "  3. none     - standard merge, fails if any requirement is not met"
    read -rp "Policy (default: 1): " POLICY_INPUT
    case "$POLICY_INPUT" in
        2) POLICY_FLAG="--auto" ;;
        3) POLICY_FLAG="" ;;
        *) POLICY_FLAG="--admin" ;;
    esac
    POLICY_LABEL="${POLICY_FLAG:-none}"

    echo ""
    read -rp "Merge PR #$PR_NUMBER into '$BASE' [${STRATEGY#--}] [$POLICY_LABEL]? (y/N): " CONFIRM
    if [[ "${CONFIRM,,}" != "y" ]]; then
        echo "Cancelled."
        return
    fi

    MERGE_ARGS=("$PR_NUMBER" "${REPO_FLAG[@]}" "$STRATEGY" "--delete-branch")
    [ -n "$POLICY_FLAG" ] && MERGE_ARGS+=("$POLICY_FLAG")
    echo "[cmd]    gh pr merge ${MERGE_ARGS[*]}"
    MERGE_OUTPUT=$(gh pr merge "${MERGE_ARGS[@]}" 2>&1)
    MERGE_EXIT=$?
    echo "$MERGE_OUTPUT"
    if [ $MERGE_EXIT -eq 0 ]; then
        ok "PR #$PR_NUMBER merged successfully."
        echo ""
        VIEW_ARGS=("$PR_NUMBER" "${REPO_FLAG[@]}" --json state,mergedAt,mergedBy,title)
        echo "[cmd]    gh pr view ${VIEW_ARGS[*]}"
        VIEW=$(gh pr view "${VIEW_ARGS[@]}" 2>/dev/null)
        echo "  state    : $(echo "$VIEW" | grep -o '"state":"[^"]*"' | cut -d'"' -f4)"
        echo "  title    : $(echo "$VIEW" | grep -o '"title":"[^"]*"' | cut -d'"' -f4)"
        echo "  mergedAt : $(echo "$VIEW" | grep -o '"mergedAt":"[^"]*"' | cut -d'"' -f4)"
        echo "  mergedBy : $(echo "$VIEW" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('mergedBy',{}).get('login',''))" 2>/dev/null || echo "n/a")"
    else
        fail "Merge failed."
        if echo "$MERGE_OUTPUT" | grep -q "Resource not accessible by personal access token"; then
            echo ""
            echo "  This error means the GitHub CLI OAuth app is not authorized for the organization."
            echo "  Fix options:"
            echo "    A) Go to https://github.com/settings/connections/applications"
            echo "       Find 'GitHub CLI' and click 'Grant' next to your organization."
            echo ""
            echo "    B) Re-authenticate and authorize the org during the browser flow:"
            echo "       gh auth refresh --scopes repo,read:org,workflow"
        fi
    fi
}

# ---- Option 8: Force merge (bypass all rulesets) -----------

bypass_merge() {
    echo ""
    chk "GitHub CLI authentication..."
    echo "[cmd]    gh auth status"
    if ! gh auth status &>/dev/null; then
        fail "Not authenticated with GitHub CLI. Run option 2 first."
        return
    fi
    ok "Authenticated."

    read -rp "Repository owner/repo (leave empty for current directory): " REPO_INPUT
    REPO_FLAG=()
    [ -n "$REPO_INPUT" ] && REPO_FLAG=("--repo" "$REPO_INPUT")
    REPO_NAME=$(get_repo_name "$REPO_INPUT") || return

    echo ""
    echo "[cmd]    gh api repos/$REPO_NAME/rulesets"
    RULESETS=$(gh api repos/$REPO_NAME/rulesets 2>&1)
    if [ -z "$RULESETS" ] || echo "$RULESETS" | grep -q '"message"'; then
        warn "No rulesets found or access denied for $REPO_NAME."
        return
    fi

    echo ""
    echo "Active rulesets:"
    echo "------------------------------------------------------------"
    echo "$RULESETS" | python3 -c "
import sys,json
for r in json.load(sys.stdin):
    print(f\"  [{r['id']}] {r['name']} - enforcement: {r['enforcement']}\")
" 2>/dev/null || echo "$RULESETS" | grep -E '"id"|"name"|"enforcement"'
    echo "------------------------------------------------------------"

    read -rp "PR number to merge: " PR_NUMBER
    [ -z "$PR_NUMBER" ] && echo "Cancelled." && return

    echo ""
    echo "Merge strategy (merge commits are often disabled - squash is safer):"
    echo "  1. squash  - squash all commits into one (default)"
    echo "  2. rebase  - rebase commits onto base branch"
    echo "  3. merge   - standard merge commit"
    read -rp "Strategy (default: 1): " STRAT_INPUT
    case "$STRAT_INPUT" in
        2) STRATEGY="--rebase" ;;
        3) STRATEGY="--merge" ;;
        *) STRATEGY="--squash" ;;
    esac

    echo ""
    read -rp "Disable ALL rulesets, merge PR #$PR_NUMBER [${STRATEGY#--}], then re-enable? (y/N): " CONFIRM
    [[ "${CONFIRM,,}" != "y" ]] && echo "Cancelled." && return

    # Disable all active rulesets
    ORG="${REPO_NAME%%/*}"
    DISABLED_ENTRIES=()
    while IFS='|' read -r RS_ID RS_NAME RS_SRC_TYPE RS_SOURCE RS_ENF; do
        if [ -n "$RS_ID" ] && [ "$RS_ENF" != "disabled" ]; then
            if [ "$RS_SRC_TYPE" = "Organization" ]; then
                ENDPOINT="orgs/$ORG/rulesets/$RS_ID"
            else
                ENDPOINT="repos/$REPO_NAME/rulesets/$RS_ID"
            fi
            echo "[cmd]    gh api --method PUT $ENDPOINT -f enforcement=disabled -f name=$RS_NAME"
            RES=$(gh api --method PUT "$ENDPOINT" -f enforcement=disabled -f name="$RS_NAME" 2>&1)
            if [ $? -eq 0 ]; then
                DISABLED_ENTRIES+=("$RS_ID|$RS_NAME|$RS_SRC_TYPE|$ENDPOINT")
                ok "Ruleset '$RS_NAME' disabled."
            else
                warn "Could not disable '$RS_NAME': $RES"
            fi
        fi
    done < <(echo "$RULESETS" | python3 -c "
import sys,json
for r in json.load(sys.stdin):
    print(f\"{r['id']}|{r['name']}|{r.get('source_type','Repository')}|{r.get('source','')}|{r['enforcement']}\")
" 2>/dev/null)

    # Merge
    MERGE_ARGS=("$PR_NUMBER" "${REPO_FLAG[@]}" "$STRATEGY" "--delete-branch")
    echo "[cmd]    gh pr merge ${MERGE_ARGS[*]}"
    MERGE_OUTPUT=$(gh pr merge "${MERGE_ARGS[@]}" 2>&1)
    MERGE_EXIT=$?
    echo "$MERGE_OUTPUT"

    # Re-enable rulesets (always, even if merge failed)
    for entry in "${DISABLED_ENTRIES[@]}"; do
        RS_ID="${entry%%|*}"
        rest="${entry#*|}"
        RS_NAME="${rest%%|*}"
        rest="${rest#*|}"
        RS_SRC_TYPE="${rest%%|*}"
        ENDPOINT="${rest#*|}"
        echo "[cmd]    gh api --method PUT $ENDPOINT -f enforcement=active -f name=$RS_NAME"
        RES=$(gh api --method PUT "$ENDPOINT" -f enforcement=active -f name="$RS_NAME" 2>&1)
        [ $? -eq 0 ] && ok "Ruleset '$RS_NAME' re-enabled." || warn "Could not re-enable '$RS_NAME'."
    done

    if [ $MERGE_EXIT -eq 0 ]; then
        ok "PR #$PR_NUMBER merged successfully."
        echo ""
        VIEW_ARGS=("$PR_NUMBER" "${REPO_FLAG[@]}" --json state,mergedAt,mergedBy,title)
        echo "[cmd]    gh pr view ${VIEW_ARGS[*]}"
        VIEW=$(gh pr view "${VIEW_ARGS[@]}" 2>/dev/null)
        echo "  state    : $(echo "$VIEW" | grep -o '"state":"[^"]*"' | cut -d'"' -f4)"
        echo "  title    : $(echo "$VIEW" | grep -o '"title":"[^"]*"' | cut -d'"' -f4)"
        echo "  mergedAt : $(echo "$VIEW" | grep -o '"mergedAt":"[^"]*"' | cut -d'"' -f4)"
    else
        fail "Merge failed even after bypassing rulesets. Check the output above."
    fi
}

# ---- Option 9: List pending conversations ------------------

list_conversations() {
    echo ""
    read -rp "Repository owner/repo (leave empty to detect from git remote): " REPO_INPUT
    REPO_NAME=$(get_repo_name "$REPO_INPUT") || return
    read -rp "PR number: " PR_NUMBER
    [ -z "$PR_NUMBER" ] && echo "Cancelled." && return

    OWNER="${REPO_NAME%%/*}"; REPO_ONLY="${REPO_NAME#*/}"
    GQL_QUERY='query($owner:String!,$name:String!,$num:Int!){repository(owner:$owner,name:$name){pullRequest(number:$num){reviewThreads(first:50){nodes{id isResolved comments(first:1){nodes{body author{login}}}}}}}}'
    echo "[cmd]    gh api graphql -f query=<reviewThreads> -f owner=$OWNER -f name=$REPO_ONLY -F num=$PR_NUMBER"
    RAW=$(gh api graphql -f query="$GQL_QUERY" -f owner="$OWNER" -f name="$REPO_ONLY" -F num="$PR_NUMBER" 2>&1)
    if [ $? -ne 0 ]; then fail "GraphQL error: $RAW"; return; fi

    echo ""
    echo "Pending conversations in PR #$PR_NUMBER:"
    echo "------------------------------------------------------------"
    echo "$RAW" | python3 -c "
import sys, json
data = json.load(sys.stdin)
threads = data['data']['repository']['pullRequest']['reviewThreads']['nodes']
pending = [t for t in threads if not t['isResolved']]
if not pending:
    print('  No pending conversations.')
for t in pending:
    c = t['comments']['nodes'][0]
    body = c['body'][:120] + ('...' if len(c['body']) > 120 else '')
    print(f\"  ID     : {t['id']}\")
    print(f\"  Author : {c['author']['login']}\")
    print(f\"  Comment: {body}\")
    print()
" 2>/dev/null || { warn "Could not parse response. Raw output:"; echo "$RAW"; }
    echo "------------------------------------------------------------"
}

# ---- Option 10: Resolve a conversation ---------------------

resolve_conversation() {
    echo ""
    read -rp "Repository owner/repo (leave empty to detect from git remote): " REPO_INPUT
    REPO_NAME=$(get_repo_name "$REPO_INPUT") || return
    read -rp "PR number: " PR_NUMBER
    [ -z "$PR_NUMBER" ] && echo "Cancelled." && return

    OWNER="${REPO_NAME%%/*}"; REPO_ONLY="${REPO_NAME#*/}"
    GQL_QUERY='query($owner:String!,$name:String!,$num:Int!){repository(owner:$owner,name:$name){pullRequest(number:$num){reviewThreads(first:50){nodes{id isResolved comments(first:1){nodes{body author{login}}}}}}}}'
    echo "[cmd]    gh api graphql -f query=<reviewThreads> -f owner=$OWNER -f name=$REPO_ONLY -F num=$PR_NUMBER"
    RAW=$(gh api graphql -f query="$GQL_QUERY" -f owner="$OWNER" -f name="$REPO_ONLY" -F num="$PR_NUMBER" 2>&1)
    if [ $? -ne 0 ]; then fail "GraphQL error: $RAW"; return; fi

    echo ""
    echo "$RAW" | python3 -c "
import sys, json
data = json.load(sys.stdin)
threads = data['data']['repository']['pullRequest']['reviewThreads']['nodes']
for t in threads:
    if not t['isResolved']:
        c = t['comments']['nodes'][0]
        body = c['body'][:80] + ('...' if len(c['body']) > 80 else '')
        print(f\"  {t['id']}  |  {c['author']['login']}: {body}\")
" 2>/dev/null
    echo ""

    read -rp "Thread ID to resolve (or 'all' to resolve all): " THREAD_ID
    [ -z "$THREAD_ID" ] && echo "Cancelled." && return

    PENDING_IDS=()
    if [ "$THREAD_ID" = "all" ]; then
        mapfile -t PENDING_IDS < <(echo "$RAW" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for t in data['data']['repository']['pullRequest']['reviewThreads']['nodes']:
    if not t['isResolved']: print(t['id'])
" 2>/dev/null)
    else
        PENDING_IDS=("$THREAD_ID")
    fi

    GQL_MUTATION='mutation($tid:ID!){resolveReviewThread(input:{threadId:$tid}){thread{id isResolved}}}'
    for TID in "${PENDING_IDS[@]}"; do
        echo "[cmd]    gh api graphql -f query=<resolveReviewThread> -f tid=$TID"
        RES=$(gh api graphql -f query="$GQL_MUTATION" -f tid="$TID" 2>&1)
        [ $? -eq 0 ] && ok "Thread $TID resolved." || fail "Failed: $RES"
    done
}

# ---- Option 11: List rulesets ------------------------------

list_rulesets() {
    echo ""
    read -rp "Repository owner/repo (leave empty to detect from git remote): " REPO_INPUT
    REPO_NAME=$(get_repo_name "$REPO_INPUT") || return
    echo ""
    echo "[cmd]    gh api repos/$REPO_NAME/rulesets"
    RAW=$(gh api repos/$REPO_NAME/rulesets 2>&1)
    if [ $? -ne 0 ]; then fail "API error: $RAW"; return; fi
    echo ""
    echo "Rulesets for $REPO_NAME:"
    echo "------------------------------------------------------------"
    echo "$RAW" | python3 -c "
import sys, json
for r in json.load(sys.stdin):
    print(f\"  [{r['id']}] {r['name']}\")
    print(f\"       enforcement : {r['enforcement']}\")
    print(f\"       target      : {r.get('target','')}\")
    print()
" 2>/dev/null || echo "$RAW"
    echo "------------------------------------------------------------"
}

# ---- Options 12/13: Toggle a specific ruleset --------------

set_ruleset_state() {
    local TARGET_STATE="$1"
    echo ""
    read -rp "Repository owner/repo (leave empty to detect from git remote): " REPO_INPUT
    REPO_NAME=$(get_repo_name "$REPO_INPUT") || return

    echo "[cmd]    gh api repos/$REPO_NAME/rulesets"
    RAW=$(gh api repos/$REPO_NAME/rulesets 2>&1)
    if [ $? -ne 0 ]; then fail "API error: $RAW"; return; fi

    echo ""
    echo "$RAW" | python3 -c "
import sys, json
for r in json.load(sys.stdin):
    src = r.get('source_type','?')
    print(f\"  [{r['id']}] {r['name']} - enforcement: {r['enforcement']} - source: {src}\")
" 2>/dev/null || echo "$RAW"
    echo ""

    read -rp "Ruleset ID to set to '$TARGET_STATE': " RS_ID
    [ -z "$RS_ID" ] && echo "Cancelled." && return

    RS_DATA=$(echo "$RAW" | python3 -c "
import sys, json
for r in json.load(sys.stdin):
    if str(r['id']) == '$RS_ID':
        print(r['name'] + '|' + r.get('source_type','Repository') + '|' + r.get('source',''))
" 2>/dev/null)
    RS_NAME="${RS_DATA%%|*}"
    RS_REST="${RS_DATA#*|}"
    RS_SRC_TYPE="${RS_REST%%|*}"

    read -rp "Set ruleset '$RS_NAME' to '$TARGET_STATE'? (y/N): " CONFIRM
    [[ "${CONFIRM,,}" != "y" ]] && echo "Cancelled." && return

    ORG="${REPO_NAME%%/*}"
    if [ "$RS_SRC_TYPE" = "Organization" ]; then
        ENDPOINT="orgs/$ORG/rulesets/$RS_ID"
    else
        ENDPOINT="repos/$REPO_NAME/rulesets/$RS_ID"
    fi
    echo "[cmd]    gh api --method PUT $ENDPOINT -f enforcement=$TARGET_STATE -f name=$RS_NAME"
    RES=$(gh api --method PUT "$ENDPOINT" -f enforcement="$TARGET_STATE" -f name="$RS_NAME" 2>&1)
    [ $? -eq 0 ] && ok "Ruleset '$RS_NAME' is now '$TARGET_STATE'." || fail "Failed: $RES"
}

disable_ruleset() { set_ruleset_state "disabled"; }
enable_ruleset()  { set_ruleset_state "active"; }

# ---- Option 14: Dependabot alerts --------------------------

list_dependabot_alerts() {
    echo ""
    read -rp "Repository owner/repo (leave empty to detect from git remote): " REPO_INPUT
    REPO_NAME=$(get_repo_name "$REPO_INPUT") || return

    read -rp "State filter (open/dismissed/fixed/auto_dismissed/all - default: all): " STATE_INPUT
    FILTER_STATE="${STATE_INPUT}"
    [ -z "$FILTER_STATE" ] || [ "$FILTER_STATE" = "all" ] && FILTER_STATE=""

    if [ -n "$FILTER_STATE" ]; then
        echo "[cmd]    gh api --paginate repos/$REPO_NAME/dependabot/alerts -f state=$FILTER_STATE"
        RAW=$(gh api --paginate "repos/$REPO_NAME/dependabot/alerts" -f state="$FILTER_STATE" 2>&1)
    else
        echo "[cmd]    gh api --paginate repos/$REPO_NAME/dependabot/alerts"
        RAW=$(gh api --paginate "repos/$REPO_NAME/dependabot/alerts" 2>&1)
    fi
    if [ $? -ne 0 ]; then
        fail "Dependabot API error."
        echo "  Possible causes:"
        echo "    1. Dependabot not enabled -> Settings -> Security -> Dependabot alerts"
        echo "    2. Token missing scope -> gh auth refresh --scopes repo,security_events"
        return
    fi

    echo ""
    echo "$RAW" | python3 -c "
import sys, json
alerts = json.load(sys.stdin)
if not alerts: print('No Dependabot alerts found.'); sys.exit(0)
print(f'Dependabot alerts ({len(alerts)} total):')
print('------------------------------------------------------------')
for a in alerts:
    sev = a['security_advisory']['severity'].upper()
    eco = a['dependency']['package']['ecosystem']
    pkg = a['dependency']['package']['name']
    cve = a['security_advisory'].get('cve_id','N/A')
    cvss = a['security_advisory'].get('cvss',{}).get('score','N/A')
    print(f\"  [#{a['number']}] [{a['state'].upper()}] [{sev}] {eco}/{pkg}\")
    print(f\"         {a['security_advisory']['summary']}\")
    print(f\"         CVE: {cve}  CVSS: {cvss}\")
    print()
print('------------------------------------------------------------')
" 2>/dev/null || { warn "Could not parse response."; echo "$RAW"; }
    echo "Browser: https://github.com/$REPO_NAME/security/dependabot"
}

# ---- Option 15: Secret scanning alerts ---------------------

list_secret_alerts() {
    echo ""
    read -rp "Repository owner/repo (leave empty to detect from git remote): " REPO_INPUT
    REPO_NAME=$(get_repo_name "$REPO_INPUT") || return

    read -rp "State filter (open/resolved/all - default: all): " STATE_INPUT
    FILTER_STATE="${STATE_INPUT}"
    [ -z "$FILTER_STATE" ] || [ "$FILTER_STATE" = "all" ] && FILTER_STATE=""

    if [ -n "$FILTER_STATE" ]; then
        echo "[cmd]    gh api --paginate repos/$REPO_NAME/secret-scanning/alerts -f state=$FILTER_STATE"
        RAW=$(gh api --paginate "repos/$REPO_NAME/secret-scanning/alerts" -f state="$FILTER_STATE" 2>&1)
    else
        echo "[cmd]    gh api --paginate repos/$REPO_NAME/secret-scanning/alerts"
        RAW=$(gh api --paginate "repos/$REPO_NAME/secret-scanning/alerts" 2>&1)
    fi
    if [ $? -ne 0 ]; then
        fail "Secret scanning API error."
        echo "  Possible causes:"
        echo "    1. Secret scanning not enabled -> Settings -> Security -> Secret scanning"
        echo "    2. Token missing scope -> gh auth refresh --scopes repo,security_events"
        return
    fi

    echo ""
    echo "$RAW" | python3 -c "
import sys, json
alerts = json.load(sys.stdin)
if not alerts: print('No secret scanning alerts found.'); sys.exit(0)
print(f'Secret scanning alerts ({len(alerts)} total):')
print('------------------------------------------------------------')
for a in alerts:
    print(f\"  [#{a['number']}] [{a['state'].upper()}] {a['secret_type_display_name']}\")
    print(f\"         Validity : {a.get('validity','N/A')}\")
    print(f\"         Created  : {a.get('created_at','N/A')}\")
    print(f\"         URL      : {a.get('html_url','N/A')}\")
    print()
print('------------------------------------------------------------')
" 2>/dev/null || { warn "Could not parse response."; echo "$RAW"; }
    echo "Browser: https://github.com/$REPO_NAME/security/secret-scanning"
}

# ---- Option 16: Code scanning alerts -----------------------

list_code_alerts() {
    echo ""
    read -rp "Repository owner/repo (leave empty to detect from git remote): " REPO_INPUT
    REPO_NAME=$(get_repo_name "$REPO_INPUT") || return

    read -rp "State filter (open/dismissed/fixed/all - default: all): " STATE_INPUT
    FILTER_STATE="${STATE_INPUT}"
    [ -z "$FILTER_STATE" ] || [ "$FILTER_STATE" = "all" ] && FILTER_STATE=""

    if [ -n "$FILTER_STATE" ]; then
        echo "[cmd]    gh api --paginate repos/$REPO_NAME/code-scanning/alerts -f state=$FILTER_STATE"
        RAW=$(gh api --paginate "repos/$REPO_NAME/code-scanning/alerts" -f state="$FILTER_STATE" 2>&1)
    else
        echo "[cmd]    gh api --paginate repos/$REPO_NAME/code-scanning/alerts"
        RAW=$(gh api --paginate "repos/$REPO_NAME/code-scanning/alerts" 2>&1)
    fi
    if [ $? -ne 0 ]; then
        fail "Code scanning API error."
        echo "  Possible causes:"
        echo "    1. No code scanning analysis found (GitHub Actions workflow needed)"
        echo "    2. Token missing scope -> gh auth refresh --scopes repo,security_events,admin:repo_hook"
        echo "    3. Code scanning not configured -> Settings -> Security -> Code scanning"
        return
    fi

    echo ""
    echo "$RAW" | python3 -c "
import sys, json
alerts = json.load(sys.stdin)
if not alerts: print('No code scanning alerts found.'); sys.exit(0)
print(f'Code scanning alerts ({len(alerts)} total):')
print('------------------------------------------------------------')
for a in alerts:
    rule = a.get('rule', {})
    sev = rule.get('security_severity_level') or rule.get('severity','N/A')
    tags = ', '.join(rule.get('tags') or [])
    ref = a.get('most_recent_instance',{}).get('ref','N/A')
    print(f\"  [#{a['number']}] [{a['state'].upper()}] [{sev.upper()}] {rule.get('name','')}\")
    print(f\"         {rule.get('description','')}\")
    if tags: print(f\"         Tags: {tags}\")
    print(f\"         Tool: {a.get('tool',{}).get('name','N/A')} | Ref: {ref}\")
    print()
print('------------------------------------------------------------')
" 2>/dev/null || { warn "Could not parse response."; echo "$RAW"; }
    echo "Browser: https://github.com/$REPO_NAME/security/code-scanning"
}

# ---- Option 17: Generate JSON reports ----------------------

generate_report() {
    echo ""
    read -rp "Repository owner/repo (leave empty to detect from git remote): " REPO_INPUT
    REPO_NAME=$(get_repo_name "$REPO_INPUT") || return

    mkdir -p tmp

    # PR report
    read -rp "PR number for issue report (leave empty to skip): " PR_NUMBER
    if [ -n "$PR_NUMBER" ]; then
        echo ""
        echo "[action] Generating PR report for #$PR_NUMBER..."
        OWNER="${REPO_NAME%%/*}"; REPO_ONLY="${REPO_NAME#*/}"

        echo "[cmd]    gh api repos/$REPO_NAME/pulls/$PR_NUMBER"
        PR_DATA=$(gh api "repos/$REPO_NAME/pulls/$PR_NUMBER" 2>/dev/null)

        GQL_QUERY='query($owner:String!,$name:String!,$num:Int!){repository(owner:$owner,name:$name){pullRequest(number:$num){title state body author{login} baseRefName headRefName createdAt mergedAt reviews(first:50){nodes{id state author{login} body submittedAt}} reviewThreads(first:50){nodes{id isResolved path line comments(first:20){nodes{body author{login} createdAt}}}}}}}'
        echo "[cmd]    gh api graphql -f query=<PR full detail>"
        GQL_DATA=$(gh api graphql -f query="$GQL_QUERY" -f owner="$OWNER" -f name="$REPO_ONLY" -F num="$PR_NUMBER" 2>/dev/null)

        echo "[cmd]    gh api repos/$REPO_NAME/issues/$PR_NUMBER/comments"
        COMMENTS=$(gh api "repos/$REPO_NAME/issues/$PR_NUMBER/comments" 2>/dev/null)

        OUT="tmp/issue.pr${PR_NUMBER}.json"
        python3 -c "
import sys, json
from datetime import datetime, timezone

pr = json.loads('''$PR_DATA''') if '''$PR_DATA''' else {}
gql = json.loads('''$GQL_DATA''') if '''$GQL_DATA''' else {}
comments = json.loads('''$COMMENTS''') if '''$COMMENTS''' else []

pr_gql = gql.get('data',{}).get('repository',{}).get('pullRequest',{}) if gql else {}
threads = pr_gql.get('reviewThreads',{}).get('nodes',[]) if pr_gql else []
pending = [t for t in threads if not t.get('isResolved')]

report = {
    'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    'repo': '$REPO_NAME',
    'pr_number': $PR_NUMBER,
    'title': pr.get('title'),
    'state': pr.get('state'),
    'author': pr.get('user',{}).get('login'),
    'base_branch': pr.get('base',{}).get('ref'),
    'head_branch': pr.get('head',{}).get('ref'),
    'created_at': pr.get('created_at'),
    'merged_at': pr.get('merged_at'),
    'body': pr.get('body'),
    'pending_count': len(pending),
    'pending_conversations': pending,
    'all_review_threads': threads,
    'reviews': pr_gql.get('reviews',{}).get('nodes',[]),
    'comments': comments,
}
with open('$OUT','w') as f: json.dump(report, f, indent=2)
print(f'[ok]     PR report saved: $OUT ({len(pending)} pending conversations)')
" 2>/dev/null || { warn "Could not generate PR report."; }
    fi

    # Security report
    read -rp "Generate security report? (Y/n - default: y): " GEN_SEC
    if [[ "${GEN_SEC,,}" != "n" ]]; then
        echo ""
        echo "[action] Fetching Dependabot alerts..."
        echo "[cmd]    gh api --paginate repos/$REPO_NAME/dependabot/alerts"
        DEP=$(gh api --paginate "repos/$REPO_NAME/dependabot/alerts" 2>/dev/null || echo "[]")

        echo "[action] Fetching secret scanning alerts..."
        echo "[cmd]    gh api --paginate repos/$REPO_NAME/secret-scanning/alerts"
        SEC=$(gh api --paginate "repos/$REPO_NAME/secret-scanning/alerts" 2>/dev/null || echo "[]")

        echo "[action] Fetching code scanning alerts..."
        echo "[cmd]    gh api --paginate repos/$REPO_NAME/code-scanning/alerts"
        CODE=$(gh api --paginate "repos/$REPO_NAME/code-scanning/alerts" 2>/dev/null || echo "[]")

        OUT="tmp/issue.security.json"
        python3 -c "
import sys, json
from datetime import datetime, timezone

dep   = json.loads('''$DEP''')   if '''$DEP'''   else []
sec   = json.loads('''$SEC''')   if '''$SEC'''   else []
code  = json.loads('''$CODE''')  if '''$CODE'''  else []

report = {
    'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    'repo': '$REPO_NAME',
    'summary': {
        'dependabot_total':  len(dep),
        'secret_scan_total': len(sec),
        'code_scan_total':   len(code),
    },
    'dependabot_alerts':      dep,
    'secret_scanning_alerts': sec,
    'code_scanning_alerts':   code,
}
with open('$OUT','w') as f: json.dump(report, f, indent=2)
print(f'[ok]     Security report saved: $OUT (dep:{len(dep)} sec:{len(sec)} code:{len(code)})')
" 2>/dev/null || { warn "Could not generate security report."; }
    fi
}

# ============================================================
#  Bootstrap
# ============================================================

echo ""
echo "============================================"
echo " GitHub Key & Auth Manager"
echo "============================================"
echo ""
echo "Checking dependencies..."
echo ""

ensure_ssh_keygen
ensure_gh
ensure_ssh_dir

echo ""
ok "All dependencies satisfied."

# ============================================================
#  Main menu
# ============================================================

while true; do
    echo ""
    echo "============================================"
    echo " Menu"
    echo "============================================"
    echo "  --- SSH & Auth ---"
    echo "  1.  Create SSH key for GitHub"
    echo "  2.  Authenticate with GitHub CLI (gh auth login)"
    echo "  3.  Logout / switch GitHub account"
    echo "  4.  List SSH keys"
    echo "  5.  Set global GitHub login via SSH key (optional key selection)"
    echo "  6.  View git signing / SSH transport config"
    echo "  --- Pull Requests ---"
    echo "  7.  List pull requests"
    echo "  8.  Merge a pull request"
    echo "  9.  Force merge (bypass all rulesets temporarily)"
    echo "  10. List pending conversations in a PR"
    echo "  11. Resolve a conversation in a PR"
    echo "  --- Rulesets ---"
    echo "  12. List rulesets"
    echo "  13. Disable a specific ruleset"
    echo "  14. Enable a specific ruleset"
    echo "  --- Security ---"
    echo "  15. Dependabot alerts (dependency vulnerabilities)"
    echo "  16. Secret scanning alerts"
    echo "  17. Code scanning alerts (quality / malware)"
    echo "  18. Generate JSON reports (PR conversations + security)"
    echo "  --- ---"
    echo "  0.  Exit"
    echo ""
    read -rp "Select an option: " CHOICE

    case "$CHOICE" in
        1)  create_ssh_key ;;
        2)  github_auth ;;
        3)  github_logout ;;
        4)  list_ssh_keys ;;
        5)  set_global_ssh_login ;;
        6)  show_signing_config ;;
        7)  list_prs ;;
        8)  merge_pr ;;
        9)  bypass_merge ;;
        10) list_conversations ;;
        11) resolve_conversation ;;
        12) list_rulesets ;;
        13) disable_ruleset ;;
        14) enable_ruleset ;;
        15) list_dependabot_alerts ;;
        16) list_secret_alerts ;;
        17) list_code_alerts ;;
        18) generate_report ;;
        0)  echo ""; echo "Goodbye."; break ;;
        *)  warn "Invalid option. Enter 1-18 or 0." ;;
    esac

    if [ "$CHOICE" != "0" ]; then
        echo ""
        read -rp "Press Enter to return to menu..."
    fi
done
