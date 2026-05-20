#!/usr/bin/env bash
# wgflow — repo-rebuild.sh
#
# Ricostruisce la history del repo committando ogni tarball in
# release-tarballs/ come release a sé stante. Salta i tarball
# corrispondenti a release già committate (3.6, 3.7, 3.8, 3.8.3).
# Lascia main puntato a v4.3.0.
#
# Strategia (Opzione A):
#   - parte dal commit attuale (HEAD = v3.8.3 nel tuo repo)
#   - per ogni tarball da v4.0-alpha in poi, in ordine cronologico:
#       * estrae il tarball
#       * sostituisce il working tree (preserva .git, .gitignore,
#         release-tarballs/, tmp/, e tutto ciò che è gitignored)
#       * crea un commit con la data dal CHANGELOG (backdated)
#       * crea un tag annotato vX.Y.Z
#   - alla fine: mostra log + chiede conferma → push su origin
#
# Reversibile fino al push finale:
#   - tar di backup del repo in /tmp prima di toccare niente
#   - tutti i commit sono locali finché non si fa il push
#   - dry-run mode disponibile con --dry-run
#
# Usage:
#   ./repo-rebuild.sh                # interattivo, conferma prima del push
#   ./repo-rebuild.sh --dry-run      # nessuna modifica, mostra cosa farebbe
#   ./repo-rebuild.sh --no-push      # tutto tranne il push, lascia history locale

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

REPO_DIR="${REPO_DIR:-/home/colgab/wgflow}"
TARBALL_DIR="${REPO_DIR}/release-tarballs"
CHANGELOG_PATH=""   # popolato dopo l'estrazione del tarball v4.3.0
WORK_DIR=""          # tmp dir per le estrazioni
BACKUP_PATH=""       # tmp file del backup pre-modifica
EXPECTED_REMOTE="git@github.com:gcblauth/wgflow.git"
EXPECTED_BRANCH="main"

# Tarball già rappresentati come commit nella history attuale.
# Lo script SALTA questi anche se i tarball esistono in
# release-tarballs/.
SKIP_TARBALLS=(
    "wgflow-v3.6.tar.gz"
    "wgflow-v3.7.tar.gz"
    "wgflow-v3.8.tar.gz"
    "wgflow-v3.8.3.tar.gz"
)

# Ordine cronologico esplicito. Più sicuro di un sort numerico,
# che si confonde su "-alpha" / "-pre". Tarball non presenti in
# release-tarballs/ vengono saltati senza errore.
RELEASE_ORDER=(
    "v4.0-alpha"
    "v4.2.0"
    "v4.2.1"
    "v4.2.2"
    # v4.2.3 non ha tarball — saltato
    "v4.2.4"
    "v4.2.5"
    "v4.2.6"
    "v4.3.0"
)

DRY_RUN=0
SKIP_PUSH=0

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_DIM=$'\033[2m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_RED=$'\033[31m'
    C_CYAN=$'\033[36m'
else
    C_RESET= C_BOLD= C_DIM= C_GREEN= C_YELLOW= C_RED= C_CYAN=
fi

say()  { printf "${C_DIM}[repo]${C_RESET} %s\n" "$*"; }
ok()   { printf "${C_DIM}[repo]${C_RESET} ${C_GREEN}✓${C_RESET} %s\n" "$*"; }
warn() { printf "${C_DIM}[repo]${C_RESET} ${C_YELLOW}!${C_RESET} %s\n" "$*" >&2; }
fail() { printf "${C_DIM}[repo]${C_RESET} ${C_RED}✗${C_RESET} %s\n" "$*" >&2; exit 1; }
hdr()  { printf "\n${C_BOLD}== %s ==${C_RESET}\n" "$*"; }

# Run a command; in dry-run mode, just print it.
run() {
    if [[ $DRY_RUN -eq 1 ]]; then
        printf "${C_CYAN}[dry-run]${C_RESET} %s\n" "$*"
    else
        "$@"
    fi
}

# ---------------------------------------------------------------------------
# Flag parsing
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)  DRY_RUN=1 ;;
        --no-push)  SKIP_PUSH=1 ;;
        -h|--help)
            sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) fail "flag sconosciuto: $1" ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

hdr "Pre-flight"

# Sono nel repo giusto?
[[ -d "$REPO_DIR/.git" ]] || fail "$REPO_DIR non sembra un repo git"
cd "$REPO_DIR"
say "repo: $REPO_DIR"

# Remote corretto?
remote_url=$(git remote get-url origin 2>/dev/null || true)
if [[ "$remote_url" != "$EXPECTED_REMOTE" ]]; then
    warn "remote origin è '$remote_url' (mi aspettavo '$EXPECTED_REMOTE')"
    warn "continuo comunque, ma controlla due volte prima del push"
fi
say "remote: $remote_url"

# Branch corretto?
current_branch=$(git branch --show-current)
[[ "$current_branch" == "$EXPECTED_BRANCH" ]] || \
    fail "sei su branch '$current_branch', mi serve '$EXPECTED_BRANCH'"
say "branch: $current_branch"

# Working tree pulito? (ignora file untracked che sono gitignored)
if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    git status --short >&2
    fail "working tree ha modifiche non committate — fai commit/stash prima"
fi
ok "working tree pulito"

# Tarball directory esiste?
[[ -d "$TARBALL_DIR" ]] || fail "directory tarball non trovata: $TARBALL_DIR"

# Tarball v4.3.0 esiste? Ce ne serve almeno uno per il CHANGELOG.
[[ -f "$TARBALL_DIR/wgflow-v4.3.0.tar.gz" ]] || \
    fail "wgflow-v4.3.0.tar.gz mancante in $TARBALL_DIR"
ok "tarball trovati"

# Comandi richiesti.
for cmd in git tar awk grep sed; do
    command -v "$cmd" >/dev/null || fail "comando mancante: $cmd"
done
ok "tutti i comandi richiesti disponibili"

# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------

hdr "Backup"

BACKUP_PATH="/tmp/wgflow-repo-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
if [[ $DRY_RUN -eq 0 ]]; then
    say "backup completo del repo (incluso .git) in $BACKUP_PATH"
    tar -czf "$BACKUP_PATH" -C "$(dirname "$REPO_DIR")" "$(basename "$REPO_DIR")"
    ok "backup: $BACKUP_PATH ($(du -h "$BACKUP_PATH" | cut -f1))"
    say "per ripristinare: rm -rf $REPO_DIR && tar -xzf $BACKUP_PATH -C $(dirname "$REPO_DIR")"
else
    say "[dry-run] salterei la creazione del backup"
fi

# ---------------------------------------------------------------------------
# Estrazione di tutti i tarball in una working dir
# ---------------------------------------------------------------------------

hdr "Estrazione tarball"

WORK_DIR=$(mktemp -d -t wgflow-rebuild-XXXXXX)
say "work dir: $WORK_DIR"

# Estraggo prima v4.3.0 per parsare il CHANGELOG (è il più completo).
say "estraggo v4.3.0 per leggere il CHANGELOG..."
tar -xzf "$TARBALL_DIR/wgflow-v4.3.0.tar.gz" -C "$WORK_DIR"
CHANGELOG_PATH="$WORK_DIR/wgflow-v4.3.0/CHANGELOG.md"
[[ -f "$CHANGELOG_PATH" ]] || fail "CHANGELOG.md non trovato nel tarball v4.3.0"
ok "CHANGELOG riferimento: $CHANGELOG_PATH"

# Adesso estraggo tutti i tarball che dobbiamo committare. Salto
# quelli in SKIP_TARBALLS e quelli che non esistono fisicamente.
declare -A AVAILABLE_RELEASES
for ver in "${RELEASE_ORDER[@]}"; do
    tarball="wgflow-${ver}.tar.gz"
    tarball_path="$TARBALL_DIR/$tarball"

    # Salto se in skip-list.
    skip=0
    for skip_tar in "${SKIP_TARBALLS[@]}"; do
        [[ "$tarball" == "$skip_tar" ]] && { skip=1; break; }
    done
    if [[ $skip -eq 1 ]]; then
        warn "salto $tarball (già committato come tag esistente)"
        continue
    fi

    if [[ ! -f "$tarball_path" ]]; then
        warn "tarball mancante: $tarball — salto"
        continue
    fi

    # Già estratto da v4.3.0 sopra? Skippo nuova estrazione.
    extract_dir="$WORK_DIR/wgflow-${ver}"
    if [[ ! -d "$extract_dir" ]]; then
        tar -xzf "$tarball_path" -C "$WORK_DIR"
    fi
    [[ -d "$extract_dir" ]] || fail "estrazione fallita per $tarball (mi aspettavo $extract_dir)"

    AVAILABLE_RELEASES["$ver"]="$extract_dir"
    say "  $ver → $extract_dir"
done

# ---------------------------------------------------------------------------
# Parser data dal CHANGELOG
# ---------------------------------------------------------------------------

# Cerca la riga "## [X.Y.Z] — YYYY-MM-DD" e ritorna YYYY-MM-DD.
# Per v4.0-alpha cerca v4.0.0-alpha (formato CHANGELOG).
date_for_version() {
    local ver="$1"  # es. v4.2.6, v4.0-alpha
    # Strip leading v.
    local ver_num="${ver#v}"
    # Mapping speciale: v4.0-alpha nel filename → 4.0.0-alpha nel CHANGELOG.
    case "$ver_num" in
        4.0-alpha) ver_num="4.0.0-alpha" ;;
    esac

    # Cerca la riga e estrae la data. Tollerante a spazi.
    local date_str
    date_str=$(grep -E "^## \[${ver_num}\] — [0-9]{4}-[0-9]{2}-[0-9]{2}" "$CHANGELOG_PATH" \
               | head -1 \
               | sed -E 's/^## \[[^]]+\] — ([0-9-]+).*/\1/')

    if [[ -z "$date_str" ]]; then
        warn "data non trovata nel CHANGELOG per $ver_num — uso data corrente"
        date_str=$(date +%Y-%m-%d)
    fi

    printf '%s' "$date_str"
}

# Estrae le righe del CHANGELOG tra "## [X.Y.Z]" e la successiva "## [".
# Per il messaggio di commit. Limitato a 50 righe per non strapazzarsi.
notes_for_version() {
    local ver="$1"
    local ver_num="${ver#v}"
    case "$ver_num" in
        4.0-alpha) ver_num="4.0.0-alpha" ;;
    esac

    awk -v ver="$ver_num" '
        $0 ~ "^## \\[" ver "\\] " { found=1; next }
        found && /^## \[/ { exit }
        found { print }
    ' "$CHANGELOG_PATH" | sed '/./,$!d' | head -50
}

# ---------------------------------------------------------------------------
# Snapshot del working tree dal tarball
# ---------------------------------------------------------------------------

# Sostituisce il contenuto del repo (escludendo .git/, .gitignore,
# release-tarballs/, tmp/) con quello della directory passata.
swap_working_tree() {
    local src_dir="$1"

    # 1. Rimuovi tutto nel repo TRANNE le cose protette.
    #    Uso find + -mindepth 1 per non cancellare il repo stesso.
    find "$REPO_DIR" \
        -mindepth 1 -maxdepth 1 \
        -not -name '.git' \
        -not -name '.gitignore' \
        -not -name 'release-tarballs' \
        -not -name 'tmp' \
        -exec rm -rf {} +

    # 2. Copia il contenuto del tarball nel repo. Usiamo find + cp
    #    invece di rsync così non aggiungiamo dipendenze. Il glob
    #    `src_dir/*` include i top-level files e dirs ma NON i
    #    file dotfile (es. .gitignore). Li gestiamo separatamente.
    local f
    for f in "$src_dir"/* "$src_dir"/.[!.]*; do
        # Glob non-matching produce literal "$src_dir/.[!.]*" — skippa.
        [[ -e "$f" ]] || continue
        local base
        base=$(basename "$f")
        # Salta le directory protette se per qualche motivo sono nel
        # tarball (non dovrebbero — siamo paranoici).
        case "$base" in
            .git|release-tarballs|tmp) continue ;;
        esac
        cp -a "$f" "$REPO_DIR/"
    done
}

# ---------------------------------------------------------------------------
# Loop principale: per ogni release, swap + commit + tag
# ---------------------------------------------------------------------------

hdr "Costruzione history"

COMMITS_MADE=()
TAGS_MADE=()

for ver in "${RELEASE_ORDER[@]}"; do
    extract_dir="${AVAILABLE_RELEASES[$ver]:-}"
    [[ -z "$extract_dir" ]] && continue   # tarball saltato sopra

    # Tag già esiste? (sicurezza extra — non sovrascriviamo niente.)
    if git rev-parse "refs/tags/$ver" >/dev/null 2>&1; then
        warn "tag $ver esiste già nel repo — salto"
        continue
    fi

    commit_date=$(date_for_version "$ver")
    commit_subject="release: $ver"
    commit_body=$(notes_for_version "$ver")

    say ""
    say "── $ver ($commit_date) ──"

    if [[ $DRY_RUN -eq 1 ]]; then
        printf "${C_CYAN}[dry-run]${C_RESET} swap_working_tree %s\n" "$extract_dir"
        printf "${C_CYAN}[dry-run]${C_RESET} git add -A\n"
        printf "${C_CYAN}[dry-run]${C_RESET} GIT_AUTHOR_DATE='%sT12:00:00' git commit -m '%s'\n" \
               "$commit_date" "$commit_subject"
        printf "${C_CYAN}[dry-run]${C_RESET} git tag -a %s -m '%s'\n" "$ver" "$commit_subject"
        continue
    fi

    # Swap nel working tree.
    swap_working_tree "$extract_dir"

    # Stage tutto. -A include anche cancellazioni e file binari.
    git add -A

    # Sanità: c'è davvero qualcosa da committare?
    if git diff --cached --quiet; then
        warn "$ver non produce diff rispetto al commit precedente — salto"
        continue
    fi

    # Commit con data backdatata. Sia author che committer date.
    # Mettiamo l'ora a mezzogiorno per evitare ambiguità di
    # ordinamento se due release sono nello stesso giorno (es. tutte
    # le 4.2.x sono datate 2026-05-05 nel CHANGELOG).
    # Per garantire ordine corretto, aggiungiamo offset incrementale
    # in ore basato sulla posizione in RELEASE_ORDER.
    pos=0
    for v in "${RELEASE_ORDER[@]}"; do
        [[ "$v" == "$ver" ]] && break
        pos=$((pos + 1))
    done
    hour=$(printf "%02d" $((10 + pos)))   # 10, 11, 12, 13, ...
    commit_timestamp="${commit_date}T${hour}:00:00"

    full_msg="$commit_subject

$commit_body"

    GIT_AUTHOR_DATE="$commit_timestamp" \
    GIT_COMMITTER_DATE="$commit_timestamp" \
    git commit -m "$full_msg" --quiet

    # Tag annotato. Stessa data del commit.
    GIT_COMMITTER_DATE="$commit_timestamp" \
    git tag -a "$ver" -m "Release $ver"

    sha=$(git rev-parse --short HEAD)
    ok "$ver → commit $sha (data $commit_date)"
    COMMITS_MADE+=("$sha $ver")
    TAGS_MADE+=("$ver")
done

# ---------------------------------------------------------------------------
# Riepilogo + conferma push
# ---------------------------------------------------------------------------

hdr "Riepilogo"

if [[ $DRY_RUN -eq 1 ]]; then
    say "dry-run completato — nessuna modifica fatta al repo"
    say "rilancia senza --dry-run per applicare"
    rm -rf "$WORK_DIR"
    exit 0
fi

say "commit creati:"
for entry in "${COMMITS_MADE[@]}"; do
    say "  $entry"
done

say ""
say "tag creati:"
for t in "${TAGS_MADE[@]}"; do
    say "  $t"
done

echo
git log --oneline --decorate -20

# ---------------------------------------------------------------------------
# Push
# ---------------------------------------------------------------------------

if [[ $SKIP_PUSH -eq 1 ]]; then
    say ""
    warn "--no-push: salto il push, history applicata solo localmente"
    say "quando sei pronto:"
    say "  cd $REPO_DIR"
    say "  git push origin $EXPECTED_BRANCH"
    say "  git push origin ${TAGS_MADE[*]}"
    rm -rf "$WORK_DIR"
    exit 0
fi

echo
echo "${C_BOLD}Push su origin?${C_RESET}"
echo "  ${C_DIM}git push origin $EXPECTED_BRANCH${C_RESET}"
echo "  ${C_DIM}git push origin ${TAGS_MADE[*]}${C_RESET}"
echo
read -r -p "procedo? [y/N]: " reply
case "$reply" in
    y|Y|yes|YES)
        say "push main..."
        git push origin "$EXPECTED_BRANCH"
        ok "main pushato"

        say "push tag..."
        git push origin "${TAGS_MADE[@]}"
        ok "tag pushati"
        ;;
    *)
        warn "push saltato dall'utente"
        say "per pushare manualmente:"
        say "  cd $REPO_DIR"
        say "  git push origin $EXPECTED_BRANCH"
        say "  git push origin ${TAGS_MADE[*]}"
        ;;
esac

# Cleanup
rm -rf "$WORK_DIR"

hdr "Fatto"

say "backup repo: $BACKUP_PATH (rimuovilo quando sei sicuro)"
say "ripristino: rm -rf $REPO_DIR && tar -xzf $BACKUP_PATH -C $(dirname "$REPO_DIR")"
