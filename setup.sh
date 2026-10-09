#!/usr/bin/env bash
#
# Turn this template into your own project.
#
# Asks for a project name (plus author, repository and a few other details),
# then renames the `app` and `app-core` crates everywhere they appear and
# rewrites the template's own metadata.
#
# The replacements are deliberately surgical rather than a blanket
# find-and-replace: `app` is also the name of a *module* (`mod app;`,
# `crate::app::Mode`, `src/app.rs`) and of the `App` struct, and those must
# survive untouched. Only the package identity is renamed.
#
# Run it once, from the repository root, then delete it.
#
# Examples:
#   ./setup.sh
#   ./setup.sh --name my-tui --author 'Ada Lovelace' --yes

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: setup.sh [options]

  --name NAME            Cargo package name for the binary crate, e.g. my-tui
  --core-name NAME       Library crate name (default: <name>-core)
  --description TEXT     Short description
  --author NAME          Author name
  --email EMAIL          Author email
  --repository URL       Repository URL
  --qualifier Q          ProjectDirs qualifier (com / io / dev ...)
  --organization ORG     ProjectDirs organization
  -y, --yes              Accept every default without prompting
  -n, --dry-run          Report what would change without writing anything
  -h, --help             Show this help
EOF
}

Name='' CoreName='' Description='' Author='' Email='' Repository=''
Qualifier='' Organization='' Yes=0 DryRun=0

while (($#)); do
    opt=$1
    # Accept both `--name value` and `--name=value`.
    if [[ $opt == --*=* ]]; then
        set -- "${opt%%=*}" "${opt#*=}" "${@:2}"
        opt=$1
    fi
    case $opt in
        -y | --yes) Yes=1 ;;
        -n | --dry-run) DryRun=1 ;;
        -h | --help) usage; exit 0 ;;
        --name | --core-name | --description | --author | --email | --repository | --qualifier | --organization)
            (($# >= 2)) || { echo "error: $opt needs a value" >&2; exit 2; }
            case $opt in
                --name) Name=$2 ;;
                --core-name) CoreName=$2 ;;
                --description) Description=$2 ;;
                --author) Author=$2 ;;
                --email) Email=$2 ;;
                --repository) Repository=$2 ;;
                --qualifier) Qualifier=$2 ;;
                --organization) Organization=$2 ;;
            esac
            shift
            ;;
        *) echo "error: unknown option '$opt'" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

Root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
Changed=()

# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------

if [[ -t 1 ]]; then
    C_HEAD=$'\e[36m' C_STEP=$'\e[90m' C_NOTE=$'\e[33m' C_OK=$'\e[32m' C_ERR=$'\e[31m' C_OFF=$'\e[0m'
else
    C_HEAD='' C_STEP='' C_NOTE='' C_OK='' C_ERR='' C_OFF=''
fi

write_head() { printf '\n%s%s%s\n' "$C_HEAD" "$1" "$C_OFF"; }
write_step() { printf '  %s%s%s\n' "$C_STEP" "$1" "$C_OFF"; }
write_note() { printf '  %s%s%s\n' "$C_NOTE" "$1" "$C_OFF"; }
die() { printf '%serror: %s%s\n' "$C_ERR" "$1" "$C_OFF" >&2; exit 1; }

trim() {
    local s=$1
    s=${s#"${s%%[![:space:]]*}"}
    s=${s%"${s##*[![:space:]]}"}
    printf '%s' "$s"
}

# --------------------------------------------------------------------------
# Prompting
# --------------------------------------------------------------------------

# read_answer VAR QUESTION DEFAULT VALIDATOR PRESET
# VALIDATOR is a function name (or '') that prints a problem, or nothing.
read_answer() {
    local var=$1 question=$2 default=$3 validate=$4 preset=$5
    local answer problem

    # A value passed on the command line skips the prompt but not validation.
    if [[ -n $preset ]]; then
        if [[ -n $validate ]]; then
            problem=$("$validate" "$preset")
            [[ -z $problem ]] || die "$question : $problem"
        fi
        printf -v "$var" '%s' "$preset"
        return
    fi

    while true; do
        if ((Yes)); then
            answer=$default
        else
            local suffix=''
            [[ -n $default ]] && suffix=" [$default]"
            read -r -p "$question$suffix: " answer || die 'input closed.'
            [[ -n $(trim "$answer") ]] || answer=$default
        fi

        answer=$(trim "$answer")
        if [[ -z $answer ]]; then
            ((Yes)) && die "$question : a value is required."
            write_note 'A value is required.'
            continue
        fi

        if [[ -n $validate ]]; then
            problem=$("$validate" "$answer")
            if [[ -n $problem ]]; then
                ((Yes)) && die "$question : $problem"
                write_note "$problem"
                continue
            fi
        fi
        printf -v "$var" '%s' "$answer"
        return
    done
}

# read_confirmation QUESTION DEFAULT(1|0) — exit status is the answer.
read_confirmation() {
    local question=$1 default=$2 hint answer
    if ((Yes)); then return $((1 - default)); fi
    if ((default)); then hint='[Y/n]'; else hint='[y/N]'; fi
    while true; do
        read -r -p "$question $hint " answer || die 'input closed.'
        answer=$(trim "${answer,,}")
        case $answer in
            '') return $((1 - default)) ;;
            y | yes) return 0 ;;
            n | no) return 1 ;;
            *) write_note 'Answer y or n.' ;;
        esac
    done
}

# Cargo package names allow letters, digits, '-' and '_'. Once snake_cased into
# a crate path the name also has to be a legal Rust identifier, so screen for
# the keywords and built-in crate names that would collide.
validate_crate_name() {
    local value=$1
    if [[ ! $value =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]]; then
        echo "Start with a letter and use only letters, digits, '-' or '_'."
        return
    fi
    if [[ $value != "${value,,}" ]]; then
        echo 'Cargo package names are lowercase by convention.'
        return
    fi
    local snake=${value//-/_} word
    for word in crate self super extern move match loop type ref box fn mod \
        use impl dyn std core alloc test proc_macro; do
        if [[ $snake == "$word" ]]; then
            echo "'$value' collides with a Rust keyword or built-in crate."
            return
        fi
    done
}

# --------------------------------------------------------------------------
# File editing
#
# Every edit anchors on the template's exact text, so a missing match is a
# loud warning instead of a silent no-op if the template has drifted.
#
# Usage: begin_file PATH; replace FIND REPL; ...; end_file
# The whole file is held in TEXT verbatim, so the existing line endings, which
# differ file by file in this checkout, survive untouched.
# --------------------------------------------------------------------------

CUR_REL='' CUR_FULL='' CUR_SKIP=0 TEXT='' ORIGINAL=''

begin_file() {
    CUR_REL=$1
    CUR_FULL=$Root/$1
    CUR_SKIP=0
    if [[ ! -f $CUR_FULL ]]; then
        write_note "skipped $CUR_REL (not found)"
        CUR_SKIP=1
        return
    fi
    # The trailing sentinel stops $(...) from eating final newlines.
    TEXT=$(cat -- "$CUR_FULL"; printf x)
    TEXT=${TEXT%x}
    ORIGINAL=$TEXT
}

# replace FIND REPLACE [optional]
replace() {
    ((CUR_SKIP)) && return
    local find=$1 repl=$2 optional=${3:-}
    # A no-op replacement (the user kept the name `app`) is not a miss.
    [[ $find == "$repl" ]] && return
    if [[ $TEXT != *"$find"* ]]; then
        [[ -n $optional ]] || write_note "$CUR_REL : no match for '$find'"
        return
    fi
    # Both sides quoted: matched literally, and `&` in the replacement is not
    # expanded (bash 5.2 patsub_replacement).
    TEXT=${TEXT//"$find"/"$repl"}
}

end_file() {
    ((CUR_SKIP)) && return
    [[ $TEXT == "$ORIGINAL" ]] && return
    ((DryRun)) || printf '%s' "$TEXT" >"$CUR_FULL"
    Changed+=("$CUR_REL")
    write_step "edited $CUR_REL"
}

# Line-wise helpers for the edits that need a pattern. Each line keeps its own
# trailing '\r', if any, so CRLF files stay CRLF.
LINES=() TRAIL=''
split_lines() {
    local t=$TEXT
    TRAIL=''
    if [[ $t == *$'\n' ]]; then TRAIL=$'\n'; t=${t%$'\n'}; fi
    LINES=()
    [[ -z $t ]] || mapfile -t LINES <<<"$t"
}
join_lines() {
    local IFS=$'\n'
    TEXT="${LINES[*]}$TRAIL"
}

move_crate_directory() {
    local from=$1 to=$2
    [[ $from == "$to" ]] && return
    local src=$Root/$from dst=$Root/$to

    if [[ ! -d $src ]]; then
        write_note "skipped $from (not found)"
        return
    fi
    [[ ! -e $dst ]] || die "Cannot rename $from -> $to : the destination already exists."
    if ((DryRun)); then write_step "would rename $from -> $to"; return; fi

    mv -- "$src" "$dst"
    Changed+=("$from -> $to")
    write_step "renamed $from -> $to"
}

# --------------------------------------------------------------------------
# Questions
# --------------------------------------------------------------------------

[[ -f $Root/crates/app/Cargo.toml ]] ||
    die "crates/app/Cargo.toml not found under '$Root'. Either setup has already run, or this is not the template root."

printf '\n%srust-tui-template setup%s\n' "$C_OK" "$C_OFF"
printf '%sPress Enter to accept the value in brackets.%s\n' "$C_STEP" "$C_OFF"

defaultName=$(basename -- "$Root")
defaultName=${defaultName,,}
defaultName=${defaultName//[^a-z0-9_-]/-}
[[ -z $(validate_crate_name "$defaultName") ]] || defaultName='my-tui'

write_head 'Project'
read_answer projectName 'Project (binary crate) name' "$defaultName" validate_crate_name "$Name"
read_answer coreCrate 'Library (domain) crate name' "$projectName-core" validate_crate_name "$CoreName"
read_answer summary 'Short description' 'A terminal user interface built with ratatui' '' "$Description"

# `repository` is read at compile time by errors.rs for the panic message, so
# it has to point somewhere real.
write_head 'Metadata'
read_answer authorName 'Author name' 'Your Name' '' "$Author"
read_answer authorMail 'Author email' 'you@example.com' '' "$Email"
read_answer repoUrl 'Repository URL' "https://github.com/your-username/$projectName" '' "$Repository"

# `directories::ProjectDirs::from(qualifier, organization, application)` decides
# where per-user config and data land on each platform.
write_head 'Per-user config and data directories'
repoTail=${repoUrl%/}
repoTail=${repoTail%.git}
if [[ $repoTail =~ [:/]([^/:]+/[^/]+)$ ]]; then
    ownerRepo=${BASH_REMATCH[1]}
else
    ownerRepo="your-username/$projectName"
fi
defaultOrg=${ownerRepo%%/*}
read_answer appQualifier 'Qualifier (reverse-domain, e.g. com / io / dev)' 'com' '' "$Qualifier"
read_answer appOrganization 'Organization' "$defaultOrg" '' "$Organization"

# Derived spellings. All four have to agree: Cargo package name, Rust crate
# path, environment variable prefix and on-disk directory.
coreSnake=${coreCrate//-/_}
envPrefix=${projectName//-/_}
envPrefix=${envPrefix^^}

write_head 'Summary'
row() { printf '  %-18s %s\n' "$1" "$2"; }
row 'binary crate' "app -> $projectName"
row 'library crate' "app-core -> $coreCrate"
row 'rust crate path' "app_core -> $coreSnake"
row 'env var prefix' "APP_ -> ${envPrefix}_"
row 'log file' "$projectName.log"
row 'description' "$summary"
row 'author' "$authorName <$authorMail>"
row 'repository' "$repoUrl"
row 'project dirs' "$appQualifier / $appOrganization / $projectName"
((DryRun)) && write_note '(dry run - nothing will be written)'

if ! read_confirmation 'Apply these changes?' 1; then
    write_note 'Aborted. Nothing was changed.'
    exit 1
fi

# --------------------------------------------------------------------------
# Apply
# --------------------------------------------------------------------------

write_head 'Applying'

authorLine="$authorName <$authorMail>"
year=$(date +%Y)

begin_file 'Cargo.toml'
replace 'app-core = { path = "crates/app-core" }' "$coreCrate = { path = \"crates/$coreCrate\" }"
replace 'authors = ["qviperh <olteanromeodavid34@gmail.com>"]' "authors = [\"$authorLine\"]"
replace 'repository = "https://github.com/qviperh/rust-tui-template"' "repository = \"$repoUrl\""
end_file

begin_file 'crates/app/Cargo.toml'
replace 'name = "app"' "name = \"$projectName\""
replace 'description = "A terminal user interface built with ratatui"' "description = \"$summary\""
replace 'app-core = { workspace = true }' "$coreCrate = { workspace = true }"
end_file

begin_file 'crates/app-core/Cargo.toml'
replace 'name = "app-core"' "name = \"$coreCrate\""
replace 'description = "Domain logic for the app, independent of any user interface"' \
    "description = \"Domain logic for $projectName, independent of any user interface\""
end_file

# `use app_core::Core;` is the only place Rust code names the library crate,
# and it uses the snake_cased spelling.
begin_file 'crates/app/src/app.rs'
replace 'use app_core::Core;' "use ${coreSnake}::Core;"
replace 'owned by the `app-core` crate' "owned by the \`$coreCrate\` crate" optional
end_file

begin_file 'crates/app/src/main.rs'
replace '`app-core` crate' "\`$coreCrate\` crate" optional
end_file

begin_file 'crates/app-core/src/lib.rs'
replace 'The `app` crate owns rendering' "The \`$projectName\` crate owns rendering" optional
replace 'The `app` crate converts these' "The \`$projectName\` crate converts these" optional
replace 'the `app` -> `app-core` seam' "the \`$projectName\` -> \`$coreCrate\` seam" optional
end_file

begin_file 'crates/app/src/config.rs'
replace 'const APP_QUALIFIER: &str = "com";' "const APP_QUALIFIER: &str = \"$appQualifier\";"
replace 'const APP_ORGANIZATION: &str = "example";' "const APP_ORGANIZATION: &str = \"$appOrganization\";"
end_file

begin_file 'crates/app/src/components/home.rs'
replace '.title(" app ")' ".title(\" $projectName \")"
end_file

# This prefix must match `config::PROJECT_NAME` (CARGO_CRATE_NAME upper-cased)
# or direnv silently stops redirecting config, data and logs into the repo.
begin_file '.envrc'
replace 'APP_CONFIG' "${envPrefix}_CONFIG"
replace 'APP_DATA' "${envPrefix}_DATA"
replace 'APP_LOG_LEVEL' "${envPrefix}_LOG_LEVEL"
replace 'the `app` crate' "the \`$projectName\` crate" optional
end_file

begin_file '.github/workflows/cd.yml'
replace 'BINARY_NAME: app' "BINARY_NAME: $projectName"
replace 'the `app` crate' "the \`$projectName\` crate" optional
end_file

begin_file 'LICENSE'
if ((!CUR_SKIP)); then
    split_lines
    copyright_re='^Copyright \(c\) [0-9]{4}'
    found=0
    for i in "${!LINES[@]}"; do
        line=${LINES[i]} cr=''
        [[ $line == *$'\r' ]] && cr=$'\r'
        if [[ $line =~ $copyright_re ]]; then
            LINES[i]="Copyright (c) $year $authorLine$cr"
            found=1
        fi
    done
    join_lines
    ((found)) || write_note "LICENSE : no match for 'Copyright (c) <year>'"
fi
end_file

# Order matters: the tree pass needs the original column widths, so it runs
# before the prose pass below. Note there is no bare `app` replacement here -
# the README also mentions `app.rs` and `app::Mode`, which are the module.
begin_file 'README.md'
replace '# rust-tui-template' "# $projectName"
replace 'qviperh/rust-tui-template' "$ownerRepo"
if ((!CUR_SKIP)); then
    split_lines

    # Keep the README's ASCII tree aligned after the crate names change length.
    tree_re='^  (app-core|app)/( *)'
    for i in "${!LINES[@]}"; do
        line=${LINES[i]}
        [[ $line =~ $tree_re ]] || continue
        old=${BASH_REMATCH[1]} pad=${BASH_REMATCH[2]}
        if [[ $old == app ]]; then new=$projectName; else new=$coreCrate; fi
        width=$((${#old} + ${#pad} - ${#new}))
        ((width >= 1)) || width=1
        printf -v newPad '%*s' "$width" ''
        LINES[i]="  $new/$newPad${line:${#BASH_REMATCH[0]}}"
    done

    # The "Using the template" checklist is exactly what this script just did.
    # Drop it up to (not including) the next `## ` heading.
    start=-1 stop=-1
    for i in "${!LINES[@]}"; do
        line=${LINES[i]%$'\r'}
        if ((start < 0)); then
            [[ $line == '## Using the template' ]] && start=$i
        elif [[ $line == '## '* ]]; then
            stop=$i
            break
        fi
    done
    if ((start >= 0 && stop >= 0)); then
        LINES=("${LINES[@]:0:start}" "${LINES[@]:stop}")
    else
        write_note "README.md : no match for '## Using the template' section"
    fi

    join_lines
fi
replace 'app-core' "$coreCrate"
replace '-p app' "-p $projectName"
replace 'app.log' "$projectName.log"
replace 'APP_CONFIG' "${envPrefix}_CONFIG"
replace 'APP_DATA' "${envPrefix}_DATA"
replace 'APP_LOG_LEVEL' "${envPrefix}_LOG_LEVEL"
end_file

move_crate_directory 'crates/app-core' "crates/$coreCrate"
move_crate_directory 'crates/app' "crates/$projectName"

# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

write_head 'Done'
if ((${#Changed[@]} == 0)); then
    write_note 'Nothing changed.'
else
    printf '  %s%d path(s) updated.%s\n' "$C_OK" "${#Changed[@]}" "$C_OFF"
fi

if ((DryRun)); then
    write_note 'Dry run - re-run without --dry-run to apply.'
    exit 0
fi

# Cargo.lock still lists the old package names, and CI builds with `--locked`.
if command -v cargo >/dev/null 2>&1; then
    if read_confirmation 'Run `cargo check --workspace` now to refresh Cargo.lock?' 1; then
        write_head 'cargo check'
        cargo check --workspace --manifest-path "$Root/Cargo.toml" ||
            write_note 'cargo check failed - see the output above.'
    fi
else
    write_note 'cargo not found on PATH; Cargo.lock still holds the old crate names.'
fi

write_head 'Next steps'
echo "  1. cargo check --workspace     # if you skipped it above - CI builds --locked"
echo "  2. Review LICENSE if you want something other than MIT."
echo "  3. Replace Core/Error in crates/$coreCrate/src/lib.rs with your model,"
echo "     then rewrite crates/$projectName/src/components/home.rs."
echo "  4. cargo run -p $projectName"

echo
if read_confirmation 'Delete setup.sh and setup.ps1 now that setup has run?' 0; then
    rm -f -- "$Root/setup.sh" "$Root/setup.ps1"
    write_step 'removed setup.sh and setup.ps1'
fi
