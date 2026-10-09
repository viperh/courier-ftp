#Requires -Version 5.1

<#
.SYNOPSIS
    Turn this template into your own project.

.DESCRIPTION
    Asks for a project name (plus author, repository and a few other details),
    then renames the `app` and `app-core` crates everywhere they appear and
    rewrites the template's own metadata.

    The replacements are deliberately surgical rather than a blanket
    find-and-replace: `app` is also the name of a *module* (`mod app;`,
    `crate::app::Mode`, `src/app.rs`) and of the `App` struct, and those must
    survive untouched. Only the package identity is renamed.

    Run it once, from the repository root, then delete it.

.PARAMETER Name
    Cargo package name for the binary crate, e.g. `my-tui`. The library crate
    defaults to `<Name>-core`.

.PARAMETER Yes
    Accept every default without prompting.

.PARAMETER DryRun
    Report what would change without writing anything.

.EXAMPLE
    ./setup.ps1

.EXAMPLE
    ./setup.ps1 -Name my-tui -Author 'Ada Lovelace' -Yes
#>

[CmdletBinding()]
param(
    [string]$Name,
    [string]$CoreName,
    [string]$Description,
    [string]$Author,
    [string]$Email,
    [string]$Repository,
    [string]$Qualifier,
    [string]$Organization,
    [switch]$Yes,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$script:Changed = [System.Collections.Generic.List[string]]::new()

# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------

function Write-Head { param([string]$Text) Write-Host ''; Write-Host $Text -ForegroundColor Cyan }
function Write-Step { param([string]$Text) Write-Host "  $Text" -ForegroundColor DarkGray }
function Write-Note { param([string]$Text) Write-Host "  $Text" -ForegroundColor Yellow }

# --------------------------------------------------------------------------
# Prompting
# --------------------------------------------------------------------------

function Read-Answer {
    param(
        [Parameter(Mandatory)][string]$Question,
        [string]$Default = '',
        [scriptblock]$Validate,
        [string]$Preset
    )

    # A value passed on the command line skips the prompt but not validation.
    if ($Preset) {
        if ($Validate) {
            $problem = & $Validate $Preset
            if ($problem) { throw "$Question : $problem" }
        }
        return $Preset
    }

    while ($true) {
        if ($Yes) {
            $answer = $Default
        }
        else {
            $suffix = if ($Default) { " [$Default]" } else { '' }
            $answer = Read-Host "$Question$suffix"
            if ([string]::IsNullOrWhiteSpace($answer)) { $answer = $Default }
        }

        $answer = "$answer".Trim()
        if ([string]::IsNullOrWhiteSpace($answer)) {
            if ($Yes) { throw "$Question : a value is required." }
            Write-Note 'A value is required.'
            continue
        }

        if ($Validate) {
            $problem = & $Validate $answer
            if ($problem) {
                if ($Yes) { throw "$Question : $problem" }
                Write-Note $problem
                continue
            }
        }
        return $answer
    }
}

function Read-Confirmation {
    param([Parameter(Mandatory)][string]$Question, [bool]$Default = $true)

    if ($Yes) { return $Default }
    $hint = if ($Default) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $answer = "$(Read-Host "$Question $hint")".Trim().ToLowerInvariant()
        if (-not $answer) { return $Default }
        if ($answer -eq 'y' -or $answer -eq 'yes') { return $true }
        if ($answer -eq 'n' -or $answer -eq 'no') { return $false }
        Write-Note 'Answer y or n.'
    }
}

# Cargo package names allow letters, digits, '-' and '_'. Once snake_cased into
# a crate path the name also has to be a legal Rust identifier, so screen for
# the keywords and built-in crate names that would collide.
$ValidateCrateName = {
    param([string]$Value)

    if ($Value -notmatch '^[a-zA-Z][a-zA-Z0-9_-]*$') {
        return "Start with a letter and use only letters, digits, '-' or '_'."
    }
    if ($Value -cne $Value.ToLowerInvariant()) {
        return 'Cargo package names are lowercase by convention.'
    }
    $snake = $Value.Replace('-', '_')
    $reserved = @(
        'crate', 'self', 'super', 'extern', 'move', 'match', 'loop', 'type',
        'ref', 'box', 'fn', 'mod', 'use', 'impl', 'dyn', 'std', 'core',
        'alloc', 'test', 'proc_macro'
    )
    if ($reserved -ccontains $snake) {
        return "'$Value' collides with a Rust keyword or built-in crate."
    }
    return $null
}

# --------------------------------------------------------------------------
# File editing
#
# Every edit anchors on the template's exact text, so a missing match is a
# loud warning instead of a silent no-op if the template has drifted.
# --------------------------------------------------------------------------

function New-Edit {
    param(
        [Parameter(Mandatory)][string]$Find,
        [AllowEmptyString()][string]$Replace = '',
        [scriptblock]$Evaluator,
        [switch]$Regex,
        [switch]$Optional
    )
    [pscustomobject]@{
        Find      = $Find
        Replace   = $Replace
        Evaluator = $Evaluator
        Regex     = ([bool]$Regex -or ($null -ne $Evaluator))
        Optional  = [bool]$Optional
    }
}

# '$' is special on the right-hand side of [regex]::Replace, so user-supplied
# text spliced into a regex replacement has to double its dollar signs.
function ConvertTo-ReplacementText {
    param([AllowEmptyString()][string]$Text)
    return $Text.Replace('$', '$$$$')
}

function Update-ProjectFile {
    param([Parameter(Mandatory)][string]$RelPath, [Parameter(Mandatory)][object[]]$Edits)

    $full = Join-Path $Root $RelPath
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        Write-Note "skipped $RelPath (not found)"
        return
    }

    # Read and write the whole file as text so the existing line endings, which
    # differ file by file in this checkout, survive untouched.
    $original = [System.IO.File]::ReadAllText($full)
    $text = $original

    foreach ($edit in $Edits) {
        # A no-op replacement (the user kept the name `app`) is not a miss.
        if (-not $edit.Regex -and $edit.Find -ceq $edit.Replace) { continue }

        $pattern = if ($edit.Regex) { $edit.Find } else { [regex]::Escape($edit.Find) }
        if (-not [regex]::IsMatch($text, $pattern)) {
            if (-not $edit.Optional) { Write-Note "$RelPath : no match for '$($edit.Find)'" }
            continue
        }

        if ($edit.Evaluator) {
            $text = [regex]::Replace($text, $edit.Find, $edit.Evaluator)
        }
        elseif ($edit.Regex) {
            $text = [regex]::Replace($text, $edit.Find, $edit.Replace)
        }
        else {
            $text = $text.Replace($edit.Find, $edit.Replace)
        }
    }

    if ($text -ceq $original) { return }
    if (-not $DryRun) { [System.IO.File]::WriteAllText($full, $text, $Utf8NoBom) }
    $script:Changed.Add($RelPath)
    Write-Step "edited $RelPath"
}

function Move-CrateDirectory {
    param([Parameter(Mandatory)][string]$From, [Parameter(Mandatory)][string]$To)

    if ($From -ceq $To) { return }
    $src = Join-Path $Root $From
    $dst = Join-Path $Root $To

    if (-not (Test-Path -LiteralPath $src -PathType Container)) {
        Write-Note "skipped $From (not found)"
        return
    }
    if (Test-Path -LiteralPath $dst) {
        throw "Cannot rename $From -> $To : the destination already exists."
    }
    if ($DryRun) { Write-Step "would rename $From -> $To"; return }

    Rename-Item -LiteralPath $src -NewName (Split-Path $To -Leaf)
    $script:Changed.Add("$From -> $To")
    Write-Step "renamed $From -> $To"
}

# --------------------------------------------------------------------------
# Questions
# --------------------------------------------------------------------------

if (-not (Test-Path -LiteralPath (Join-Path $Root 'crates/app/Cargo.toml') -PathType Leaf)) {
    throw "crates/app/Cargo.toml not found under '$Root'. Either setup has already run, or this is not the template root."
}

Write-Host ''
Write-Host 'rust-tui-template setup' -ForegroundColor Green
Write-Host 'Press Enter to accept the value in brackets.' -ForegroundColor DarkGray

$defaultName = (Split-Path $Root -Leaf).ToLowerInvariant() -replace '[^a-z0-9_-]', '-'
if (& $ValidateCrateName $defaultName) { $defaultName = 'my-tui' }

Write-Head 'Project'
$projectName = Read-Answer -Question 'Project (binary crate) name' -Default $defaultName -Validate $ValidateCrateName -Preset $Name
$coreCrate = Read-Answer -Question 'Library (domain) crate name' -Default "$projectName-core" -Validate $ValidateCrateName -Preset $CoreName
$summary = Read-Answer -Question 'Short description' -Default 'A terminal user interface built with ratatui' -Preset $Description

# `repository` is read at compile time by errors.rs for the panic message, so
# it has to point somewhere real.
Write-Head 'Metadata'
$authorName = Read-Answer -Question 'Author name' -Default 'Your Name' -Preset $Author
$authorMail = Read-Answer -Question 'Author email' -Default 'you@example.com' -Preset $Email
$repoUrl = Read-Answer -Question 'Repository URL' -Default "https://github.com/your-username/$projectName" -Preset $Repository

# `directories::ProjectDirs::from(qualifier, organization, application)` decides
# where per-user config and data land on each platform.
Write-Head 'Per-user config and data directories'
$ownerRepo = if ($repoUrl -match '[:/]([^/:]+/[^/]+?)(\.git)?/?$') { $Matches[1] } else { "your-username/$projectName" }
$defaultOrg = ($ownerRepo -split '/')[0]
$appQualifier = Read-Answer -Question 'Qualifier (reverse-domain, e.g. com / io / dev)' -Default 'com' -Preset $Qualifier
$appOrganization = Read-Answer -Question 'Organization' -Default $defaultOrg -Preset $Organization

# Derived spellings. All four have to agree: Cargo package name, Rust crate
# path, environment variable prefix and on-disk directory.
$coreSnake = $coreCrate.Replace('-', '_')
$envPrefix = $projectName.Replace('-', '_').ToUpperInvariant()

Write-Head 'Summary'
Write-Host ("  {0,-18} {1}" -f 'binary crate', "app -> $projectName")
Write-Host ("  {0,-18} {1}" -f 'library crate', "app-core -> $coreCrate")
Write-Host ("  {0,-18} {1}" -f 'rust crate path', "app_core -> $coreSnake")
Write-Host ("  {0,-18} {1}" -f 'env var prefix', "APP_ -> ${envPrefix}_")
Write-Host ("  {0,-18} {1}" -f 'log file', "$projectName.log")
Write-Host ("  {0,-18} {1}" -f 'description', $summary)
Write-Host ("  {0,-18} {1}" -f 'author', "$authorName <$authorMail>")
Write-Host ("  {0,-18} {1}" -f 'repository', $repoUrl)
Write-Host ("  {0,-18} {1}" -f 'project dirs', "$appQualifier / $appOrganization / $projectName")
if ($DryRun) { Write-Note '(dry run - nothing will be written)' }

if (-not (Read-Confirmation -Question 'Apply these changes?' -Default $true)) {
    Write-Note 'Aborted. Nothing was changed.'
    exit 1
}

# --------------------------------------------------------------------------
# Apply
# --------------------------------------------------------------------------

Write-Head 'Applying'

$authorLine = "$authorName <$authorMail>"
$year = (Get-Date).Year

Update-ProjectFile 'Cargo.toml' @(
    (New-Edit -Find 'app-core = { path = "crates/app-core" }' -Replace "$coreCrate = { path = ""crates/$coreCrate"" }"),
    (New-Edit -Find 'authors = ["qviperh <olteanromeodavid34@gmail.com>"]' -Replace "authors = [""$authorLine""]"),
    (New-Edit -Find 'repository = "https://github.com/qviperh/rust-tui-template"' -Replace "repository = ""$repoUrl""")
)

Update-ProjectFile 'crates/app/Cargo.toml' @(
    (New-Edit -Find 'name = "app"' -Replace "name = ""$projectName"""),
    (New-Edit -Find 'description = "A terminal user interface built with ratatui"' -Replace "description = ""$summary"""),
    (New-Edit -Find 'app-core = { workspace = true }' -Replace "$coreCrate = { workspace = true }")
)

Update-ProjectFile 'crates/app-core/Cargo.toml' @(
    (New-Edit -Find 'name = "app-core"' -Replace "name = ""$coreCrate"""),
    (New-Edit -Find 'description = "Domain logic for the app, independent of any user interface"' -Replace "description = ""Domain logic for $projectName, independent of any user interface""")
)

# `use app_core::Core;` is the only place Rust code names the library crate,
# and it uses the snake_cased spelling.
Update-ProjectFile 'crates/app/src/app.rs' @(
    (New-Edit -Find 'use app_core::Core;' -Replace "use ${coreSnake}::Core;"),
    (New-Edit -Find 'owned by the `app-core` crate' -Replace "owned by the ``$coreCrate`` crate" -Optional)
)

Update-ProjectFile 'crates/app/src/main.rs' @(
    (New-Edit -Find '`app-core` crate' -Replace "``$coreCrate`` crate" -Optional)
)

Update-ProjectFile 'crates/app-core/src/lib.rs' @(
    (New-Edit -Find 'The `app` crate owns rendering' -Replace "The ``$projectName`` crate owns rendering" -Optional),
    (New-Edit -Find 'The `app` crate converts these' -Replace "The ``$projectName`` crate converts these" -Optional),
    (New-Edit -Find 'the `app` -> `app-core` seam' -Replace "the ``$projectName`` -> ``$coreCrate`` seam" -Optional)
)

Update-ProjectFile 'crates/app/src/config.rs' @(
    (New-Edit -Find 'const APP_QUALIFIER: &str = "com";' -Replace "const APP_QUALIFIER: &str = ""$appQualifier"";"),
    (New-Edit -Find 'const APP_ORGANIZATION: &str = "example";' -Replace "const APP_ORGANIZATION: &str = ""$appOrganization"";")
)

Update-ProjectFile 'crates/app/src/components/home.rs' @(
    (New-Edit -Find '.title(" app ")' -Replace ".title("" $projectName "")")
)

# This prefix must match `config::PROJECT_NAME` (CARGO_CRATE_NAME upper-cased)
# or direnv silently stops redirecting config, data and logs into the repo.
Update-ProjectFile '.envrc' @(
    (New-Edit -Find 'APP_CONFIG' -Replace "${envPrefix}_CONFIG"),
    (New-Edit -Find 'APP_DATA' -Replace "${envPrefix}_DATA"),
    (New-Edit -Find 'APP_LOG_LEVEL' -Replace "${envPrefix}_LOG_LEVEL"),
    (New-Edit -Find 'the `app` crate' -Replace "the ``$projectName`` crate" -Optional)
)

Update-ProjectFile '.github/workflows/cd.yml' @(
    (New-Edit -Find 'BINARY_NAME: app' -Replace "BINARY_NAME: $projectName"),
    (New-Edit -Find 'the `app` crate' -Replace "the ``$projectName`` crate" -Optional)
)

# `[^\r\n]*` rather than `.*`: `.` matches `\r`, which would silently convert
# this one line to LF in an otherwise CRLF file.
Update-ProjectFile 'LICENSE' @(
    (New-Edit -Regex -Find '(?m)^Copyright \(c\) \d{4}[^\r\n]*' -Replace ("Copyright (c) $year " + (ConvertTo-ReplacementText $authorLine)))
)

# Keep the README's ASCII tree aligned after the crate names change length.
$treeNames = @{ 'app' = $projectName; 'app-core' = $coreCrate }
$treeEvaluator = {
    param([System.Text.RegularExpressions.Match]$M)
    $old = $M.Groups[2].Value
    $new = $treeNames[$old]
    $pad = $M.Groups[3].Value
    $width = $old.Length + $pad.Length
    $newPad = ' ' * [Math]::Max(1, $width - $new.Length)
    "$($M.Groups[1].Value)$new/$newPad"
}

# Order matters: the tree pass needs the original column widths, so it runs
# before the prose pass below. Note there is no bare `app` replacement here -
# the README also mentions `app.rs` and `app::Mode`, which are the module.
Update-ProjectFile 'README.md' @(
    (New-Edit -Find '# rust-tui-template' -Replace "# $projectName"),
    (New-Edit -Find 'qviperh/rust-tui-template' -Replace $ownerRepo),
    (New-Edit -Find '(?m)^([ ]{2})(app-core|app)/([ ]*)' -Evaluator $treeEvaluator -Optional),
    (New-Edit -Find 'app-core' -Replace $coreCrate),
    (New-Edit -Find '-p app' -Replace "-p $projectName"),
    (New-Edit -Find 'app.log' -Replace "$projectName.log"),
    (New-Edit -Find 'APP_CONFIG' -Replace "${envPrefix}_CONFIG"),
    (New-Edit -Find 'APP_DATA' -Replace "${envPrefix}_DATA"),
    (New-Edit -Find 'APP_LOG_LEVEL' -Replace "${envPrefix}_LOG_LEVEL"),
    # The "Using the template" checklist is exactly what this script just did.
    (New-Edit -Regex -Find '(?ms)^## Using the template\r?\n.*?(?=^## )' -Replace '')
)

Move-CrateDirectory -From 'crates/app-core' -To "crates/$coreCrate"
Move-CrateDirectory -From 'crates/app' -To "crates/$projectName"

# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

Write-Head 'Done'
if ($script:Changed.Count -eq 0) {
    Write-Note 'Nothing changed.'
}
else {
    Write-Host "  $($script:Changed.Count) path(s) updated." -ForegroundColor Green
}

if ($DryRun) {
    Write-Note 'Dry run - re-run without -DryRun to apply.'
    exit 0
}

# Cargo.lock still lists the old package names, and CI builds with `--locked`.
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if ($cargo -and (Read-Confirmation -Question 'Run `cargo check --workspace` now to refresh Cargo.lock?' -Default $true)) {
    Write-Head 'cargo check'
    & cargo check --workspace --manifest-path (Join-Path $Root 'Cargo.toml')
    if ($LASTEXITCODE -ne 0) { Write-Note 'cargo check failed - see the output above.' }
}
elseif (-not $cargo) {
    Write-Note 'cargo not found on PATH; Cargo.lock still holds the old crate names.'
}

Write-Head 'Next steps'
Write-Host "  1. cargo check --workspace     # if you skipped it above - CI builds --locked"
Write-Host "  2. Review LICENSE if you want something other than MIT."
Write-Host "  3. Replace Core/Error in crates/$coreCrate/src/lib.rs with your model,"
Write-Host "     then rewrite crates/$projectName/src/components/home.rs."
Write-Host "  4. cargo run -p $projectName"

Write-Host ''
if (Read-Confirmation -Question 'Delete setup.ps1 now that it has run?' -Default $false) {
    Remove-Item -LiteralPath (Join-Path $Root 'setup.ps1') -Force
    Write-Step 'removed setup.ps1'
}
