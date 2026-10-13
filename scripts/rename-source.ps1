# Run from the repository root AFTER stopping services, terminals and editors
# using the application directory. Preview is the default; -Apply performs it.
param(
    [switch]$Apply,
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\', '/')
$source = [IO.Path]::GetFullPath((Join-Path $repo 'WinSecAgent'))
$target = [IO.Path]::GetFullPath((Join-Path $repo 'Microlnsight'))
foreach ($path in @($source, $target)) {
    if (-not $path.StartsWith($repo + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Directory is outside the repository.'
    }
}
if ((Test-Path -LiteralPath $target) -and -not (Test-Path -LiteralPath $source)) {
    Write-Output 'Application directory is already Microlnsight. No changes made.'
    return
}
if (-not (Test-Path -LiteralPath $source -PathType Container)) { throw 'Source directory is missing.' }
if (Test-Path -LiteralPath $target) { throw 'Both directories exist; refusing to merge or overwrite.' }
if ((Get-Item -LiteralPath $source -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'Source is a link or junction; refusing to move it.'
}
if (Test-Path -LiteralPath (Join-Path $source '.git')) { throw 'Source contains a separate Git repository.' }

$names = @('README.md', 'CONTRIBUTING.md', '.gitignore',
    '.github/workflows/ci.yml', '.github/workflows/cli-release.yml', 'WinSecAgent/README.md')
$docs = Join-Path $repo 'docs'
if (Test-Path -LiteralPath $docs) {
    $names += Get-ChildItem -LiteralPath $docs -Filter '*.md' -Recurse -File |
        Where-Object { $_.FullName -notlike '*\archive\*' -and $_.Name -ne 'brand-migration.md' } |
        ForEach-Object { $_.FullName.Substring($repo.Length + 1) }
}
$encoding = New-Object System.Text.UTF8Encoding($false)
$changes = @()
foreach ($name in $names) {
    $path = [IO.Path]::GetFullPath((Join-Path $repo $name))
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    $bytes = [IO.File]::ReadAllBytes($path)
    $text = [IO.File]::ReadAllText($path)
    # Keep historical migration tables verbatim; update active references.
    $updated = ($text -split "`n" | ForEach-Object {
        if ($_ -match '^\| `WinSecAgent/(docs/|README\.md` 的完整指南)') { $_ }
        else { $_.Replace('WinSecAgent', 'Microlnsight') }
    }) -join "`n"
    if ($updated -ne $text) {
        $after = $path
        if ($path.StartsWith($source + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            $after = $target + $path.Substring($source.Length)
        }
        $changes += [pscustomobject]@{ Name = $name; Before = $path; After = $after; Bytes = $bytes; Text = $updated }
    }
}
Write-Output "Rename: $source -> $target"
Write-Output "Reference files to update: $($changes.Count)"
if (-not $Apply) { Write-Output 'Preview only. Stop old processes, then run again with -Apply.'; return }

$backup = Join-Path $repo ('outputs/source-rename-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $backup | Out-Null
foreach ($change in $changes) {
    $saved = Join-Path $backup $change.Name
    New-Item -ItemType Directory -Path (Split-Path -Parent $saved) -Force | Out-Null
    [IO.File]::WriteAllBytes($saved, $change.Bytes)
}
$moved = $false
try {
    Move-Item -LiteralPath $source -Destination $target
    $moved = $true
    foreach ($change in $changes) { [IO.File]::WriteAllText($change.After, $change.Text, $encoding) }
} catch {
    $failure = $_
    if ($moved) {
        foreach ($change in $changes) { [IO.File]::WriteAllBytes($change.After, $change.Bytes) }
        Move-Item -LiteralPath $target -Destination $source
    }
    throw "Rename did not complete. Reference backup: $backup. $failure"
}
Write-Output "Done. Original reference files: $backup"
Write-Output 'Recreate virtual environments if their launchers contain old absolute paths. Restart using Microlnsight/.'
