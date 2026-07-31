# CHIMERA QUICK FIX
# Run inside C:\Cyber\chimera

# 1. Create missing plugins directory
New-Item -ItemType Directory -Path "chimera\plugins" -Force | Out-Null
"" | Set-Content "chimera\plugins\__init__.py" -Encoding utf8
@"# Chimera Plugins

## How to Extend

Drop a Python module here or install as a separate package with entry points.

## Plugin Types

| Type | Interface |
|------|-----------|
| Parser | `chimera.parsers.base.BaseParser` |
| Analyzer | `chimera.analysis.base.BaseAnalyzer` |
| Bridge | `chimera.execution.base.ExecutionAdapter` |
| Reporter | `chimera.reports.base.BaseReporter` |

## Rules
1. Lazy-load heavy dependencies
2. Return Pydantic models
3. Handle your own exceptions
"@ | Set-Content "chimera\plugins\README.md" -Encoding utf8

# 2. Remove fix.ps1 from repo and disk
git rm --cached fix.ps1 | Out-Null
Remove-Item fix.ps1 -Force

# 3. Commit plugins, remove fix.ps1
git add -A
git commit -m "fix: add missing plugins directory, remove fix script"

# 4. Push (retry until network is back)
Write-Host "[*] Pushing to GitHub..." -ForegroundColor Cyan
git push origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Push successful." -ForegroundColor Green
} else {
    Write-Host "[!] Push failed — network issue. Retry later with: git push origin main" -ForegroundColor Yellow
}

Write-Host "`nCurrent structure:" -ForegroundColor Cyan
tree /F chimera