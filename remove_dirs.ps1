# PowerShell script to remove empty or unnecessary directories
# Execute with: .\remove_dirs.ps1

Write-Host "Ransomware Directory Cleanup" -ForegroundColor Green
Write-Host "============================" -ForegroundColor Green
Write-Host ""

# List current directories
Write-Host "Current directories:" -ForegroundColor Cyan
Get-ChildItem -Directory | ForEach-Object { Write-Host "  - $($_.Name)" }
Write-Host ""

# Essential directories that should be kept
$essentialDirs = @("test_files", "rules")

# Directories we want to remove
$dirsToRemove = @("assets")

# Find empty directories
$emptyDirs = Get-ChildItem -Directory | Where-Object { 
    (Get-ChildItem -Path $_.FullName -Recurse -File).Count -eq 0 -and 
    $essentialDirs -notcontains $_.Name
} | Select-Object -ExpandProperty Name

Write-Host "Empty directories found:" -ForegroundColor Yellow
if ($emptyDirs.Count -eq 0) {
    Write-Host "  None"
} else {
    $emptyDirs | ForEach-Object { Write-Host "  - $_" }
}
Write-Host ""

# Remove empty directories
Write-Host "Removing empty directories:" -ForegroundColor Yellow
foreach ($dir in $emptyDirs) {
    try {
        Remove-Item -Path $dir -Recurse -Force
        Write-Host "  - Removed empty directory: $dir" -ForegroundColor Green
    } catch {
        Write-Host "  - Failed to remove directory: $dir - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Remove specific directories
Write-Host "Removing specified directories:" -ForegroundColor Yellow
foreach ($dir in $dirsToRemove) {
    if (Test-Path $dir) {
        try {
            Remove-Item -Path $dir -Recurse -Force
            Write-Host "  - Removed directory: $dir" -ForegroundColor Green
        } catch {
            Write-Host "  - Failed to remove directory: $dir - $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "  - Directory does not exist: $dir" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "Final directory structure:" -ForegroundColor Cyan
Get-ChildItem -Directory | ForEach-Object { Write-Host "  - $($_.Name)" }
Write-Host ""
Write-Host "Directory cleanup complete!" -ForegroundColor Green 