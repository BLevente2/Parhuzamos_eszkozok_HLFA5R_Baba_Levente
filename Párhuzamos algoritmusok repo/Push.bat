@echo off
REM ---------------------------------------------------------
REM Push.bat – belép a baba repo-ba, commit+push
REM Megoldja a dubious ownership hibát is
REM ---------------------------------------------------------

REM 0. Biztonságossá tesszük a repót (ha még nem lenne)
git config --global --add safe.directory "F:/Automatak/baba"

REM 1. Lépjünk a script könyvtárába
cd /d "%~dp0"

REM 2. Hol van a repo?
set "REPO_DIR=baba"
if not exist "%REPO_DIR%\.git" (
  echo Hiba: nem találom a repo-t a %REPO_DIR% mappában!
  echo Előbb futtasd a Pull.bat-ot, vagy klónozd le a repót!
  pause
  exit /b
)

REM 3. Lépjünk be a repo könyvtárába
cd "%REPO_DIR%"

REM 4. (Opcionális) Győződjünk meg róla, hogy jó az origin URL
git remote set-url origin https://dev.azure.com/parallel2025A/_git/baba

REM 5. Üzenet bekérése
setlocal enabledelayedexpansion
set /p commitMessage=Commit üzenet: 
if "!commitMessage!"=="" (
    echo Hiba: Nem adtál meg commit üzenetet!
    pause
    exit /b
)

echo Commit üzenet: !commitMessage!

REM 6. Minden változás staged
git add -A

REM 7. Commit
git commit -m "!commitMessage!"
if errorlevel 1 (
    echo Nincs új commitolható változás, kilépés.
    pause
    exit /b
)

REM 8. Váltsunk a megfelelő ágra (main vagy master)
git checkout main 2>nul || git checkout master 2>nul
if errorlevel 1 (
    echo Hiba: sem main, sem master ág nem található!
    pause
    exit /b
)

REM 9. Push az aktuális ágra
git push origin HEAD
if errorlevel 1 (
    echo Hiba a push során!
    pause
    exit /b
)

echo Push sikeres.
pause
