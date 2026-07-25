@echo off
echo ========================================
echo  Sync + Docker Rebuild + Git Push
echo ========================================

echo.
echo [1/4] Copie des fichiers vers D:\PhishingMail...
xcopy /E /Y /I "C:\Users\Arielle Yao\Claude\Projects\Phishing Mail Forensics\scripts" "D:\PhishingMail\scripts"
xcopy /E /Y /I "C:\Users\Arielle Yao\Claude\Projects\Phishing Mail Forensics\webapp.py" "D:\PhishingMail\"
xcopy /E /Y /I "C:\Users\Arielle Yao\Claude\Projects\Phishing Mail Forensics\docker-compose.yml" "D:\PhishingMail\"
xcopy /E /Y /I "C:\Users\Arielle Yao\Claude\Projects\Phishing Mail Forensics\Dockerfile" "D:\PhishingMail\"
xcopy /E /Y /I "C:\Users\Arielle Yao\Claude\Projects\Phishing Mail Forensics\requirements.txt" "D:\PhishingMail\"
xcopy /E /Y /I "C:\Users\Arielle Yao\Claude\Projects\Phishing Mail Forensics\dashboard.html" "D:\PhishingMail\"
xcopy /Y "C:\Users\Arielle Yao\Claude\Projects\Phishing Mail Forensics\sync_and_deploy.bat" "D:\PhishingMail\"

echo.
echo [2/4] Docker rebuild...
cd /d D:\PhishingMail
docker compose down
docker compose build --no-cache
docker compose up -d

echo.
echo [3/4] Git commit + push...
cd /d D:\PhishingMail
git add -A
git commit -m "feat: impact analysis — victim scenario timeline, MITRE ATT&CK mapping, business impact, response actions + URL sandboxing"
git push

echo.
echo [4/4] Done!
echo ========================================
pause
