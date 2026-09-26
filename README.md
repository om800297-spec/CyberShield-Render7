# CyberShield Advanced Major Project

Direct-access student scam-awareness prototype. No Gmail registration is required.

## Scanners
- Mobile Number
- Email Address
- Bank/SMS Message
- URL
- Job/Internship
- Screenshot OCR
- General message analysis
- Awareness quiz and reports

## Run
```powershell
pip install -r requirements.txt
python app.py
```
Open `http://127.0.0.1:5000`.

Email scanner direct URL: `/email-checker`
Mobile scanner direct URL: `/mobile-checker`

Results are heuristic risk indicators and do not confirm that a contact is fraudulent.
