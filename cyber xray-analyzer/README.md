# X-Ray Analyzer — Complete Setup Guide

## Project Structure

```
xray-analyzer/
├── login.html        ← Sign-in page (all users start here)
├── app.html          ← Main client dashboard (6 tools + history)
├── admin.html        ← Admin panel (manage users, view all scans)
│
├── css/
│   └── style.css     ← Full dark design system
│
├── js/
│   ├── firebase.js   ← Firebase config + all DB/Auth helpers
│   ├── core.js       ← API calls (WHOIS/DNS/Geo/SSL/VT/AI) + render utils
│   └── modules.js    ← All 6 analysis modules + PDF export + history
│
└── README.md         ← This file
```

---

## Step 1 — Firebase Setup (5 minutes, free)

1. Go to https://console.firebase.google.com
2. Click **"Add project"** → name it `X-Ray Analyzer` → Create
3. **Enable Authentication:**
   - Left sidebar → Authentication → Get Started
   - Sign-in method → Email/Password → Enable → Save
4. **Enable Firestore:**
   - Left sidebar → Firestore Database → Create Database
   - Choose **"Start in test mode"** → Next → Select region → Done
5. **Get your config:**
   - Project Settings (gear icon) → General → Your Apps → `</>` Web
   - Register app → copy the `firebaseConfig` object
6. **Paste config** into `js/firebase.js` (replace the placeholder values)

---

## Step 2 — Create the Admin Account

Firebase Authentication only stores passwords — you must also create the Firestore user document manually.

1. Go to Firebase Console → Authentication → Add User
   - Email: `admin@yourproject.com`
   - Password: choose a strong password
   - Copy the generated **UID**
2. Go to Firestore → Data → Add Collection: `users`
3. Add a document with ID = the UID you copied:
```json
{
  "firstName": "Admin",
  "lastName": "Name",
  "email": "admin@yourproject.com",
  "org": "University Name",
  "role": "admin",
  "active": true,
  "scanCount": 0
}
```

Now sign in at `login.html` with admin credentials → you'll land on `admin.html`.

---

## Step 3 — Add Clients (from Admin Panel)

1. Sign in as admin → go to `admin.html`
2. Click **"Add Client"**
3. Fill in name, email, password, organization
4. Click **"Create Account"** — the account is created in Firebase Auth + Firestore automatically
5. Share the credentials securely with the client
6. Client signs in at `login.html` → lands on `app.html`

---

## Step 4 — VirusTotal API Key (free)

1. Go to https://www.virustotal.com → Sign Up (free)
2. Go to your profile → API Key tab
3. Copy the key — paste it into the VirusTotal tool when using it
4. Free tier: 500 lookups/day, 4 lookups/minute

---

## Tools & APIs Used

| Tool | Purpose | Cost |
|------|---------|------|
| Firebase Auth | User login/logout | Free |
| Firebase Firestore | Users DB + scan history | Free (1GB) |
| Anthropic Claude API | AI phishing analysis | Included |
| RDAP (rdap.org) | WHOIS domain ownership | Free |
| Google DNS over HTTPS | DNS record queries | Free |
| ipapi.co | IP geolocation + map | Free |
| Qualys SSL Labs | SSL/TLS certificate grade | Free |
| VirusTotal API v3 | 90+ engine blacklist scan | Free key |
| Leaflet.js + CartoCDN | Interactive attack maps | Free |

---

## Security Features

- Admin-only user creation (no public registration)
- Active/inactive user toggle (admin can revoke access)
- All scans saved per user to Firestore
- PDF report export (opens print dialog)
- Role-based routing: admin → admin.html, client → app.html

---

## Project Information

| Field | Value |
|-------|-------|
| Student Name | [Your Name] |
| Student ID | [Your ID] |
| University | [University Name] |
| Department | Computer Science / Cybersecurity |
| Supervisor | [Supervisor Name] |
| Academic Year | 2025–2026 |
