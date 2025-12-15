# Screenshots Guide

## How to Add Screenshots

### Step 1: Take Screenshots

Run your Flask app and capture these views:

```bash
# Start the application
source venv/bin/activate
python app.py
```

Visit `http://localhost:5000` and take screenshots of:

1. **homepage.png** - The main search interface
   - Show the IP input field
   - Include the dark cybersecurity theme

2. **results-dashboard.png** - Full results page for a malicious IP
   - Use IP: 93.174.95.106 (high risk score)
   - Capture the circular risk gauge
   - Show confidence score and recommendation

3. **kill-chain.png** - Scroll to Kill Chain section
   - Show the 6/7 stages progress bar
   - Capture the visual stage list (orange/gray)

4. **mitre-attack.png** - MITRE ATT&CK section
   - Show technique IDs (T1595, etc.)
   - Capture the tactic classifications

5. **source-health.png** - API Source Health dashboard
   - Show which sources responded (green checkmarks)
   - Capture the "3/4 sources responded" indicator

6. **export.png** - Export buttons section
   - Show JSON, CSV, PDF buttons
   - Include the cybersecurity styling

### Step 2: Save Screenshots Here

Place all images in this directory (`screenshots/`) with exact filenames:
- `homepage.png`
- `results-dashboard.png`
- `kill-chain.png`
- `mitre-attack.png`
- `source-health.png`
- `export.png`

### Recommended Settings:

- **Format:** PNG (for transparency and quality)
- **Size:** 1200x800px minimum (or full browser window)
- **Tool:**
  - Windows: Snipping Tool or Win+Shift+S
  - Mac: Cmd+Shift+4
  - Linux: GNOME Screenshot or Flameshot

### Tips for Best Screenshots:

1. **Use a real malicious IP** for dramatic visuals:
   - 93.174.95.106 (Risk: 97/100)
   - 119.18.55.217 (Risk: 70/100)

2. **Zoom browser to 100%** for crisp images

3. **Show full sections** - don't cut off important parts

4. **Dark theme looks professional** - the dark background shows well

5. **Scroll to capture specific sections** - you can take multiple screenshots and crop

## Why Screenshots Matter

For your assignment submission:
- ✅ Proves the application works
- ✅ Shows professional UI design
- ✅ Demonstrates all features visually
- ✅ Makes README more engaging
- ✅ Helps reviewers understand capabilities

## Viewing in README

Once you add the images here, the README will automatically display them when viewed on:
- GitHub
- GitLab
- Local Markdown viewers
- VS Code preview

The markdown syntax used:
```markdown
![Description](screenshots/filename.png)
*Caption text explaining what's shown*
```

## Current Status

📁 Directory created: ✅
📝 README updated: ✅
📸 Screenshots: ⏳ (Add your screenshots here)

Once you add the images, commit everything:
```bash
git add screenshots/ README.md
git commit -m "Add UI screenshots to README"
```
