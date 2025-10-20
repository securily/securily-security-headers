# AI Insights Feature

The Security Headers Scanner now includes optional AI-powered insights using Google Gemini.

## How It Works

When you provide a Gemini API key with the `-ai` flag, the scanner will:

1. **Analyze your scan results** - Understand which headers are present/missing
2. **Provide a security grade** - From A+ to F based on your security posture
3. **Generate priority actions** - Specific steps tailored to your site
4. **Assess risks** - Explain what attacks you're vulnerable to
5. **Suggest quick wins** - Easy headers to implement immediately
6. **Give industry context** - Compare your security to best practices

## Usage

### Basic scan (no AI):
```bash
./securily-headers.sh -u https://example.com
```

### Enhanced scan with AI insights:
```bash
./securily-headers.sh -u https://example.com -ai YOUR_GEMINI_API_KEY
```

## Example AI Output

```json
{
  "grade": "B",
  "priority_actions": [
    "1. Implement Permissions-Policy to control browser features",
    "2. Add Cross-Origin-Opener-Policy for isolation",
    "3. Configure Cross-Origin-Resource-Policy"
  ],
  "risk_assessment": "Vulnerable to clickjacking, XSS attacks...",
  "quick_wins": [
    "Add X-Frame-Options: DENY",
    "Set Referrer-Policy: same-origin"
  ],
  "industry_context": "Below modern security standards..."
}
```

## Benefits

- **Contextual recommendations** - Not just generic advice
- **Prioritized actions** - Know what to fix first
- **Risk understanding** - Learn what attacks you're exposed to
- **Quick implementation** - Get easy wins immediately

## Getting a Gemini API Key

1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Sign in with your Google account
3. Click "Create API Key"
4. Copy and use with the `-ai` flag

## Privacy Note

When using AI insights:
- Only your scan results summary is sent to Google Gemini
- No sensitive data from your site is transmitted
- The API is only called when you explicitly use the `-ai` flag
