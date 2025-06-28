"""
🔐 Sentinel: AI PHI Risk Scanner - Enhanced with Gemini AI
A Streamlit app for detecting Protected Health Information (PHI) in documents

Required packages:
pip install streamlit pandas PyPDF2 python-docx google-generativeai

Run with:
streamlit run sentinel_phi_scanner_ai.py
"""

import streamlit as st
import pandas as pd
import re
from datetime import datetime
import io
import base64
import json
from typing import Dict, List, Tuple, Optional
import time
import google.generativeai as genai
import os

# Import libraries for file processing
try:
    import PyPDF2
except ImportError:
    st.error("Please install PyPDF2: pip install PyPDF2")
    st.stop()

try:
    import docx
except ImportError:
    docx = None  # Optional for Word docs

# Page configuration
st.set_page_config(
    page_title="Sentinel: PHI Risk Scanner",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main {
        padding-top: 2rem;
    }
    .stButton>button {
        width: 100%;
        border-radius: 8px;
        height: 3em;
        font-weight: 600;
    }
    .risk-high {
        background-color: #ff4757;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-weight: bold;
    }
    .risk-moderate {
        background-color: #ffa502;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-weight: bold;
    }
    .risk-low {
        background-color: #2ed573;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-weight: bold;
    }
    div.stAlert {
        border-radius: 10px;
    }
    .stDownloadButton {
        display: inline-block;
    }
    .risk-card {
        border-radius: 10px;
        padding: 20px;
        margin: 20px 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .risk-high-card {
        background: linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%);
        border-left: 5px solid #ff4757;
    }
    .risk-moderate-card {
        background: linear-gradient(135deg, #fff8e1 0%, #ffe0b2 100%);
        border-left: 5px solid #ff9f43;
    }
    .risk-low-card {
        background: linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%);
        border-left: 5px solid #10ac84;
    }
    .phi-revealed {
        background-color: #ffe5e5;
        padding: 2px 6px;
        border-radius: 4px;
        color: #d32f2f;
        font-weight: bold;
    }
    .phi-redacted {
        background-color: #f5f5f5;
        padding: 2px 6px;
        border-radius: 4px;
        color: #666;
        font-family: monospace;
    }
    .ai-verified {
        color: #4CAF50;
        font-weight: bold;
    }
    .ai-discovered {
        color: #2196F3;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []
if 'total_files_scanned' not in st.session_state:
    st.session_state.total_files_scanned = 0
if 'high_risk_count' not in st.session_state:
    st.session_state.high_risk_count = 0
if 'total_phi_found' not in st.session_state:
    st.session_state.total_phi_found = 0
if 'current_results' not in st.session_state:
    st.session_state.current_results = []
if 'active_tab' not in st.session_state:
    st.session_state.active_tab = 0
if 'ai_enabled' not in st.session_state:
    st.session_state.ai_enabled = False
if 'ai_verification_count' not in st.session_state:
    st.session_state.ai_verification_count = 0
if 'ai_findings_count' not in st.session_state:
    st.session_state.ai_findings_count = 0

# PHI Detection Patterns - ENHANCED VERSION WITH SENSITIVE CONTENT
PHI_PATTERNS = {
    'SSN': {
        'pattern': r'\b(?:SSN|Social Security|SS#|SS\s*#|Social\s*Security\s*Number)[\s:]*(\d{3}-\d{2}-\d{4}|\d{9})\b',
        'description': 'Social Security Number',
        'priority': 'high',
        'category': 'demographic',
        'hipaa_identifier': 7
    },
    'MRN': {
        'pattern': r'\b(?:MRN|Medical Record|MR#|Account#|Acct#|Patient ID)[\s:#]*([A-Z]{0,3}\d{6,12})\b',
        'description': 'Medical Record Number',
        'priority': 'high',
        'category': 'demographic',
        'hipaa_identifier': 8
    },
    'DOB': {
        'pattern': r'\b(?:DOB|Date of Birth|Birth Date|Born|Birthdate)\s*:?\s*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b',
        'description': 'Date of Birth',
        'priority': 'medium',
        'category': 'demographic',
        'hipaa_identifier': 3
    },
    'Phone': {
        'pattern': r'\b(?:Phone|Ph|Tel|Telephone|Cell|Mobile|Contact)?\s*:?\s*(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b',
        'description': 'Phone Number',
        'priority': 'medium',
        'category': 'demographic',
        'hipaa_identifier': 4
    },
    'Email': {
        'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'description': 'Email Address',
        'priority': 'low',
        'category': 'demographic',
        'hipaa_identifier': 6
    },
    'Patient_Name': {
        'pattern': r'(?:Patient Name|Patient|Name|Pt)\s*:?\s*([A-Z][a-z]+(?:\s+[A-Z]\.?)?\s+[A-Z][a-z]+)',
        'description': 'Patient Name',
        'priority': 'high',
        'category': 'demographic',
        'hipaa_identifier': 1
    },
    'Address': {
        'pattern': r'\b\d{1,5}\s+(?:[NSEW]\.?\s+)?(?:\w+\s+){0,2}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Circle|Cir|Plaza|Pl|Way|Parkway|Pkwy)(?:\s+(?:Apt|Apartment|Suite|Ste|Unit|#)\s*\w+)?\b',
        'description': 'Physical Address',
        'priority': 'medium',
        'category': 'demographic',
        'hipaa_identifier': 2
    },
    'Credit_Card': {
        'pattern': r'\b(?:Credit Card|CC|Card|card on file)?\s*:?\s*(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b',
        'description': 'Credit Card Number',
        'priority': 'high',
        'category': 'financial',
        'hipaa_identifier': 10
    },
    'Insurance_ID': {
        'pattern': r'\b(?:Insurance ID|Member ID|Policy#|Group#)\s*:?\s*([A-Z0-9]{6,15})\b',
        'description': 'Insurance ID',
        'priority': 'medium',
        'category': 'financial',
        'hipaa_identifier': 9
    },
    'License': {
        'pattern': r'\b(?:DL|Drivers License|Driver License|License#?)\s*:?\s*([A-Z]{0,2}\d{5,10})\b',
        'description': 'Driver License',
        'priority': 'medium',
        'category': 'demographic',
        'hipaa_identifier': 11
    },
    'Case_Number': {
        'pattern': r'\b(?:Case\s*(?:Number|#|No\.?)|Docket\s*(?:Number|#))[\s:]*([A-Z0-9-]{6,20})\b',
        'description': 'Legal Case Number',
        'priority': 'high',
        'category': 'legal',
        'hipaa_identifier': 18
    },
    'Fax': {
        'pattern': r'\b(?:Fax|Facsimile)\s*:?\s*(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b',
        'description': 'Fax Number',
        'priority': 'low',
        'category': 'demographic',
        'hipaa_identifier': 5
    },
    'IP_Address': {
        'pattern': r'\b(?:IP|IP Address)\s*:?\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
        'description': 'IP Address',
        'priority': 'medium',
        'category': 'technical',
        'hipaa_identifier': 15
    },
    'URL': {
        'pattern': r'\b(?:https?://|www\.)[a-zA-Z0-9-._~:/?#[\]@!$&\'()*+,;=]+\b',
        'description': 'Web URL',
        'priority': 'low',
        'category': 'technical',
        'hipaa_identifier': 14
    },
    'Device_ID': {
        'pattern': r'\b(?:Device ID|Serial Number|Device Serial|Equipment ID)\s*:?\s*([A-Z0-9-]{6,20})\b',
        'description': 'Device/Serial Number',
        'priority': 'medium',
        'category': 'technical',
        'hipaa_identifier': 13
    },
    'Vehicle_ID': {
        'pattern': r'\b(?:VIN|Vehicle ID|License Plate)\s*:?\s*([A-Z0-9]{6,17})\b',
        'description': 'Vehicle Identifier',
        'priority': 'low',
        'category': 'demographic',
        'hipaa_identifier': 12
    },
    'Biometric': {
        'pattern': r'\b(?:Fingerprint|Retinal|Iris|Voice|Face|Biometric)\s*(?:ID|Scan|Data|Recognition)\b',
        'description': 'Biometric Identifier',
        'priority': 'high',
        'category': 'biometric',
        'hipaa_identifier': 16
    }
}

# Initialize Gemini
try:
    # Try to get API key from Streamlit secrets first, then environment
    GEMINI_API_KEY = st.secrets.get("GEMINI_API_KEY", os.getenv("GEMINI_API_KEY"))
    if GEMINI_API_KEY:
        genai.configure(api_key=GEMINI_API_KEY)
        # Initialize models
        flash_model = genai.GenerativeModel('gemini-1.5-flash')
        pro_model = genai.GenerativeModel('gemini-1.5-pro')
        AI_AVAILABLE = True
    else:
        AI_AVAILABLE = False
except Exception as e:
    AI_AVAILABLE = False
    print(f"Gemini initialization error: {e}")

# Complete list of HIPAA identifiers for compliance checking
HIPAA_IDENTIFIERS = {
    1: "Names",
    2: "Geographic subdivisions smaller than state",
    3: "Dates (except year) related to individual",
    4: "Telephone numbers",
    5: "Fax numbers",
    6: "Email addresses",
    7: "Social Security numbers",
    8: "Medical record numbers",
    9: "Health plan beneficiary numbers",
    10: "Account numbers",
    11: "Certificate/license numbers",
    12: "Vehicle identifiers and serial numbers",
    13: "Device identifiers and serial numbers",
    14: "Web URLs",
    15: "IP addresses",
    16: "Biometric identifiers",
    17: "Full face photos and comparable images",
    18: "Any other unique identifying number"
}

# Sensitive content patterns for context analysis
SENSITIVE_CONTENT_PATTERNS = {
    'mental_health_crisis': {
        'patterns': [
            r'\b(?:suicide|suicidal|self-harm|overdose|psychiatric\s*emergency|crisis\s*intervention|involuntary\s*commitment|5150|baker\s*act)\b',
            r'\b(?:attempted\s*suicide|suicide\s*attempt|danger\s*to\s*self|danger\s*to\s*others)\b'
        ],
        'category': 'mental_health',
        'sensitivity': 'extreme'
    },
    'domestic_violence': {
        'patterns': [
            r'\b(?:domestic\s*violence|DV|intimate\s*partner\s*violence|IPV|abuse|abused|battered|assault|restraining\s*order|protective\s*order|shelter)\b',
            r'\b(?:victim\s*of\s*violence|physical\s*abuse|emotional\s*abuse|sexual\s*abuse)\b'
        ],
        'category': 'violence',
        'sensitivity': 'extreme'
    },
    'substance_abuse': {
        'patterns': [
            r'\b(?:substance\s*abuse|drug\s*abuse|addiction|alcoholism|rehab|rehabilitation|detox|withdrawal|methadone|suboxone|naloxone|narcan)\b',
            r'\b(?:overdose|OD|drug\s*dependency|alcohol\s*dependency|opioid\s*use\s*disorder|substance\s*use\s*disorder)\b'
        ],
        'category': 'substance',
        'sensitivity': 'high'
    },
    'mental_health_general': {
        'patterns': [
            r'\b(?:depression|anxiety|bipolar|schizophrenia|PTSD|psychosis|psychiatric|mental\s*health|therapy|counseling|psychiatrist|psychologist)\b',
            r'\b(?:antidepressant|antipsychotic|mood\s*stabilizer|benzodiazepine|SSRI|SNRI)\b'
        ],
        'category': 'mental_health',
        'sensitivity': 'high'
    },
    'hiv_std': {
        'patterns': [
            r'\b(?:HIV|AIDS|human\s*immunodeficiency|acquired\s*immune|STD|STI|sexually\s*transmitted|syphilis|gonorrhea|chlamydia|hepatitis\s*[BC])\b'
        ],
        'category': 'protected_health',
        'sensitivity': 'high'
    },
    'reproductive': {
        'patterns': [
            r'\b(?:pregnancy|pregnant|abortion|miscarriage|fertility|IVF|contraception|birth\s*control|reproductive\s*health)\b',
            r'\b(?:prenatal|obstetric|gynecolog|termination|family\s*planning)\b'
        ],
        'category': 'reproductive',
        'sensitivity': 'high'
    },
    'legal_involvement': {
        'patterns': [
            r'\b(?:incarcerated|incarceration|jail|prison|custody|parole|probation|arrest|criminal|conviction|court\s*order)\b',
            r'\b(?:detained|detention|correctional|inmate|prisoner)\b'
        ],
        'category': 'legal',
        'sensitivity': 'extreme'
    }
}

# Medical terms to exclude from name detection
MEDICAL_TERMS = {
    'medical', 'history', 'physical', 'examination', 'emergency', 'department',
    'chief', 'complaint', 'present', 'illness', 'review', 'systems', 'vital', 'signs',
    'blood', 'pressure', 'pulse', 'temperature', 'general', 'appearance', 'skin',
    'chest', 'abdomen', 'extremities', 'neurological', 'assessment', 'plan',
    'diagnosis', 'treatment', 'medication', 'allergy', 'social', 'family',
    'surgical', 'medical', 'problem', 'list', 'discharge', 'summary',
    'heart', 'lung', 'liver', 'kidney', 'brain', 'spine', 'bone',
    'normal', 'abnormal', 'positive', 'negative', 'stable', 'acute', 'chronic',
    'bilateral', 'left', 'right', 'upper', 'lower', 'anterior', 'posterior'
}

def is_medical_term(text: str) -> bool:
    """Check if text contains common medical terms"""
    words = text.lower().split()
    return any(word in MEDICAL_TERMS for word in words)

def detect_phi(text: str) -> List[Dict]:
    """Detect PHI in text using advanced regex patterns with context awareness"""
    findings = []
    found_positions = set()  # Track positions to avoid duplicates
    
    for phi_type, config in PHI_PATTERNS.items():
        matches = re.finditer(config['pattern'], text, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            # Skip if we've already found PHI at this position
            if match.start() in found_positions:
                continue
                
            # Get the full match and the captured group (if any)
            full_match = match.group(0)
            value = match.group(1) if match.groups() else match.group(0)
            original_value = value  # Store original before any processing
            
            # Special handling for patient names
            if phi_type == 'Patient_Name':
                # Extract just the name part, not the label
                value = match.group(1) if match.groups() else value
                original_value = value
                # Skip if it's a medical term
                if is_medical_term(value):
                    continue
            
            # Special handling for phone numbers to extract just the number
            if phi_type == 'Phone':
                # Extract just the phone number without the label
                phone_match = re.search(r'(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})', full_match)
                if phone_match:
                    value = phone_match.group(1)
                    original_value = value
            
            # Special handling for credit cards to extract just the number
            if phi_type == 'Credit_Card':
                # Extract just the credit card number
                cc_match = re.search(r'(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})', full_match)
                if cc_match:
                    value = cc_match.group(1)
                    original_value = value
            
            # Skip dates that are clearly not DOB (like years only)
            if phi_type == 'DOB':
                # Extract year using a simpler approach
                try:
                    # Look for 4-digit or 2-digit year at the end
                    year_pattern = re.compile(r"(\d{4}|\d{2})$")
                    year_match = year_pattern.search(value)
                    if year_match:
                        year = int(year_match.group(1))
                        # Convert 2-digit year to 4-digit
                        if year < 100:
                            year = 1900 + year if year > 50 else 2000 + year
                        # Skip if date is too old (before 1900) or in the future
                        current_year = datetime.now().year
                        if year < 1900 or year > current_year:
                            continue
                except:
                    pass
            
            # Redact the value appropriately
            if len(value) > 4:
                if phi_type == 'Email':
                    # Keep first letter and domain
                    parts = value.split('@')
                    if len(parts) == 2:
                        redacted = parts[0][0] + '*' * (len(parts[0]) - 1) + '@' + parts[1]
                    else:
                        redacted = value[:1] + '*' * (len(value) - 3) + value[-2:]
                elif phi_type == 'Patient_Name':
                    # Show first letter of first name and last initial
                    parts = value.split()
                    if len(parts) >= 2:
                        redacted = parts[0][0] + '*' * (len(parts[0]) - 1) + ' ' + parts[-1][0] + '*' * (len(parts[-1]) - 1)
                    else:
                        redacted = value[0] + '*' * (len(value) - 1)
                elif phi_type == 'Credit_Card':
                    # Show last 4 digits only
                    redacted = '**** **** **** ' + value.replace('-', '').replace(' ', '')[-4:]
                else:
                    redacted = value[:2] + '*' * (len(value) - 4) + value[-2:]
            else:
                redacted = '*' * len(value)
            
            finding = {
                'type': phi_type.replace('_', ' '),
                'description': config['description'],
                'value': redacted,
                'original_value': original_value,  # Store original value
                'position': match.span(),
                'confidence': calculate_confidence(phi_type, value, full_match),
                'priority': config.get('priority', 'medium')
            }
            
            # Only add if confidence is above threshold
            if finding['confidence'] >= 60:  # Minimum 60% confidence
                findings.append(finding)
                found_positions.add(match.start())
    
    # Remove duplicates and sort by position
    findings = sorted(findings, key=lambda x: x['position'][0])
    
    return findings

def calculate_confidence(phi_type: str, value: str, full_match: str = "") -> int:
    """Calculate confidence score for PHI detection with context awareness"""
    base_confidence = 70
    
    # High confidence for explicit labels
    if any(label in full_match.lower() for label in ['patient name:', 'dob:', 'ssn:', 'mrn:', 'credit card']):
        return 95
    
    # Specific pattern confidence adjustments
    if phi_type == 'SSN':
        if re.match(r'^\d{3}-\d{2}-\d{4}$', value):
            return 95
        elif re.match(r'^\d{9}$', value):
            return 85
    
    elif phi_type == 'MRN':
        if 'MRN' in full_match or 'Medical Record' in full_match:
            return 90
        return 75
    
    elif phi_type == 'Email':
        if '@' in value and '.' in value.split('@')[1]:
            return 90
    
    elif phi_type == 'Patient_Name':
        # Higher confidence if preceded by patient-related terms
        if any(term in full_match.lower() for term in ['patient name', 'patient:', 'name:']):
            return 90
        # Lower confidence for generic names
        return 65
    
    elif phi_type == 'DOB':
        # Check if it looks like a realistic birth date
        try:
            # Simple year extraction
            year_str = re.search(r'\d{4}|\d{2}$', value)
            if year_str:
                year = int(year_str.group())
                if year < 100:
                    year = 1900 + year if year > 50 else 2000 + year
                current_year = datetime.now().year
                age = current_year - year
                if 0 <= age <= 120:  # Realistic age range
                    return 85
        except:
            pass
        return 70
    
    elif phi_type == 'Phone':
        if re.match(r'^\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}$', value):
            return 85
    
    elif phi_type == 'Address':
        # Higher confidence for complete addresses
        if any(apt in full_match.lower() for apt in ['apt', 'suite', 'unit']):
            return 85
        return 75
    
    elif phi_type == 'Credit_Card':
        # Check if it's a valid credit card pattern
        if re.match(r'^\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}$', value):
            return 90
        return 85
    
    elif phi_type == 'License':
        if 'DL' in full_match or 'License' in full_match:
            return 85
        return 75
    
    return base_confidence

# Gemini AI Helper Functions
def extract_json_from_gemini_response(response_text: str) -> Dict:
    """Extract JSON from Gemini response, handling markdown formatting"""
    import json
    
    # Clean up response text
    response_text = response_text.strip()
    
    # Remove markdown code blocks if present
    if response_text.startswith("```json"):
        response_text = response_text[7:]
    if response_text.startswith("```"):
        response_text = response_text[3:]
    if response_text.endswith("```"):
        response_text = response_text[:-3]
    
    # Try to find JSON content
    try:
        # Look for JSON object
        start_idx = response_text.find('{')
        end_idx = response_text.rfind('}') + 1
        if start_idx != -1 and end_idx != 0:
            json_str = response_text[start_idx:end_idx]
            return json.loads(json_str)
    except:
        pass
    
    # Try parsing the whole thing
    try:
        return json.loads(response_text)
    except:
        return {}

def verify_phi_with_gemini(
    text_context: str, 
    phi_type: str, 
    detected_value: str,
    original_value: str,
    model_name: str = "flash"
) -> Dict[str, any]:
    """Use Gemini to verify if detected text is actually PHI"""
    
    if not AI_AVAILABLE:
        return {"is_phi": True, "confidence": 75, "reasoning": "AI unavailable"}
    
    # Select model
    model = flash_model if model_name == "flash" else pro_model
    
    prompt = f"""You are a HIPAA compliance expert. Analyze if this is real PHI or a false positive.

Context around the finding: "{text_context}"

Detection details:
- PHI Type: {phi_type}
- Detected Value: "{original_value}"
- Pattern matched: {phi_type}

Determine:
1. Is this actually {phi_type} that belongs to a real patient?
2. Or is this a false positive (template text, example, non-patient data)?
3. Consider the context carefully

Respond with JSON only:
{{
    "is_phi": true or false,
    "confidence": 0-100,
    "reasoning": "brief explanation why this is or isn't real PHI",
    "risk_level": "low" or "medium" or "high"
}}"""

    try:
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.1,
                max_output_tokens=200,
            )
        )
        
        result = extract_json_from_gemini_response(response.text)
        
        # Validate response
        if not result or 'is_phi' not in result:
            return {"is_phi": True, "confidence": 75, "reasoning": "Invalid AI response format"}
            
        return result
        
    except Exception as e:
        print(f"Gemini verification error: {e}")
        return {"is_phi": True, "confidence": 75, "reasoning": f"AI error: {str(e)}"}

def find_missed_phi_with_gemini(
    text_chunk: str,
    existing_findings: List[Dict],
    model_name: str = "flash"
) -> List[Dict]:
    """Use Gemini to find PHI that regex patterns might have missed"""
    
    if not AI_AVAILABLE or not text_chunk:
        return []
    
    # Summarize what we already found
    found_summary = []
    for f in existing_findings[:5]:  # Limit to prevent token overflow
        found_summary.append(f"{f['type']}: {f['value']}")
    
    model = flash_model if model_name == "flash" else pro_model
    
    prompt = f"""Analyze this medical text for PHI that standard patterns might miss.

Text to analyze:
{text_chunk[:2000]}  # Limit size

Already found PHI:
{', '.join(found_summary) if found_summary else 'None found yet'}

Look for:
1. Indirect identifiers (e.g., "the patient from apartment 2B")
2. Contextual dates (e.g., "admitted last Tuesday")
3. Nicknames or unusual name formats
4. Partial identifiers
5. Misspelled PHI
6. Any other HIPAA identifiers stated indirectly

For each NEW finding (not already listed above), provide:
{{
    "findings": [
        {{
            "type": "PHI type",
            "value": "the actual text containing PHI",
            "reasoning": "why this is PHI"
        }}
    ]
}}

Only include actual PHI, not generic medical terms. Return empty findings array if nothing new found."""

    try:
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.2,
                max_output_tokens=500,
            )
        )
        
        result = extract_json_from_gemini_response(response.text)
        
        if result and 'findings' in result:
            # Convert to format matching your existing findings
            ai_findings = []
            for f in result['findings']:
                ai_findings.append({
                    'type': f.get('type', 'Unknown'),
                    'description': f.get('reasoning', 'AI-detected PHI'),
                    'value': f.get('value', '')[:50],  # Limit length
                    'original_value': f.get('value', ''),
                    'position': (0, 0),  # AI doesn't give exact positions
                    'confidence': 85,  # Default high confidence for AI findings
                    'priority': 'medium',
                    'source': 'gemini_ai'
                })
            return ai_findings
            
        return []
        
    except Exception as e:
        print(f"Gemini missed PHI error: {e}")
        return []

def analyze_document_with_gemini(
    text: str,
    findings: List[Dict],
    model_name: str = "flash"
) -> Dict:
    """Comprehensive document analysis with Gemini"""
    
    if not AI_AVAILABLE:
        return {}
    
    model = flash_model if model_name == "flash" else pro_model
    
    # Prepare findings summary
    findings_summary = []
    for f in findings[:20]:  # Limit to prevent token overflow
        findings_summary.append(f"{f['type']}: {f['value']}")
    
    prompt = f"""Analyze this medical document comprehensively for PHI risks and compliance.

Document excerpt (first 3000 chars):
{text[:3000]}

PHI already detected:
{chr(10).join(findings_summary)}

Provide analysis:
{{
    "document_type": "specific type of medical document",
    "sensitivity_assessment": {{
        "level": "low/moderate/high/extreme",
        "reasoning": "why this sensitivity level"
    }},
    "compliance_risks": ["list of specific risks"],
    "special_handling": ["specific requirements based on content"],
    "recommendations": ["actionable recommendations"]
}}"""

    try:
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.3,
                max_output_tokens=800,
            )
        )
        
        return extract_json_from_gemini_response(response.text)
        
    except Exception as e:
        print(f"Document analysis error: {e}")
        return {}

def detect_phi_with_ai(
    text: str, 
    use_ai: bool = False, 
    ai_model: str = "flash",
    ai_confidence_threshold: int = 70,
    find_missed_phi: bool = True
) -> Tuple[List[Dict], Dict]:
    """Enhanced PHI detection with optional Gemini AI verification and discovery"""
    
    # First, use your existing regex detection
    regex_findings = detect_phi(text)
    
    # If AI is not enabled, return original results
    if not use_ai or not AI_AVAILABLE:
        return regex_findings, {}
    
    # Track AI statistics
    ai_stats = {
        "verified": 0,
        "rejected": 0,
        "added": 0,
        "model": ai_model,
        "errors": 0
    }
    
    # Phase 1: Verify existing findings with AI
    verified_findings = []
    
    for finding in regex_findings:
        # Get context window around finding
        start, end = finding['position']
        context_start = max(0, start - 100)
        context_end = min(len(text), end + 100)
        context = text[context_start:context_end]
        
        # Verify with Gemini
        ai_result = verify_phi_with_gemini(
            context,
            finding['type'],
            finding['value'],
            finding.get('original_value', finding['value']),
            ai_model
        )
        
        # Check AI verification
        if ai_result.get('is_phi', True) and ai_result.get('confidence', 0) >= ai_confidence_threshold:
            # AI confirmed this is PHI
            finding['ai_verified'] = True
            finding['ai_confidence'] = ai_result.get('confidence', 0)
            finding['ai_reasoning'] = ai_result.get('reasoning', '')
            verified_findings.append(finding)
            ai_stats['verified'] += 1
        else:
            # AI rejected this finding
            ai_stats['rejected'] += 1
    
    # Phase 2: Look for missed PHI (if enabled)
    if find_missed_phi and len(text) < 10000:  # Limit for performance
        # Process in chunks
        chunk_size = 2000
        for i in range(0, len(text), chunk_size):
            chunk = text[i:i + chunk_size]
            
            # Find PHI that regex missed
            ai_findings = find_missed_phi_with_gemini(
                chunk,
                verified_findings,
                ai_model
            )
            
            # Add AI-discovered findings
            for ai_finding in ai_findings:
                # Adjust position relative to chunk
                ai_finding['position'] = (i, i + len(ai_finding.get('original_value', '')))
                ai_finding['ai_discovered'] = True
                verified_findings.append(ai_finding)
                ai_stats['added'] += 1
    
    # Sort findings by position
    verified_findings = sorted(verified_findings, key=lambda x: x['position'][0])
    
    # Update session state
    st.session_state.ai_verification_count += ai_stats['verified'] + ai_stats['rejected']
    st.session_state.ai_findings_count += ai_stats['added']
    
    return verified_findings, ai_stats

def detect_sensitive_content(text: str) -> Dict[str, List[Dict]]:
    """Detect sensitive health and legal content in text"""
    sensitive_findings = {}
    
    for content_type, config in SENSITIVE_CONTENT_PATTERNS.items():
        matches = []
        for pattern in config['patterns']:
            found = re.finditer(pattern, text, re.IGNORECASE)
            for match in found:
                matches.append({
                    'text': match.group(0),
                    'position': match.span(),
                    'category': config['category'],
                    'sensitivity': config['sensitivity']
                })
        
        if matches:
            sensitive_findings[content_type] = matches
    
    return sensitive_findings

def analyze_data_categories(text: str, phi_findings: List[Dict], sensitive_content: Dict) -> Dict:
    """Analyze and categorize all data types present in the document"""
    categories = {
        'demographic_identifiers': [],
        'financial_information': [],
        'health_conditions': [],
        'treatments_medications': [],
        'mental_health': [],
        'legal_information': [],
        'high_risk_situations': []
    }
    
    # Categorize PHI findings
    for finding in phi_findings:
        phi_type_key = finding['type'].replace(' ', '_')
        if phi_type_key in PHI_PATTERNS:
            category = PHI_PATTERNS[phi_type_key].get('category', 'other')
            if category == 'demographic':
                categories['demographic_identifiers'].append(finding['type'])
            elif category == 'financial':
                categories['financial_information'].append(finding['type'])
            elif category == 'legal':
                categories['legal_information'].append(finding['type'])
    
    # Analyze sensitive content
    for content_type, matches in sensitive_content.items():
        if not matches:
            continue
            
        config = SENSITIVE_CONTENT_PATTERNS[content_type]
        if config['category'] == 'mental_health':
            categories['mental_health'].append(content_type)
        elif config['category'] == 'legal':
            categories['legal_information'].append(content_type)
        elif config['category'] in ['violence', 'substance']:
            categories['high_risk_situations'].append(content_type)
        elif config['category'] in ['protected_health', 'reproductive']:
            categories['health_conditions'].append(content_type)
    
    # Look for medications and treatments
    medication_patterns = [
        r'\b(?:mg|mcg|ml|tablet|capsule|injection|dose|daily|twice|PRN)\b',
        r'\b(?:medication|prescription|treatment|therapy)\b'
    ]
    for pattern in medication_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            categories['treatments_medications'].append('medication_references')
            break
    
    return categories

def calculate_enhanced_risk_score(phi_findings: List[Dict], sensitive_content: Dict, data_categories: Dict) -> Tuple[str, int, str]:
    """
    Calculate risk score with enhanced sensitivity analysis
    Returns: (sensitivity_level, risk_score, detailed_rationale)
    """
    # Base scoring from PHI
    phi_types_found = set()
    high_risk_phi = 0
    
    for finding in phi_findings:
        phi_type = finding['type']
        phi_types_found.add(phi_type)
        if finding.get('priority') == 'high':
            high_risk_phi += 1
    
    # Count data categories
    has_identifiers = bool(data_categories['demographic_identifiers'])
    has_financial = bool(data_categories['financial_information'])
    has_mental_health = bool(data_categories['mental_health'])
    has_legal = bool(data_categories['legal_information'])
    has_high_risk = bool(data_categories['high_risk_situations'])
    has_protected_health = bool(data_categories['health_conditions'])
    
    # Determine sensitivity level and build rationale
    sensitivity_level = 'low'
    risk_score = 0
    rationale_parts = []
    
    # Check for extreme sensitivity conditions first
    if has_high_risk or (has_mental_health and 'mental_health_crisis' in data_categories['mental_health']):
        sensitivity_level = 'extreme'
        risk_score = 95
        if 'domestic_violence' in data_categories['high_risk_situations']:
            rationale_parts.append("Document contains domestic violence information")
        if 'mental_health_crisis' in data_categories['mental_health']:
            rationale_parts.append("Mental health crisis data detected")
        if has_legal:
            rationale_parts.append("Legal involvement information present")
    
    # Check for high sensitivity
    elif (has_identifiers and has_financial) or has_mental_health or has_protected_health:
        sensitivity_level = 'high'
        risk_score = 80
        if has_identifiers and has_financial:
            rationale_parts.append(f"Multiple identifiers ({len(data_categories['demographic_identifiers'])}) with financial data")
        if has_mental_health:
            rationale_parts.append("Mental health information present")
        if has_protected_health:
            rationale_parts.append("Protected health information (HIV/STD/Reproductive) detected")
    
    # Check for moderate sensitivity
    elif has_identifiers and len(phi_findings) > 3:
        sensitivity_level = 'moderate'
        risk_score = 60
        rationale_parts.append(f"Direct identifiers with {len(phi_findings)} PHI elements")
    
    # Low sensitivity
    else:
        sensitivity_level = 'low'
        risk_score = 30
        if len(phi_findings) > 0:
            rationale_parts.append(f"Limited identifiers ({len(phi_findings)} elements)")
        else:
            rationale_parts.append("No significant PHI detected")
    
    # Build detailed rationale
    detailed_rationale = f"Sensitivity Level: {sensitivity_level.upper()}\n"
    detailed_rationale += f"Risk Score: {risk_score}/100\n\n"
    detailed_rationale += "Key Findings:\n"
    for part in rationale_parts:
        detailed_rationale += f"• {part}\n"
    
    # Add specific data points
    if phi_types_found:
        detailed_rationale += f"\nPHI Types Found: {', '.join(sorted(phi_types_found))}\n"
    
    if sensitive_content:
        detailed_rationale += "\nSensitive Content Detected:\n"
        for content_type, matches in sensitive_content.items():
            if matches:
                detailed_rationale += f"• {content_type.replace('_', ' ').title()}: {len(matches)} instance(s)\n"
    
    return sensitivity_level, risk_score, detailed_rationale

def calculate_risk_score(findings: List[Dict]) -> Tuple[str, int]:
    """Calculate document risk score based on PHI findings with smart weighting"""
    if not findings:
        return 'low', 0
    
    # Count unique PHI types, not total instances
    phi_types_found = set()
    high_risk_items = 0
    
    for finding in findings:
        phi_type = finding['type']
        phi_types_found.add(phi_type)
        
        # Count high-risk items (SSN, Credit Card, etc.)
        if finding.get('priority') == 'high' and phi_type in ['SSN', 'Credit Card', 'MRN', 'Patient Name']:
            high_risk_items += 1
    
    # Base score on diversity of PHI types found
    base_score = len(phi_types_found) * 15
    
    # Add points for high-risk items
    high_risk_score = high_risk_items * 20
    
    # Add small penalty for volume (but not too much)
    volume_score = min(len(findings) * 2, 20)  # Max 20 points for volume
    
    # Total score
    total_score = base_score + high_risk_score + volume_score
    
    # More reasonable risk levels
    if total_score >= 80 or high_risk_items >= 2:
        return 'high', min(total_score, 95)  # Cap at 95 instead of 100
    elif total_score >= 40 or high_risk_items >= 1:
        return 'moderate', total_score
    else:
        return 'low', total_score

def extract_text_from_file(file) -> str:
    """Extract text from various file types"""
    text = ""
    
    try:
        if file.type == "application/pdf":
            # Read PDF
            pdf_reader = PyPDF2.PdfReader(file)
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                text += page.extract_text() + "\n"
                
        elif file.type == "text/plain":
            # Read text file
            text = str(file.read(), 'utf-8')
            
        elif file.type in ["application/vnd.openxmlformats-officedocument.wordprocessingml.document", 
                          "application/msword"] and docx:
            # Read Word document
            doc = docx.Document(file)
            for paragraph in doc.paragraphs:
                text += paragraph.text + "\n"
                
        else:
            st.warning(f"File type {file.type} not fully supported. Using basic text extraction.")
            try:
                text = str(file.read(), 'utf-8', errors='ignore')
            except:
                text = ""
            
    except Exception as e:
        st.error(f"Error reading {file.name}: {str(e)}")
        return ""
    
    return text

def process_file(file, min_confidence: int = 60, debug: bool = False, use_ai: bool = False, 
                 ai_model: str = "flash", ai_confidence_threshold: int = 70, 
                 find_missed_phi: bool = True) -> Dict:
    """Process uploaded file and scan for PHI with optional Gemini AI enhancement"""
    
    # Extract actual text from the file
    text = extract_text_from_file(file)
    
    if not text:
        st.error(f"Could not extract text from {file.name}")
        return {
            'filename': file.name,
            'file_size': f"{file.size / 1024:.2f} KB",
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'findings': [],
            'risk_level': 'low',
            'risk_score': 0,
            'text_preview': "No text extracted",
            'sensitivity_level': 'low',
            'detailed_rationale': 'No text extracted from file',
            'ai_stats': {}
        }
    
    # Debug mode - show extracted text
    if debug:
        with st.expander("🐛 Debug: Raw Extracted Text"):
            st.text_area("Extracted Text (first 2000 chars)", text[:2000], height=300)
            st.info(f"Total text length: {len(text)} characters")
    
    # Detect PHI with optional AI enhancement
    if use_ai:
        with st.spinner(f"🤖 Analyzing with Gemini AI ({ai_model} model)..."):
            all_findings, ai_stats = detect_phi_with_ai(
                text, 
                use_ai=True, 
                ai_model=ai_model,
                ai_confidence_threshold=ai_confidence_threshold,
                find_missed_phi=find_missed_phi
            )
            
            # Get comprehensive document analysis
            doc_analysis = analyze_document_with_gemini(text, all_findings, ai_model)
    else:
        # Use original regex detection
        all_findings = detect_phi(text)
        ai_stats = {}
        doc_analysis = {}
    
    # Debug mode - show all pattern matches
    if debug:
        with st.expander("🐛 Debug: All Pattern Matches"):
            if all_findings:
                debug_df = pd.DataFrame([{
                    'Type': f['type'],
                    'Value': f['value'],
                    'Confidence': f['confidence'],
                    'AI Verified': f.get('ai_verified', 'N/A'),
                    'AI Discovered': f.get('ai_discovered', False),
                    'Position': f['position']
                } for f in all_findings])
                st.dataframe(debug_df)
                
                if ai_stats:
                    st.json(ai_stats)
            else:
                st.warning("No pattern matches found!")
    
    # Filter by confidence threshold
    findings = [f for f in all_findings if f['confidence'] >= min_confidence]
    
    # Detect sensitive content
    sensitive_content = detect_sensitive_content(text)
    
    # Analyze data categories
    data_categories = analyze_data_categories(text, findings, sensitive_content)
    
    # Enhanced risk calculation using AI insights
    if use_ai and doc_analysis:
        # Use AI sensitivity assessment if available
        ai_sensitivity = doc_analysis.get('sensitivity_assessment', {}).get('level', '')
        if ai_sensitivity:
            sensitivity_map = {
                'extreme': ('extreme', 95),
                'high': ('high', 85),
                'moderate': ('moderate', 60),
                'low': ('low', 30)
            }
            if ai_sensitivity in sensitivity_map:
                sensitivity_level, risk_score = sensitivity_map[ai_sensitivity]
                detailed_rationale = f"AI Assessment: {doc_analysis.get('sensitivity_assessment', {}).get('reasoning', '')}\n\n"
            else:
                sensitivity_level, risk_score, detailed_rationale = calculate_enhanced_risk_score(
                    findings, sensitive_content, data_categories
                )
        else:
            sensitivity_level, risk_score, detailed_rationale = calculate_enhanced_risk_score(
                findings, sensitive_content, data_categories
            )
    else:
        # Use original risk calculation
        sensitivity_level, risk_score, detailed_rationale = calculate_enhanced_risk_score(
            findings, sensitive_content, data_categories
        )
    
    # Add AI stats to rationale if available
    if ai_stats:
        detailed_rationale += f"\n\nAI Analysis Summary:\n"
        detailed_rationale += f"• Verified: {ai_stats.get('verified', 0)} findings\n"
        detailed_rationale += f"• Rejected: {ai_stats.get('rejected', 0)} false positives\n"
        detailed_rationale += f"• Discovered: {ai_stats.get('added', 0)} additional PHI\n"
        detailed_rationale += f"• Model: Gemini {ai_stats.get('model', 'unknown')}\n"
    
    # Map sensitivity level to risk level
    risk_level_map = {
        'extreme': 'high',
        'high': 'high',
        'moderate': 'moderate',
        'low': 'low'
    }
    risk_level = risk_level_map[sensitivity_level]
    
    # Create text preview
    text_preview = text[:500] + '...' if len(text) > 500 else text
    
    return {
        'filename': file.name,
        'file_size': f"{file.size / 1024:.2f} KB",
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'findings': findings,
        'risk_level': risk_level,
        'risk_score': risk_score,
        'sensitivity_level': sensitivity_level,
        'text_preview': text_preview,
        'full_text': text,
        'sensitive_content': sensitive_content,
        'data_categories': data_categories,
        'detailed_rationale': detailed_rationale,
        'ai_stats': ai_stats,
        'ai_analysis': doc_analysis
    }

def redact_text(text: str, findings: List[Dict]) -> str:
    """Redact PHI from text"""
    # Sort findings by position (reverse order to maintain positions)
    sorted_findings = sorted(findings, key=lambda x: x['position'][0], reverse=True)
    
    redacted_text = text
    for finding in sorted_findings:
        start, end = finding['position']
        redacted_text = redacted_text[:start] + '[REDACTED]' + redacted_text[end:]
    
    return redacted_text

def generate_hipaa_compliance_summary(phi_findings: List[Dict]) -> Dict:
    """Generate a HIPAA compliance summary showing all 18 identifiers"""
    found_identifiers = set()
    
    # Map findings to HIPAA identifier numbers
    for finding in phi_findings:
        phi_type = finding['type'].replace(' ', '_')
        if phi_type in PHI_PATTERNS:
            hipaa_id = PHI_PATTERNS[phi_type].get('hipaa_identifier')
            if hipaa_id:
                found_identifiers.add(hipaa_id)
    
    # Create compliance summary
    compliance_summary = {}
    for id_num, description in HIPAA_IDENTIFIERS.items():
        compliance_summary[id_num] = {
            'description': description,
            'found': id_num in found_identifiers,
            'status': '✅ DETECTED' if id_num in found_identifiers else '⚪ NOT FOUND'
        }
    
    return compliance_summary

def generate_report_content(result: Dict) -> str:
    """Generate a detailed PHI scan report with enhanced sensitivity analysis"""
    sensitivity_level = result.get('sensitivity_level', 'unknown')
    
    report = f"""# PHI Scan Report

## Document Information
- **Filename:** {result['filename']}
- **File Size:** {result['file_size']}
- **Scan Date:** {result['timestamp']}
- **Risk Level:** {result['risk_level'].upper()}
- **Sensitivity Level:** {sensitivity_level.upper()}
- **Risk Score:** {result['risk_score']}/100

## Executive Summary
This document was scanned for Protected Health Information (PHI) as defined by HIPAA regulations. 
The scan identified **{len(result['findings'])}** potential PHI element(s) with a risk assessment of **{result['risk_level'].upper()}** and sensitivity level of **{sensitivity_level.upper()}**.

## HIPAA Identifier Compliance Checklist
"""
    
    # Add HIPAA compliance summary
    compliance_summary = generate_hipaa_compliance_summary(result['findings'])
    
    report += "\n| HIPAA ID | Identifier Type | Status |\n"
    report += "|----------|----------------|--------|\n"
    
    for id_num in sorted(compliance_summary.keys()):
        item = compliance_summary[id_num]
        report += f"| {id_num} | {item['description']} | {item['status']} |\n"
    
    # Count found vs total
    found_count = sum(1 for item in compliance_summary.values() if item['found'])
    report += f"\n**Total HIPAA Identifiers Found: {found_count} of 18**\n"
    
    report += "\n## Sensitivity Analysis\n"
    report += result.get('detailed_rationale', 'No detailed analysis available.')
    
    report += "\n## PHI Findings Details\n"
    
    if result['findings']:
        # Group findings by type
        findings_by_type = {}
        for finding in result['findings']:
            phi_type = finding['type']
            if phi_type not in findings_by_type:
                findings_by_type[phi_type] = []
            findings_by_type[phi_type].append(finding)
        
        # Report each type
        for phi_type, findings in findings_by_type.items():
            report += f"\n### {phi_type} ({len(findings)} instance(s))\n"
            report += f"- **Risk Priority:** {findings[0].get('priority', 'medium').upper()}\n"
            report += f"- **Instances Found:**\n"
            for i, finding in enumerate(findings, 1):
                report += f"  {i}. {finding['value']} (Confidence: {finding['confidence']}%"
                if finding.get('ai_verified'):
                    report += " - AI Verified ✅"
                elif finding.get('ai_discovered'):
                    report += " - AI Discovered 🤖"
                report += ")\n"
    else:
        report += "\n*No PHI elements were detected in this document.*\n"
    
    # Add AI analysis if available
    if 'ai_stats' in result and result['ai_stats']:
        report += "\n## AI Analysis Summary\n"
        ai_stats = result['ai_stats']
        report += f"- **Model Used:** Gemini {ai_stats.get('model', 'unknown')}\n"
        report += f"- **Verified:** {ai_stats.get('verified', 0)} findings confirmed as true PHI\n"
        report += f"- **Rejected:** {ai_stats.get('rejected', 0)} false positives filtered out\n"
        report += f"- **Discovered:** {ai_stats.get('added', 0)} additional PHI found by AI\n"
    
    # Add sensitive content findings if present
    if 'sensitive_content' in result and result['sensitive_content']:
        report += "\n## Sensitive Content Detected\n"
        for content_type, matches in result['sensitive_content'].items():
            if matches:
                report += f"\n### {content_type.replace('_', ' ').title()}\n"
                report += f"- **Instances:** {len(matches)}\n"
                report += f"- **Sensitivity:** {SENSITIVE_CONTENT_PATTERNS[content_type]['sensitivity'].upper()}\n"
    
    # Enhanced recommendations based on sensitivity
    report += "\n## Recommendations\n"
    if sensitivity_level == 'extreme':
        report += """### ⚠️ EXTREME SENSITIVITY - CRITICAL HANDLING REQUIRED ⚠️
- **IMMEDIATE COMPLIANCE REVIEW**: This document contains extremely sensitive information requiring special handling.
- **RESTRICTED ACCESS**: Implement role-based access control with documented authorization.
- **ENHANCED ENCRYPTION**: Use FIPS 140-2 Level 3 or higher encryption standards.
- **SPECIAL PROTOCOLS**: Follow organizational protocols for mental health, domestic violence, or legal matters.
- **MANDATORY REPORTING**: Review for any mandatory reporting obligations.
- **AUDIT REQUIREMENTS**: Maintain detailed access logs with justification for each access.
- **RETENTION POLICIES**: Apply special retention/destruction policies as required.
- **LEGAL CONSULTATION**: Consider legal review before any external sharing."""
    elif result['risk_level'] == 'high':
        report += """- **IMMEDIATE ACTION REQUIRED**: This document contains high-risk PHI elements.
- Ensure proper encryption when storing or transmitting this document.
- Limit access to authorized personnel only.
- Consider redacting sensitive information before sharing.
- Log all access to this document for HIPAA compliance."""
    elif result['risk_level'] == 'moderate':
        report += """- This document contains moderate-risk PHI elements.
- Apply standard PHI handling procedures.
- Ensure secure transmission channels are used.
- Verify recipient authorization before sharing."""
    else:
        report += """- This document contains low-risk PHI elements.
- Follow standard privacy protocols.
- Maintain audit trails as per organizational policy."""
    
    # Add compliance notes
    report += """\n\n## Compliance Notes
- This scan was performed using pattern-based detection algorithms with enhanced sensitivity analysis.
- **All 18 HIPAA identifiers have been checked**, even if not all were detected in this document.
- Results should be reviewed by qualified personnel for accuracy.
- Special attention required for any mental health, substance abuse, HIV/AIDS, or domestic violence information.
- This report is for internal use only and contains sensitive information.
- Retain this report as per your organization's HIPAA documentation requirements.

### Protected Information Categories
The following types of information require special handling under federal and state regulations:
- Mental Health Records (42 CFR Part 2, state laws)
- Substance Abuse Treatment (42 CFR Part 2)
- HIV/AIDS Information (state-specific laws)
- Reproductive Health (state-specific laws)
- Domestic Violence (VAWA, state laws)
- Minor's Information (COPPA, state laws)

---
*Generated by Sentinel PHI Scanner v2.0 - Enhanced with Gemini AI*"""
    
    return report

# Main App Layout
st.title("🔐 Sentinel: AI PHI Risk Scanner")
st.markdown("**Protect patient privacy with intelligent PHI detection and risk assessment**")

# Sidebar
with st.sidebar:
    st.header("📊 Dashboard Stats")
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Files Scanned", st.session_state.total_files_scanned)
    with col2:
        st.metric("High Risk", st.session_state.high_risk_count, 
                 delta=None if st.session_state.high_risk_count == 0 else "⚠️")
    
    st.metric("Total PHI Found", st.session_state.total_phi_found)
    
    st.divider()
    
    st.header("⚙️ Settings")
    
    # Scan sensitivity
    sensitivity = st.select_slider(
        "Detection Sensitivity",
        options=['Low', 'Medium', 'High'],
        value='Medium',
        help="Low: 80%+ confidence, Medium: 60%+ confidence, High: 40%+ confidence"
    )
    
    # Confidence threshold based on sensitivity
    confidence_thresholds = {'Low': 80, 'Medium': 60, 'High': 40}
    min_confidence = confidence_thresholds[sensitivity]
    
    # AI Settings Section
    if AI_AVAILABLE:
        st.subheader("🤖 Gemini AI Enhancement")
        
        use_ai = st.checkbox(
            "Enable AI Verification",
            value=True,
            help="Use Google's Gemini AI to verify findings and reduce false positives"
        )
        
        if use_ai:
            st.session_state.ai_enabled = True
            
            ai_model = st.radio(
                "AI Model",
                ["flash", "pro"],
                index=0,
                help="Flash: Faster & free tier available | Pro: More accurate but limited free usage"
            )
            
            ai_confidence_threshold = st.slider(
                "AI Confidence Threshold",
                min_value=50,
                max_value=95,
                value=70,
                step=5,
                help="Minimum AI confidence to accept a PHI finding"
            )
            
            find_missed_phi = st.checkbox(
                "AI Discovery Mode",
                value=True,
                help="Let AI search for PHI that regex patterns might miss"
            )
            
            # Show AI stats
            if st.session_state.ai_verification_count > 0:
                st.metric("AI Verifications", st.session_state.ai_verification_count)
            if st.session_state.ai_findings_count > 0:
                st.metric("AI Discoveries", st.session_state.ai_findings_count)
        else:
            st.session_state.ai_enabled = False
            use_ai = False
            ai_model = "flash"
            ai_confidence_threshold = 70
            find_missed_phi = False
    else:
        st.warning("🔧 Gemini AI not configured")
        with st.expander("Setup Instructions"):
            st.markdown("""
            1. Get a free API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
            2. Add to your `.streamlit/secrets.toml`:
            ```
            GEMINI_API_KEY = "your-api-key-here"
            ```
            3. Restart the app
            """)
        use_ai = False
        ai_model = "flash"
        ai_confidence_threshold = 70
        find_missed_phi = False
    
    # Rest of existing sidebar settings
    auto_redact = st.checkbox("Auto-redact PHI in reports", value=False)
    show_confidence = st.checkbox("Show confidence scores", value=True)
    allow_phi_reveal = st.checkbox(
        "Allow PHI reveal", 
        value=True, 
        help="Enable buttons to reveal actual PHI values. Use with caution!"
    )
    debug_mode = st.checkbox("Debug mode", value=False, help="Show raw extracted text and pattern matching details")
    
    # Export format
    export_format = st.selectbox(
        "Export Format",
        ['PDF', 'CSV', 'JSON']
    )

# Main content area
# Create tabs
tab1, tab2, tab3 = st.tabs(["📤 Upload & Scan", "📋 Scan History", "📊 Analytics"])

with tab1:
    # Check if we should show results or upload
    if st.session_state.current_results:
        # Results View
        st.header("📄 Scan Results")
        
        # Action buttons at the top
        col1, col2 = st.columns([1, 5])
        with col1:
            if st.button("🔙 Back to Upload", key="back_to_upload"):
                st.session_state.current_results = []
                st.rerun()
        
        with col2:
            if st.button("🗑️ Clear All Results", key="clear_all_results"):
                st.session_state.current_results = []
                st.rerun()
        
        # Summary Statistics
        high_risk_files = [r for r in st.session_state.current_results if r['risk_level'] == 'high']
        moderate_risk_files = [r for r in st.session_state.current_results if r['risk_level'] == 'moderate']
        low_risk_files = [r for r in st.session_state.current_results if r['risk_level'] == 'low']
        
        # Alert Box for High Risk Files
        if high_risk_files:
            st.error(f"""
            🚨 **ATTENTION: {len(high_risk_files)} HIGH-RISK FILE(S) DETECTED**
            
            These files contain sensitive PHI and require immediate security measures. 
            Review handling recommendations below and notify your compliance officer.
            """)
        
        # Summary Metrics
        st.markdown("### 📊 Scan Summary")
        sum_col1, sum_col2, sum_col3, sum_col4 = st.columns(4)
        
        with sum_col1:
            st.metric(
                "Total Files Scanned", 
                len(st.session_state.current_results),
                delta=None
            )
        
        with sum_col2:
            st.metric(
                "High Risk", 
                len(high_risk_files),
                delta=None if not high_risk_files else "⚠️",
                delta_color="inverse"
            )
        
        with sum_col3:
            st.metric(
                "Moderate Risk", 
                len(moderate_risk_files),
                delta=None
            )
        
        with sum_col4:
            st.metric(
                "Low Risk", 
                len(low_risk_files),
                delta=None
            )
        
        st.divider()
        
        # Display results
        for idx, result in enumerate(st.session_state.current_results):
            # Create unique container for each result
            with st.container():
                # Result header
                st.subheader(f"📄 {result['filename']}")
                
                # Prominent Risk Assessment Box with Enhanced Sensitivity
                risk_level = result['risk_level']
                sensitivity_level = result.get('sensitivity_level', 'unknown')
                
                # Enhanced risk configurations with sensitivity levels
                risk_configs = {
                    'high': {
                        'color': '#ff4757',
                        'bg_color': '#ffebee',
                        'icon': '🚨',
                        'label': 'HIGH RISK',
                        'action': 'IMMEDIATE ACTION REQUIRED',
                        'recommendations': [
                            '🔒 **Encrypt immediately** - This file must be encrypted at rest and in transit',
                            '👤 **Restrict access** - Limit to authorized personnel only',
                            '📝 **Log all access** - Document who accesses this file and when',
                            '🔐 **Consider redaction** - Remove PHI before sharing externally',
                            '⚡ **Report to compliance** - Notify your HIPAA compliance officer'
                        ]
                    },
                    'moderate': {
                        'color': '#ff9f43',
                        'bg_color': '#fff8e1',
                        'icon': '⚠️',
                        'label': 'MODERATE RISK',
                        'action': 'STANDARD PHI PROTOCOLS APPLY',
                        'recommendations': [
                            '🔒 **Apply standard encryption** - Use organizational encryption standards',
                            '✅ **Verify recipient authorization** - Confirm BAA is in place',
                            '📧 **Use secure channels** - Send via encrypted email or secure portal',
                            '📋 **Follow PHI procedures** - Apply your organization\'s standard protocols',
                            '🗂️ **Maintain audit trail** - Keep records of file handling'
                        ]
                    },
                    'low': {
                        'color': '#10ac84',
                        'bg_color': '#e8f5e9',
                        'icon': '✅',
                        'label': 'LOW RISK',
                        'action': 'MINIMAL PHI DETECTED',
                        'action_color': '#2e7d32',  # Dark green for better readability
                        'recommendations': [
                            '✅ **Follow basic protocols** - Standard privacy measures apply',
                            '🔍 **Review before sharing** - Quick check before external distribution',
                            '📁 **Store securely** - Use standard secure storage',
                            '📝 **Document as needed** - Follow organizational policies',
                            '👍 **Safe for most uses** - Minimal PHI exposure risk'
                        ]
                    }
                }
                
                # Special handling for extreme sensitivity
                if sensitivity_level == 'extreme':
                    risk_configs['high']['label'] = 'EXTREME SENSITIVITY'
                    risk_configs['high']['action'] = 'CRITICAL - REQUIRES SPECIAL HANDLING'
                    risk_configs['high']['color'] = '#d32f2f'
                    risk_configs['high']['recommendations'] = [
                        '🚨 **EXTREME CAUTION REQUIRED** - Contains highly sensitive information',
                        '🔐 **Maximum encryption** - Use highest available encryption standards',
                        '⛔ **Strictly limited access** - Only specifically authorized personnel',
                        '📋 **Special handling protocols** - Follow mental health/DV/legal procedures',
                        '🚔 **Legal compliance** - May be subject to mandatory reporting',
                        '📝 **Detailed audit trail** - Document all access and sharing',
                        '⚡ **Immediate supervisor notification** - Alert compliance and management'
                    ]
                
                config = risk_configs[risk_level]
                
                # Risk Assessment Card
                st.markdown(f"""
                <div style="
                    background-color: {config['bg_color']};
                    border-left: 5px solid {config['color']};
                    padding: 20px;
                    border-radius: 10px;
                    margin: 20px 0;
                ">
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <div>
                            <h2 style="color: {config['color']}; margin: 0;">
                                {config['icon']} {config['label']}
                            </h2>
                            <p style="font-size: 16px; font-weight: bold; margin: 10px 0 0 0; color: {config.get('action_color', '#333')};">
                                {config['action']}
                            </p>
                        </div>
                        <div style="text-align: right;">
                            <div style="font-size: 48px; font-weight: bold; color: {config['color']};">
                                {result['risk_score']}
                            </div>
                            <div style="font-size: 14px; color: #666;">Risk Score</div>
                            <div style="font-size: 12px; color: {config['color']}; font-weight: bold;">
                                {sensitivity_level.upper()} SENSITIVITY
                            </div>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                # Sensitivity Analysis Details
                if 'detailed_rationale' in result:
                    with st.expander("🔍 **Sensitivity Analysis**", expanded=sensitivity_level in ['high', 'extreme']):
                        st.markdown("### Detailed Risk Assessment")
                        st.text(result['detailed_rationale'])
                        
                        # Show data categories if available
                        if 'data_categories' in result:
                            st.markdown("### Data Categories Identified:")
                            categories = result['data_categories']
                            for category, items in categories.items():
                                if items:
                                    st.markdown(f"**{category.replace('_', ' ').title()}:** {', '.join(set(items))}")
                
                # Handling Recommendations
                with st.expander("📋 **Handling Recommendations**", expanded=risk_level in ['high', 'moderate']):
                    st.markdown("### How to Handle This File:")
                    for rec in config['recommendations']:
                        st.markdown(rec)
                
                # File info in a cleaner layout
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("File Size", result['file_size'])
                with col2:
                    st.metric("PHI Elements", len(result['findings']))
                with col3:
                    phi_types = len(set(f['type'] for f in result['findings'])) if result['findings'] else 0
                    st.metric("PHI Types", phi_types)
                with col4:
                    high_priority = len([f for f in result['findings'] if f.get('priority') == 'high'])
                    st.metric("High Priority", high_priority)
                
                # PHI Findings
                if result['findings']:
                    st.markdown("### 🔍 PHI Elements Detected")
                    
                    # Initialize session state for revealing PHI
                    if 'reveal_phi' not in st.session_state:
                        st.session_state.reveal_phi = {}
                    
                    # Create a unique key for this result
                    result_key = f"{idx}_{result['filename']}"
                    
                    # Create findings dataframe with reveal functionality
                    findings_data = []
                    for i, finding in enumerate(result['findings']):
                        finding_key = f"{result_key}_{i}"
                        
                        # Check if this PHI should be revealed
                        if finding_key not in st.session_state.reveal_phi:
                            st.session_state.reveal_phi[finding_key] = False
                        
                        # Show either redacted or original value based on state
                        display_value = finding.get('original_value', finding['value']) if st.session_state.reveal_phi[finding_key] else finding['value']
                        
                        findings_data.append({
                            'Type': finding['type'],
                            'Description': finding['description'],
                            'Value': display_value,
                            'Confidence %': finding['confidence'],
                            'finding_key': finding_key,
                            'is_revealed': st.session_state.reveal_phi[finding_key],
                            'ai_verified': finding.get('ai_verified', False),
                            'ai_discovered': finding.get('ai_discovered', False)
                        })
                    
                    # Display findings with reveal buttons and AI indicators
                    for i, row in enumerate(findings_data):
                        col1, col2, col3, col4, col5 = st.columns([2, 3, 3, 1.5, 1.5])
                        
                        with col1:
                            # Show AI indicator
                            if row['ai_verified']:
                                st.markdown(f"<span class='ai-verified'>✅ {row['Type']}</span>", unsafe_allow_html=True)
                            elif row['ai_discovered']:
                                st.markdown(f"<span class='ai-discovered'>🤖 {row['Type']}</span>", unsafe_allow_html=True)
                            else:
                                st.text(row['Type'])
                        with col2:
                            st.text(row['Description'])
                        with col3:
                            if row['is_revealed']:
                                st.markdown(f"<span style='color: #ff6b6b; font-weight: bold;'>{row['Value']}</span>", unsafe_allow_html=True)
                            else:
                                st.text(row['Value'])
                        with col4:
                            st.text(f"{row['Confidence %']}%")
                        with col5:
                            if allow_phi_reveal:
                                if st.button(
                                    "🔓 Show" if not row['is_revealed'] else "🔒 Hide",
                                    key=f"reveal_btn_{row['finding_key']}",
                                    help="Click to reveal/hide the actual PHI value"
                                ):
                                    st.session_state.reveal_phi[row['finding_key']] = not row['is_revealed']
                                    st.rerun()
                            else:
                                st.text("🔒")
                    
                    # Warning when PHI is revealed
                    if any(st.session_state.reveal_phi.values()):
                        st.warning("⚠️ **Warning**: Actual PHI values are being displayed. Ensure you are in a secure environment.")
                    
                    # Add HIPAA Compliance Summary
                    st.markdown("### 📋 HIPAA Identifier Compliance")
                    compliance_summary = generate_hipaa_compliance_summary(result['findings'])
                    
                    # Create two columns for the compliance checklist
                    comp_col1, comp_col2 = st.columns(2)
                    
                    with comp_col1:
                        st.markdown("**Identifiers 1-9:**")
                        for i in range(1, 10):
                            if i in compliance_summary:
                                item = compliance_summary[i]
                                st.markdown(f"{item['status']} {item['description']}")
                    
                    with comp_col2:
                        st.markdown("**Identifiers 10-18:**")
                        for i in range(10, 19):
                            if i in compliance_summary:
                                item = compliance_summary[i]
                                st.markdown(f"{item['status']} {item['description']}")
                    
                    # Summary count
                    found_count = sum(1 for item in compliance_summary.values() if item['found'])
                    st.info(f"**Total HIPAA Identifiers Found: {found_count} of 18**")
                    
                    # Export Options in a clean layout
                    st.markdown("### 📥 Export Options")
                    
                    # Generate report content once
                    report_content = generate_report_content(result)
                    
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        # Markdown Report
                        report_bytes = report_content.encode('utf-8')
                        report_filename = f"PHI_Report_{result['filename'].split('.')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
                        
                        st.download_button(
                            label="📄 Markdown Report",
                            data=report_bytes,
                            file_name=report_filename,
                            mime="text/markdown",
                            key=f"md_{idx}_{result['filename']}"
                        )
                    
                    with col2:
                        # CSV
                        csv_df = pd.DataFrame(result['findings'])
                        if not csv_df.empty:
                            csv_df = csv_df[['type', 'description', 'value', 'confidence']]
                            csv_df.columns = ['Type', 'Description', 'Redacted Value', 'Confidence %']
                            csv_data = csv_df.to_csv(index=False)
                        else:
                            csv_data = "Type,Description,Redacted Value,Confidence %\n"
                        
                        csv_filename = f"PHI_Findings_{result['filename'].split('.')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                        
                        st.download_button(
                            label="📊 CSV Data",
                            data=csv_data,
                            file_name=csv_filename,
                            mime="text/csv",
                            key=f"csv_{idx}_{result['filename']}"
                        )
                    
                    with col3:
                        # JSON
                        json_data = json.dumps(result['findings'], indent=2)
                        json_filename = f"PHI_Findings_{result['filename'].split('.')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                        
                        st.download_button(
                            label="🗂️ JSON Data",
                            data=json_data,
                            file_name=json_filename,
                            mime="application/json",
                            key=f"json_{idx}_{result['filename']}"
                        )
                    
                    with col4:
                        # Redacted Document
                        if 'full_text' in result:
                            redacted = redact_text(result['full_text'], result['findings'])
                            # Force .txt extension for redacted files
                            base_name = result['filename'].split('.')[0]
                            redacted_filename = f"REDACTED_{base_name}.txt"
                            
                            st.download_button(
                                label="🔒 Redacted Doc (TXT)",
                                data=redacted,
                                file_name=redacted_filename,
                                mime="text/plain",
                                key=f"redacted_{idx}_{result['filename']}",
                                help="Redacted version saved as plain text format"
                            )
                
                else:
                    st.success("✅ No PHI detected in this document")
                
                st.divider()
    
    else:
        # Upload View
        st.header("Upload Documents for PHI Scanning")
        
        uploaded_files = st.file_uploader(
            "Drop files here or click to upload",
            type=['txt', 'pdf', 'doc', 'docx'],
            accept_multiple_files=True,
            help="Supports PDF, TXT, DOC files • Simulates fax intake"
        )
        
        if uploaded_files:
            # Process button
            if st.button("🔍 Scan for PHI", type="primary"):
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                results = []
                for idx, file in enumerate(uploaded_files):
                    status_text.text(f"Scanning {file.name}...")
                    progress_bar.progress((idx + 1) / len(uploaded_files))
                    
                    # Process file with AI settings
                    result = process_file(
                        file, 
                        min_confidence,
                        debug_mode,
                        use_ai=use_ai,
                        ai_model=ai_model,
                        ai_confidence_threshold=ai_confidence_threshold,
                        find_missed_phi=find_missed_phi
                    )
                    results.append(result)
                    
                    # Update session state
                    st.session_state.scan_history.append(result)
                    st.session_state.total_files_scanned += 1
                    if result['risk_level'] == 'high':
                        st.session_state.high_risk_count += 1
                    st.session_state.total_phi_found += len(result['findings'])
                    
                    time.sleep(0.5)  # Simulate processing time
                
                progress_bar.empty()
                status_text.empty()
                
                # Store results and trigger rerun to show them
                st.session_state.current_results = results
                st.rerun()

with tab2:
    st.header("📋 Scan History")
    
    if st.session_state.scan_history:
        # Create history dataframe
        history_data = []
        for scan in st.session_state.scan_history:
            history_data.append({
                'Timestamp': scan['timestamp'],
                'Filename': scan['filename'],
                'Risk Level': scan['risk_level'].upper(),
                'PHI Found': len(scan['findings']),
                'Risk Score': scan['risk_score']
            })
        
        history_df = pd.DataFrame(history_data)
        
        # Filter options
        col1, col2 = st.columns([1, 3])
        with col1:
            risk_filter = st.multiselect(
                "Filter by Risk Level",
                ['HIGH', 'MODERATE', 'LOW'],
                default=['HIGH', 'MODERATE', 'LOW']
            )
        
        # Apply filters
        filtered_df = history_df[history_df['Risk Level'].isin(risk_filter)]
        
        # Display filtered history
        st.dataframe(
            filtered_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Risk Level": st.column_config.TextColumn(
                    "Risk Level",
                    help="Risk assessment based on PHI findings"
                ),
                "Risk Score": st.column_config.ProgressColumn(
                    "Risk Score",
                    help="Overall risk score (0-100)",
                    format="%d",
                    min_value=0,
                    max_value=100,
                ),
            }
        )
        
        # Export history button
        if st.button("📥 Export Full History"):
            csv = filtered_df.to_csv(index=False)
            st.download_button(
                label="Download History CSV",
                data=csv,
                file_name=f"phi_scan_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    else:
        st.info("No scan history yet. Upload and scan some documents to get started!")

with tab3:
    st.header("📊 PHI Detection Analytics")
    
    if st.session_state.scan_history:
        # Risk distribution
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Risk Level Distribution")
            risk_counts = pd.DataFrame(st.session_state.scan_history)['risk_level'].value_counts()
            st.bar_chart(risk_counts)
        
        with col2:
            st.subheader("PHI Types Detected")
            all_types = []
            for scan in st.session_state.scan_history:
                all_types.extend([f['type'] for f in scan['findings']])
            
            if all_types:
                type_counts = pd.Series(all_types).value_counts()
                st.bar_chart(type_counts)
            else:
                st.info("No PHI detected yet")
        
        # Trend over time
        st.subheader("Detection Trends")
        if len(st.session_state.scan_history) > 1:
            trend_data = []
            for scan in st.session_state.scan_history:
                trend_data.append({
                    'Timestamp': pd.to_datetime(scan['timestamp']),
                    'PHI Count': len(scan['findings']),
                    'Risk Score': scan['risk_score']
                })
            
            trend_df = pd.DataFrame(trend_data)
            trend_df.set_index('Timestamp', inplace=True)
            
            st.line_chart(trend_df)
    else:
        st.info("No data available yet. Start scanning documents to see analytics!")

# Footer
st.divider()
st.markdown("""
<center>
    <small>
    🔐 Sentinel PHI Scanner v2.0 - Enhanced with Gemini AI | Built for HIIM Professionals<br>
    <em>Remember: This is a demonstration tool. Always follow your organization's PHI handling policies.</em>
    </small>
</center>
""", unsafe_allow_html=True)