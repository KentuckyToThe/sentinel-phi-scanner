"""
🔐 Sentinel: AI-Only PHI Risk Scanner
A Streamlit app for detecting Protected Health Information (PHI) using Gemini AI

Required packages:
pip install streamlit pandas PyPDF2 python-docx google-generativeai

Run with:
streamlit run sentinel_phi_scanner_ai_only.py
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
    page_title="Sentinel: AI PHI Scanner",
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
    .ai-finding {
        background-color: #e3f2fd;
        border-left: 4px solid #2196F3;
        padding: 10px;
        margin: 5px 0;
        border-radius: 4px;
    }
    .phi-highlight {
        background-color: #ffeb3b;
        padding: 2px 4px;
        border-radius: 3px;
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

# Initialize Gemini
try:
    GEMINI_API_KEY = st.secrets.get("GEMINI_API_KEY", os.getenv("GEMINI_API_KEY"))
    if GEMINI_API_KEY:
        genai.configure(api_key=GEMINI_API_KEY)
        flash_model = genai.GenerativeModel('gemini-1.5-flash')
        pro_model = genai.GenerativeModel('gemini-1.5-pro')
        AI_AVAILABLE = True
    else:
        AI_AVAILABLE = False
except Exception as e:
    AI_AVAILABLE = False
    st.error(f"Gemini initialization error: {e}")

# HIPAA identifiers for reference
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

def extract_json_from_gemini_response(response_text: str) -> Dict:
    """Extract JSON from Gemini response"""
    try:
        # Clean up response text
        response_text = response_text.strip()
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        
        # Try to parse JSON
        start_idx = response_text.find('{')
        end_idx = response_text.rfind('}') + 1
        if start_idx != -1 and end_idx != 0:
            json_str = response_text[start_idx:end_idx]
            return json.loads(json_str)
        
        return json.loads(response_text)
    except:
        return {}

def detect_phi_with_ai(text: str, model_name: str = "flash") -> Tuple[List[Dict], Dict]:
    """Pure AI-based PHI detection"""
    
    if not AI_AVAILABLE:
        st.error("AI is not available. Please configure your Gemini API key.")
        return [], {}
    
    model = flash_model if model_name == "flash" else pro_model
    
    # Process in chunks if text is very long
    chunk_size = 6000  # Larger chunks for better context
    findings = []
    
    for i in range(0, len(text), chunk_size):
        chunk = text[i:i + chunk_size]
        if i > 0:
            # Add overlap for context
            chunk = text[i-200:i+chunk_size]
        
        prompt = f"""You are an expert HIPAA compliance officer. Analyze this medical document section and identify ALL Protected Health Information (PHI).

DOCUMENT SECTION:
{chunk}

TASK: Find ALL instances of PHI according to HIPAA's 18 identifiers:

1. Names (patients, doctors, family members, any person mentioned)
2. Geographic locations (addresses, cities, landmarks, facility names)
3. Dates (birth, death, admission, discharge, appointments)
4. Phone/Fax numbers
5. Email addresses
6. Social Security numbers
7. Medical record numbers
8. Health plan/Insurance numbers
9. Account numbers
10. License numbers
11. Vehicle identifiers
12. Device serial numbers
13. URLs
14. IP addresses
15. Biometric identifiers
16. Photos/Images (if mentioned)
17. Any unique identifiers

IMPORTANT: Also identify:
- Indirect references ("the patient", "her daughter", "the attending physician")
- Contextual identifiers ("room 203", "bed 2", "the morning shift nurse")
- Partial information ("born in 1985", "lives on Main Street")
- Misspellings or variations

For each PHI instance found, provide:
{{
    "findings": [
        {{
            "type": "Specific PHI type from the 18 identifiers",
            "hipaa_identifier": number 1-18,
            "text": "exact text from document",
            "context": "surrounding text for context",
            "confidence": 0-100,
            "reasoning": "why this is PHI",
            "risk_level": "low/medium/high"
        }}
    ]
}}

Be thorough and err on the side of caution - it's better to flag potential PHI than miss it."""

        try:
            response = model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.1,
                    max_output_tokens=2048,
                )
            )
            
            result = extract_json_from_gemini_response(response.text)
            
            if result and 'findings' in result:
                for finding in result['findings']:
                    # Adjust position for chunk offset
                    finding['chunk_offset'] = i
                    finding['source'] = 'gemini_ai'
                    findings.append(finding)
                    
        except Exception as e:
            st.error(f"AI detection error: {e}")
            continue
    
    # Deduplicate findings
    unique_findings = []
    seen_texts = set()
    
    for finding in findings:
        text_key = finding.get('text', '').strip().lower()
        if text_key and text_key not in seen_texts:
            seen_texts.add(text_key)
            unique_findings.append(finding)
    
    # Calculate stats
    stats = {
        "total_findings": len(unique_findings),
        "chunks_processed": (len(text) + chunk_size - 1) // chunk_size,
        "model_used": model_name,
        "hipaa_categories_found": len(set(f.get('hipaa_identifier', 0) for f in unique_findings))
    }
    
    return unique_findings, stats

def analyze_document_sensitivity(text: str, findings: List[Dict], model_name: str = "flash") -> Dict:
    """Analyze overall document sensitivity and compliance requirements"""
    
    if not AI_AVAILABLE or not findings:
        return {}
    
    model = flash_model if model_name == "flash" else pro_model
    
    # Prepare findings summary
    findings_summary = []
    for f in findings[:30]:  # Limit to prevent token overflow
        findings_summary.append(f"{f.get('type', 'Unknown')}: {f.get('text', '')[:50]}")
    
    prompt = f"""As a HIPAA compliance expert, analyze this document's overall sensitivity and risks.

Document preview (first 2000 chars):
{text[:2000]}

PHI Found:
{chr(10).join(findings_summary)}

Total PHI instances: {len(findings)}

Provide comprehensive analysis:
{{
    "document_type": "specific type of medical document",
    "sensitivity_level": "low/moderate/high/extreme",
    "primary_concerns": ["list main privacy risks"],
    "compliance_requirements": ["specific HIPAA requirements"],
    "recommended_safeguards": ["security measures needed"],
    "sharing_restrictions": "who can access this document",
    "retention_period": "how long to keep",
    "special_handling": ["any special requirements"]
}}"""

    try:
        response = model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.3,
                max_output_tokens=1024,
            )
        )
        
        return extract_json_from_gemini_response(response.text)
        
    except Exception as e:
        st.error(f"Document analysis error: {e}")
        return {}

def calculate_risk_score(findings: List[Dict], doc_analysis: Dict) -> Tuple[str, int, str]:
    """Calculate risk score based on AI findings"""
    
    if not findings:
        return 'low', 0, "No PHI detected in document"
    
    # Base score on number and types of PHI
    base_score = min(len(findings) * 5, 50)  # Max 50 points for quantity
    
    # Add points for high-risk PHI types
    high_risk_types = {7, 8, 9, 10, 11}  # SSN, MRN, Insurance, Account, License
    high_risk_count = sum(1 for f in findings if f.get('hipaa_identifier', 0) in high_risk_types)
    risk_type_score = high_risk_count * 10
    
    # Add points for different categories found
    unique_categories = len(set(f.get('hipaa_identifier', 0) for f in findings))
    diversity_score = unique_categories * 3
    
    # Total score
    total_score = min(base_score + risk_type_score + diversity_score, 100)
    
    # Determine risk level
    if total_score >= 80 or high_risk_count >= 3:
        risk_level = 'high'
    elif total_score >= 50 or high_risk_count >= 1:
        risk_level = 'moderate'
    else:
        risk_level = 'low'
    
    # Build rationale
    rationale = f"Found {len(findings)} PHI instances across {unique_categories} HIPAA categories. "
    if high_risk_count > 0:
        rationale += f"Detected {high_risk_count} high-risk identifiers. "
    
    # Add AI insights if available
    if doc_analysis and 'sensitivity_level' in doc_analysis:
        ai_level = doc_analysis['sensitivity_level']
        if ai_level == 'extreme':
            risk_level = 'high'
            total_score = max(total_score, 90)
            rationale += "AI assessment indicates extreme sensitivity. "
        elif ai_level == 'high' and risk_level == 'moderate':
            total_score = max(total_score, 70)
    
    return risk_level, total_score, rationale

def extract_text_from_file(file) -> str:
    """Extract text from various file types"""
    text = ""
    
    try:
        if file.type == "application/pdf":
            pdf_reader = PyPDF2.PdfReader(file)
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                text += page.extract_text() + "\n"
                
        elif file.type == "text/plain":
            text = str(file.read(), 'utf-8')
            
        elif file.type in ["application/vnd.openxmlformats-officedocument.wordprocessingml.document", 
                          "application/msword"] and docx:
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

def process_file(file, ai_model: str = "flash") -> Dict:
    """Process uploaded file with AI-only PHI detection"""
    
    # Extract text from file
    text = extract_text_from_file(file)
    
    if not text:
        return {
            'filename': file.name,
            'file_size': f"{file.size / 1024:.2f} KB",
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'findings': [],
            'risk_level': 'low',
            'risk_score': 0,
            'error': 'Could not extract text from file'
        }
    
    # Detect PHI using AI
    with st.spinner(f"🤖 AI is analyzing document for PHI..."):
        findings, ai_stats = detect_phi_with_ai(text, ai_model)
        
        # Get document sensitivity analysis
        doc_analysis = analyze_document_sensitivity(text, findings, ai_model)
    
    # Calculate risk score
    risk_level, risk_score, risk_rationale = calculate_risk_score(findings, doc_analysis)
    
    # Create text preview
    text_preview = text[:500] + '...' if len(text) > 500 else text
    
    return {
        'filename': file.name,
        'file_size': f"{file.size / 1024:.2f} KB",
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'findings': findings,
        'risk_level': risk_level,
        'risk_score': risk_score,
        'risk_rationale': risk_rationale,
        'text_preview': text_preview,
        'full_text': text,
        'ai_stats': ai_stats,
        'doc_analysis': doc_analysis
    }

def generate_hipaa_compliance_summary(findings: List[Dict]) -> Dict:
    """Generate HIPAA compliance summary"""
    found_identifiers = set()
    
    for finding in findings:
        hipaa_id = finding.get('hipaa_identifier', 0)
        if hipaa_id > 0:
            found_identifiers.add(hipaa_id)
    
    compliance_summary = {}
    for id_num, description in HIPAA_IDENTIFIERS.items():
        compliance_summary[id_num] = {
            'description': description,
            'found': id_num in found_identifiers,
            'count': sum(1 for f in findings if f.get('hipaa_identifier', 0) == id_num),
            'status': '🔴 DETECTED' if id_num in found_identifiers else '✅ NOT FOUND'
        }
    
    return compliance_summary

def redact_text(text: str, findings: List[Dict]) -> str:
    """Redact PHI from text"""
    redacted = text
    
    # Sort findings by text length (longest first) to avoid partial replacements
    sorted_findings = sorted(findings, key=lambda x: len(x.get('text', '')), reverse=True)
    
    for finding in sorted_findings:
        phi_text = finding.get('text', '')
        if phi_text:
            redacted = redacted.replace(phi_text, '[REDACTED]')
    
    return redacted

# Main App Layout
st.title("🔐 Sentinel: AI-Powered PHI Scanner")
st.markdown("**Advanced PHI detection using Google's Gemini AI**")

# Check AI availability
if not AI_AVAILABLE:
    st.error("""
    ⚠️ **AI Configuration Required**
    
    This scanner requires Gemini AI to function. Please:
    1. Get a free API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
    2. Add it to `.streamlit/secrets.toml`:
    ```
    GEMINI_API_KEY = "your-api-key-here"
    ```
    3. Restart the app
    """)
    st.stop()

# Sidebar
with st.sidebar:
    st.header("📊 Dashboard")
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Files Scanned", st.session_state.total_files_scanned)
    with col2:
        st.metric("High Risk", st.session_state.high_risk_count)
    
    st.metric("Total PHI Found", st.session_state.total_phi_found)
    
    st.divider()
    
    st.header("🤖 AI Settings")
    
    ai_model = st.radio(
        "AI Model",
        ["flash", "pro"],
        index=0,
        help="Flash: Faster & larger free tier | Pro: More accurate"
    )
    
    show_confidence = st.checkbox("Show confidence scores", value=True)
    show_reasoning = st.checkbox("Show AI reasoning", value=True)
    
    st.divider()
    
    st.info("""
    **How it works:**
    - AI analyzes your entire document
    - Identifies all 18 HIPAA identifiers
    - Understands context and indirect references
    - No regex patterns needed!
    """)

# Main content
tab1, tab2, tab3 = st.tabs(["📤 Scan Documents", "📋 History", "📊 Analytics"])

with tab1:
    if st.session_state.current_results:
        # Results View
        st.header("🔍 Scan Results")
        
        # Back button
        if st.button("← Back to Upload"):
            st.session_state.current_results = []
            st.rerun()
        
        # Display results
        for result in st.session_state.current_results:
            with st.container():
                # File header
                st.subheader(f"📄 {result['filename']}")
                
                # Risk assessment
                risk_level = result['risk_level']
                risk_score = result['risk_score']
                
                if risk_level == 'high':
                    st.error(f"**HIGH RISK** - Score: {risk_score}/100")
                elif risk_level == 'moderate':
                    st.warning(f"**MODERATE RISK** - Score: {risk_score}/100")
                else:
                    st.success(f"**LOW RISK** - Score: {risk_score}/100")
                
                st.markdown(f"*{result.get('risk_rationale', '')}*")
                
                # File info
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("File Size", result['file_size'])
                with col2:
                    st.metric("PHI Found", len(result['findings']))
                with col3:
                    categories = len(set(f.get('hipaa_identifier', 0) for f in result['findings']))
                    st.metric("Categories", categories)
                with col4:
                    st.metric("AI Model", result.get('ai_stats', {}).get('model_used', 'unknown'))
                
                # Document Analysis
                if result.get('doc_analysis'):
                    with st.expander("📋 Document Analysis"):
                        analysis = result['doc_analysis']
                        
                        if 'document_type' in analysis:
                            st.write(f"**Document Type:** {analysis['document_type']}")
                        if 'sensitivity_level' in analysis:
                            st.write(f"**Sensitivity Level:** {analysis['sensitivity_level'].upper()}")
                        if 'primary_concerns' in analysis:
                            st.write("**Primary Concerns:**")
                            for concern in analysis['primary_concerns']:
                                st.write(f"- {concern}")
                        if 'recommended_safeguards' in analysis:
                            st.write("**Recommended Safeguards:**")
                            for safeguard in analysis['recommended_safeguards']:
                                st.write(f"- {safeguard}")
                
                # PHI Findings
                if result['findings']:
                    st.markdown("### 🔍 PHI Detected by AI")
                    
                    # Group by HIPAA identifier
                    findings_by_type = {}
                    for finding in result['findings']:
                        hipaa_id = finding.get('hipaa_identifier', 0)
                        if hipaa_id not in findings_by_type:
                            findings_by_type[hipaa_id] = []
                        findings_by_type[hipaa_id].append(finding)
                    
                    # Display findings
                    for hipaa_id, findings in sorted(findings_by_type.items()):
                        if hipaa_id in HIPAA_IDENTIFIERS:
                            st.markdown(f"**{HIPAA_IDENTIFIERS[hipaa_id]}** ({len(findings)} found)")
                            
                            for finding in findings[:5]:  # Show first 5
                                with st.container():
                                    col1, col2 = st.columns([3, 1])
                                    with col1:
                                        # Redact the actual value for display
                                        text = finding.get('text', '')
                                        if len(text) > 20:
                                            display_text = text[:5] + "..." + text[-5:]
                                        else:
                                            display_text = '*' * len(text)
                                        
                                        st.markdown(f"🔹 `{display_text}`")
                                        
                                        if show_reasoning and finding.get('reasoning'):
                                            st.caption(f"*{finding['reasoning']}*")
                                    
                                    with col2:
                                        if show_confidence:
                                            conf = finding.get('confidence', 0)
                                            st.metric("Confidence", f"{conf}%")
                            
                            if len(findings) > 5:
                                st.caption(f"*...and {len(findings) - 5} more*")
                    
                    # HIPAA Compliance Summary
                    st.markdown("### 📊 HIPAA Compliance Summary")
                    compliance = generate_hipaa_compliance_summary(result['findings'])
                    
                    # Create two columns
                    comp_col1, comp_col2 = st.columns(2)
                    
                    with comp_col1:
                        for i in range(1, 10):
                            if i in compliance:
                                item = compliance[i]
                                if item['count'] > 0:
                                    st.write(f"{item['status']} {item['description']} ({item['count']})")
                                else:
                                    st.write(f"{item['status']} {item['description']}")
                    
                    with comp_col2:
                        for i in range(10, 19):
                            if i in compliance:
                                item = compliance[i]
                                if item['count'] > 0:
                                    st.write(f"{item['status']} {item['description']} ({item['count']})")
                                else:
                                    st.write(f"{item['status']} {item['description']}")
                    
                    # Export options
                    st.markdown("### 📥 Export Options")
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        # Generate report
                        report = f"""# PHI Scan Report
Filename: {result['filename']}
Scan Date: {result['timestamp']}
Risk Level: {result['risk_level'].upper()}
Risk Score: {result['risk_score']}/100

## Summary
Total PHI Found: {len(result['findings'])}
HIPAA Categories: {len(set(f.get('hipaa_identifier', 0) for f in result['findings']))}

## Findings by Category
"""
                        for hipaa_id, findings in sorted(findings_by_type.items()):
                            if hipaa_id in HIPAA_IDENTIFIERS:
                                report += f"\n### {HIPAA_IDENTIFIERS[hipaa_id]}\n"
                                report += f"Count: {len(findings)}\n"
                        
                        st.download_button(
                            "📄 Download Report",
                            report,
                            f"phi_report_{result['filename']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                            mime="text/markdown"
                        )
                    
                    with col2:
                        # Export findings as JSON
                        findings_export = []
                        for f in result['findings']:
                            findings_export.append({
                                'type': HIPAA_IDENTIFIERS.get(f.get('hipaa_identifier', 0), 'Unknown'),
                                'text': '[REDACTED]',
                                'confidence': f.get('confidence', 0),
                                'risk_level': f.get('risk_level', 'unknown')
                            })
                        
                        st.download_button(
                            "📊 Export Findings",
                            json.dumps(findings_export, indent=2),
                            f"phi_findings_{result['filename']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                            mime="application/json"
                        )
                    
                    with col3:
                        # Redacted document
                        if 'full_text' in result:
                            redacted = redact_text(result['full_text'], result['findings'])
                            st.download_button(
                                "🔒 Redacted Document",
                                redacted,
                                f"redacted_{result['filename']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                                mime="text/plain"
                            )
                
                else:
                    st.success("✅ No PHI detected by AI")
                
                st.divider()
    
    else:
        # Upload View
        st.header("Upload Documents for AI PHI Scanning")
        
        st.info("""
        🤖 **AI-Powered Detection**
        
        This scanner uses advanced AI to:
        - Find all 18 HIPAA identifiers
        - Understand context ("the patient", "her daughter")
        - Catch subtle references and partial information
        - Identify indirect PHI that traditional scanners miss
        """)
        
        uploaded_files = st.file_uploader(
            "Choose files to scan",
            type=['txt', 'pdf', 'doc', 'docx'],
            accept_multiple_files=True,
            help="Upload medical documents for PHI scanning"
        )
        
        if uploaded_files:
            if st.button("🔍 Scan with AI", type="primary", use_container_width=True):
                results = []
                
                progress_bar = st.progress(0)
                
                for idx, file in enumerate(uploaded_files):
                    progress_bar.progress((idx + 1) / len(uploaded_files))
                    
                    # Process file
                    result = process_file(file, ai_model)
                    results.append(result)
                    
                    # Update stats
                    st.session_state.scan_history.append(result)
                    st.session_state.total_files_scanned += 1
                    if result['risk_level'] == 'high':
                        st.session_state.high_risk_count += 1
                    st.session_state.total_phi_found += len(result['findings'])
                
                progress_bar.empty()
                
                # Show results
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
        
        df = pd.DataFrame(history_data)
        
        # Display with styling
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Risk Score": st.column_config.ProgressColumn(
                    "Risk Score",
                    help="Overall risk score",
                    format="%d",
                    min_value=0,
                    max_value=100,
                ),
                "Risk Level": st.column_config.TextColumn(
                    "Risk Level",
                    help="Risk assessment"
                ),
            }
        )
        
        # Export option
        if st.button("📥 Export History"):
            csv = df.to_csv(index=False)
            st.download_button(
                "Download CSV",
                csv,
                f"phi_scan_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    else:
        st.info("No scan history yet. Upload documents to get started!")

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
            st.subheader("HIPAA Categories Found")
            all_categories = []
            for scan in st.session_state.scan_history:
                for finding in scan['findings']:
                    hipaa_id = finding.get('hipaa_identifier', 0)
                    if hipaa_id in HIPAA_IDENTIFIERS:
                        all_categories.append(HIPAA_IDENTIFIERS[hipaa_id])
            
            if all_categories:
                category_counts = pd.Series(all_categories).value_counts().head(10)
                st.bar_chart(category_counts)
            else:
                st.info("No PHI categories detected yet")
        
        # Trends
        st.subheader("Detection Trends")
        trend_data = []
        for scan in st.session_state.scan_history:
            trend_data.append({
                'Timestamp': pd.to_datetime(scan['timestamp']),
                'PHI Count': len(scan['findings']),
                'Risk Score': scan['risk_score']
            })
        
        if trend_data:
            trend_df = pd.DataFrame(trend_data).set_index('Timestamp')
            st.line_chart(trend_df)
    else:
        st.info("No data available yet. Start scanning documents to see analytics!")

# Footer
st.divider()
st.caption("""
🔐 Sentinel AI PHI Scanner | Powered by Google Gemini
*This is an AI-powered tool. Always verify results and follow your organization's compliance policies.*
""")