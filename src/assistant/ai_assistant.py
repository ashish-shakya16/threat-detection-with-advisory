"""
AI Security Assistant Module
Provides intelligent responses to security queries using context from the system
"""

import json
import os
from typing import Dict, List, Any
from datetime import datetime, timezone

# Langchain and RAG imports
try:
    from langchain_huggingface import HuggingFaceEndpoint, HuggingFaceEmbeddings
    from langchain_community.vectorstores import Chroma
    from langchain_core.documents import Document
    from langchain_core.prompts import PromptTemplate
    from langchain_core.output_parsers import StrOutputParser
    RAG_ENABLED = True
except ImportError:
    RAG_ENABLED = False


class AIAssistant:
    """AI-powered security assistant using Hugging Face RAG"""
    
    def __init__(self, db_manager, config: Dict = None):
        """Initialize the AI assistant"""
        self.db = db_manager
        self.config = config or {}
        self.context_window = []  # Store conversation context
        self.rag_enabled = False
        
        if RAG_ENABLED:
            try:
                self._setup_rag()
                self.rag_enabled = True
            except Exception as e:
                print(f"Failed to initialize RAG: {e}")
                
    def _setup_rag(self):
        """Set up Langchain, Embeddings, LLM, and Vector Database"""
        # Set the Hugging Face API key
        os.environ["HUGGINGFACEHUB_API_TOKEN"] = "REMOVED_SECRET"
        
        # 1. Setup the LLM endpoint
        from langchain_huggingface import HuggingFaceEndpoint, ChatHuggingFace
        hf_endpoint = HuggingFaceEndpoint(
            repo_id="Qwen/Qwen2.5-72B-Instruct",
            max_new_tokens=512,
            temperature=0.3,
        )
        self.llm = ChatHuggingFace(llm=hf_endpoint)
        
        # 2. Setup local embeddings model
        self.embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        
        # 3. Load Documents (Our rules.json data for context)
        docs = []
        if os.path.exists('config/rules.json'):
            with open('config/rules.json', 'r') as f:
                rules_data = json.load(f)
                for rule in rules_data.get('rules', []):
                        content = f"Rule ID: {rule.get('id', 'Unknown')} | Name: '{rule.get('name')}' | Description: Detects {rule.get('description')}. Category: {rule.get('category')}. Severity: {rule.get('severity')}."
        
        # Fallback empty doc if vector db needs initialization
        if not docs:
            docs.append(Document(page_content="System initialized with no specific rules.", metadata={"source": "system"}))
            
        # 4. Create and persist Chroma Vector Store
        os.makedirs("data/db", exist_ok=True)
        self.vectorstore = Chroma.from_documents(docs, self.embeddings, persist_directory="data/db/chroma_db")
        self.retriever = self.vectorstore.as_retriever(search_kwargs={"k": 3})
        
        # 5. Define the Prompt Template
        template = """You are SecureAI, a professional cybersecurity assistant. 
Use the following pieces of retrieved context and the provided recent system threats to answer the user's question.
If you don't know the answer or the context is insufficient, just say that you don't know, don't try to make up an answer.
Format your response using Markdown. Keep it concise, helpful, and professional.

Retrieved Knowledge/Rules Base Context:
{context}

Recent System Threats Context:
{threat_context}

User Question: {question}

Response:"""
        self.prompt = PromptTemplate.from_template(template)
        
    def process_query(self, user_message: str) -> str:
        """Process user query using RAG and generate response"""
        
        if not self.rag_enabled:
            return "⚠️ RAG is not fully initialized. Please ensure the required libraries are installed:\n`pip install langchain langchain-community langchain-huggingface chromadb sentence-transformers huggingface-hub`\nThen restart the dashboard."
        
        # Fetch dynamic context from the DB
        threats = self.db.get_recent_threats(hours=24)
        
        threat_context = "No recent threats detected."
        if threats:
            threat_context = "Recent Threats (Last 24h):\n" + "\n".join(
                [f"- {t.get('threat_name', 'Unknown Threat')} (Severity: {t.get('severity', 'Unknown')}) at {t.get('timestamp', '')}" for t in threats[:5]]
            )
            
        try:
            # Retrieve documents
            retrieved_docs = self.retriever.invoke(user_message)
            context_text = "\n".join([doc.page_content for doc in retrieved_docs])
            
            # Chain everything together & predict
            chain = self.prompt | self.llm | StrOutputParser()
            response = chain.invoke({
                "context": context_text,
                "threat_context": threat_context,
                "question": user_message
            })
            return response
            
        except Exception as e:
            return f"❌ Error generating response from AI model:\n{str(e)}\n\nMake sure your Hugging Face limit isn't reached and internet connection is active."

    
    def _greeting_response(self) -> str:
        """Generate greeting response"""
        return """Hello! I'm SecureAI, your cybersecurity assistant. I'm here to help you understand threats, provide security recommendations, and guide you through incident response.

**I can help you with:**
- Analyzing detected threats
- Security best practices
- Understanding risk levels
- Incident response steps
- System vulnerability assessment

What would you like to know?"""
    
    def _threat_summary_response(self, threats: List[Dict], stats: Dict) -> str:
        """Generate threat summary"""
        if not threats:
            return """✅ **Good news!** No threats have been detected in the last 24 hours.

**Your system appears secure**, but I recommend:
- Running regular security scans
- Keeping software up to date
- Monitoring system resources
- Reviewing security logs periodically"""
        
        critical = sum(1 for t in threats if t.get('severity') == 'Critical')
        high = sum(1 for t in threats if t.get('severity') == 'High')
        medium = sum(1 for t in threats if t.get('severity') == 'Medium')
        low = sum(1 for t in threats if t.get('severity') == 'Low')
        
        response = f"""📊 **Threat Detection Summary** (Last 24 hours)

**Total Threats Detected:** {len(threats)}

**Severity Breakdown:**
- 🔴 Critical: {critical}
- 🟠 High: {high}
- 🟡 Medium: {medium}
- 🟢 Low: {low}

"""
        
        if critical > 0 or high > 0:
            response += """⚠️ **Action Required:** You have high-severity threats that need immediate attention!

**Recommended Actions:**
1. Review the Threats page for detailed information
2. Isolate affected systems if possible
3. Run a full system scan
4. Check for unauthorized processes
5. Update all security software

Would you like me to explain any specific threat?"""
        else:
            response += """✓ No critical threats detected. Continue monitoring your system and maintain good security practices."""
        
        return response
    
    def _latest_threat_response(self, threats: List[Dict]) -> str:
        """Provide information about latest threat"""
        if not threats:
            return "No threats have been detected recently. Your system is currently clean."
        
        latest = threats[0]
        threat_name = latest.get('threat_name', 'Unknown')
        severity = latest.get('severity', 'Unknown')
        category = latest.get('category', 'Unknown')
        timestamp = latest.get('timestamp', '')
        
        # Parse details
        details = {}
        if latest.get('details'):
            try:
                details = json.loads(latest['details'])
            except:
                pass
        
        response = f"""🚨 **Latest Detected Threat**

**Threat:** {threat_name}
**Severity:** {severity}
**Category:** {category}
**Detected:** {self._format_time(timestamp)}

"""
        
        if details:
            response += "**Details:**\n"
            for key, value in details.items():
                if key not in ['timestamp', 'severity']:
                    response += f"- {key.replace('_', ' ').title()}: {value}\n"
        
        response += f"""
**Recommended Actions:**
"""
        
        if severity in ['Critical', 'High']:
            response += """1. **Immediate**: Stop the suspicious process
2. Disconnect from network if compromised
3. Run antivirus/antimalware scan
4. Check system logs for anomalies
5. Change passwords if security breach suspected"""
        else:
            response += """1. Monitor the situation
2. Review system activity
3. Update security software
4. Run a scheduled scan"""
        
        return response
    
    def _critical_threats_response(self, threats: List[Dict]) -> str:
        """Handle critical threats queries"""
        critical_threats = [t for t in threats if t.get('severity') in ['Critical', 'High']]
        
        if not critical_threats:
            return """✅ **No critical or high-severity threats detected.**

Your system is not facing any immediate dangers. However, always maintain vigilance:
- Keep software updated
- Use strong passwords
- Enable firewall
- Regular backups
- Monitor system activity"""
        
        response = f"""⚠️ **Critical Security Alert**

**{len(critical_threats)} high-severity threat(s) detected!**

**Immediate Action Plan:**

1. **Isolate Systems**
   - Disconnect from network if actively compromised
   - Stop suspicious processes

2. **Assessment**
   - Review each threat in the Threats page
   - Identify attack vectors
   - Document findings

3. **Containment**
   - Terminate malicious processes
   - Block suspicious network connections
   - Quarantine affected files

4. **Remediation**
   - Run full system scan
   - Remove detected malware
   - Patch vulnerabilities
   - Reset compromised credentials

5. **Recovery**
   - Restore from clean backups
   - Verify system integrity
   - Monitor for re-infection

**Threats requiring attention:**
"""
        
        for i, threat in enumerate(critical_threats[:3], 1):
            response += f"\n{i}. **{threat.get('threat_name')}** - {threat.get('severity')}"
        
        if len(critical_threats) > 3:
            response += f"\n... and {len(critical_threats) - 3} more"
        
        return response
    
    def _recommendations_response(self, threats: List[Dict], stats: Dict) -> str:
        """Provide security recommendations"""
        return """🛡️ **Security Recommendations**

**Immediate Actions:**
1. **Update Software** - Ensure OS and all applications are up to date
2. **Strong Passwords** - Use complex passwords (12+ characters, mixed case, numbers, symbols)
3. **Enable 2FA** - Two-factor authentication for critical accounts
4. **Firewall** - Ensure Windows Defender Firewall is enabled
5. **Antivirus** - Keep real-time protection active

**Regular Maintenance:**
- Run security scans weekly
- Review system logs regularly
- Backup important data (3-2-1 rule)
- Monitor resource usage
- Update security policies

**Network Security:**
- Use secure WiFi (WPA3)
- Avoid public networks for sensitive tasks
- Enable network encryption
- Monitor open ports
- Use VPN for remote access

**Best Practices:**
- Don't open suspicious emails/attachments
- Verify download sources
- Limit administrative privileges
- Keep minimal software installed
- Regular security training

**Advanced Protection:**
- Enable BitLocker drive encryption
- Use Application Control (AppLocker)
- Configure Windows Defender Exploit Guard
- Enable Controlled Folder Access
- Review and harden security policies

Would you like detailed guidance on any specific area?"""
    
    def _explain_threat_response(self, threats: List[Dict], message: str) -> str:
        """Explain specific threat types"""
        message_lower = message.lower()
        
        if 'cpu' in message_lower or 'resource' in message_lower:
            return """💡 **High CPU/Resource Usage Threat**

**What it is:**
Abnormally high CPU or memory usage that may indicate:
- Cryptocurrency mining malware
- Botnet activity
- Resource-intensive malware
- Denial of service attack
- Legitimate app gone rogue

**Why it's dangerous:**
- Slows system performance
- Increases power consumption
- May indicate malware presence
- Can lead to system crashes
- Potential data theft

**How to respond:**
1. Open Task Manager (Ctrl+Shift+Esc)
2. Identify high-usage processes
3. Research unfamiliar processes online
4. Terminate suspicious processes
5. Run antivirus scan
6. Check startup programs
7. Monitor for recurrence"""
        
        elif 'network' in message_lower or 'port' in message_lower:
            return """💡 **Network/Port Security Threat**

**What it is:**
Suspicious network activity such as:
- Unauthorized port listening
- Unusual outbound connections
- Port scanning attempts
- Command & Control (C&C) communication
- Data exfiltration attempts

**Why it's dangerous:**
- May indicate system compromise
- Potential data theft
- Backdoor access for attackers
- Network reconnaissance
- Lateral movement in network

**How to respond:**
1. Use `netstat -ano` to view connections
2. Identify suspicious processes
3. Check Windows Firewall rules
4. Block unauthorized ports
5. Monitor network traffic
6. Scan for rootkits
7. Review security logs"""
        
        else:
            return """💡 **General Threat Information**

**Common Threat Types:**

**1. Malware**
- Viruses, trojans, ransomware
- Spreads and damages systems
- Response: Isolate, scan, remove

**2. Resource Abuse**
- Cryptominers, botnets
- Uses system resources maliciously
- Response: Kill process, deep scan

**3. Network Attacks**
- Port scanning, DDoS, MitM
- Compromises network security
- Response: Firewall rules, monitoring

**4. Privilege Escalation**
- Unauthorized admin access
- Critical security breach
- Response: Immediate containment

For specific threat details, ask about the threat name or check the Threats page."""
    
    def _security_status_response(self, stats: Dict) -> str:
        """Provide security status"""
        total = stats.get('total_threats', 0)
        
        if total == 0:
            return """✅ **Security Status: SECURE**

No threats detected. Your system appears to be clean.

**Keep it secure:**
- Continue regular monitoring
- Run weekly scans
- Keep software updated
- Practice safe browsing
- Maintain strong passwords"""
        else:
            return f"""⚠️ **Security Status: ATTENTION REQUIRED**

**{total} threat(s) detected** that need your attention.

Review the Threats page for details and take appropriate action. I'm here to help if you need guidance!"""
    
    def _scan_recommendation(self) -> str:
        """Recommend running a scan"""
        return """🔍 **Security Scan Recommendation**

**To run a comprehensive security scan:**

1. **Dashboard**: Click the "Run Scan" button
2. **Windows Defender**: 
   - Open Windows Security
   - Virus & threat protection
   - Quick/Full scan

3. **Third-party Tools**:
   - Malwarebytes
   - Kaspersky
   - Norton/McAfee

**Scan Types:**
- **Quick Scan**: 5-10 minutes (common locations)
- **Full Scan**: 1-2 hours (entire system)
- **Custom Scan**: Specific folders/drives

**Best Practices:**
- Run quick scans daily
- Full scans weekly
- After suspicious activity
- Post software installation
- Regular schedule

Would you like me to explain what the scan checks for?"""
    
    def _resource_analysis_response(self, threats: List[Dict]) -> str:
        """Analyze resource-related threats"""
        resource_threats = [t for t in threats if 'resource' in t.get('category', '').lower() or 
                          'cpu' in t.get('threat_name', '').lower() or
                          'memory' in t.get('threat_name', '').lower()]
        
        if not resource_threats:
            return """✅ **Resource Analysis**

No resource abuse threats detected. System resources appear normal.

**Monitoring Tips:**
- Watch for sudden CPU/memory spikes
- Unfamiliar processes using high resources
- System slowdown or freezing
- Unexpected fan noise/heat

Use Task Manager (Ctrl+Shift+Esc) to monitor resources regularly."""
        
        return f"""⚠️ **Resource Analysis**

**{len(resource_threats)} resource-related threat(s) detected**

**Common causes:**
- Cryptomining malware
- Memory leaks
- Malicious processes
- Compromised applications

**Investigation steps:**
1. Open Task Manager
2. Sort by CPU/Memory usage
3. Research suspicious processes
4. Check startup programs
5. Review Task Scheduler

Need help identifying specific processes?"""
    
    def _network_analysis_response(self, threats: List[Dict]) -> str:
        """Analyze network-related threats"""
        network_threats = [t for t in threats if 'network' in t.get('category', '').lower() or
                          'port' in t.get('threat_name', '').lower() or
                          'connection' in t.get('threat_name', '').lower()]
        
        if not network_threats:
            return """✅ **Network Analysis**

No suspicious network activity detected.

**Network Security Checklist:**
- Firewall enabled
- Strong WiFi password
- No unknown devices connected
- VPN for sensitive tasks
- Regular security updates

Keep monitoring network activity for safety!"""
        
        return f"""⚠️ **Network Security Analysis**

**{len(network_threats)} network-related threat(s) detected**

**Common network threats:**
- Port scanning
- Unauthorized connections
- C&C communication
- Data exfiltration

**Check with these commands:**
```
netstat -ano  # View connections
netsh advfirewall show allprofiles  # Firewall status
```

**Actions:**
1. Review active connections
2. Check firewall rules
3. Block suspicious IPs
4. Monitor outbound traffic
5. Run network scan

Need help interpreting network activity?"""
    
    def _help_response(self) -> str:
        """Provide help information"""
        return """🤖 **AI Assistant Capabilities**

I can help you with:

**Threat Analysis**
- Explain detected threats
- Assess severity levels
- Provide threat context

**Security Guidance**
- Best practice recommendations
- Incident response steps
- Security hardening tips

**System Monitoring**
- Resource usage analysis
- Network activity review
- Performance insights

**Quick Commands**
Try asking:
- "What threats have been detected?"
- "Explain the latest threat"
- "How do I improve security?"
- "What should I do about critical threats?"
- "Am I safe?"
- "Recommend a scan"

Just ask your question in plain English!"""
    
    def _general_security_advice(self) -> str:
        """Provide general security advice"""
        return """🛡️ **General Cybersecurity Advice**

**Essential Security Practices:**

**1. Defense in Depth**
- Use multiple security layers
- Don't rely on single solution
- Combine preventive & detective controls

**2. Least Privilege**
- Use standard user accounts
- Admin only when needed
- Limit software permissions

**3. Stay Updated**
- OS patches monthly
- Application updates
- Security software definitions

**4. Data Protection**
- Regular backups (3-2-1 rule)
- Encrypt sensitive data
- Secure disposal of old data

**5. Awareness**
- Verify email senders
- Check URLs before clicking
- Be skeptical of urgency

**6. Network Security**
- Strong WiFi passwords
- Disable WPS
- Use VPN on public networks
- Enable firewall

**7. Password Hygiene**
- Unique passwords per account
- Use password manager
- Enable 2FA everywhere
- 12+ character passwords

**8. Regular Monitoring**
- Check security logs
- Review account activity
- Monitor system resources
- Update security policies

What specific security topic would you like to explore?"""
    
    def _format_time(self, timestamp: str) -> str:
        """Format timestamp for display"""
        try:
            if timestamp:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return dt.strftime('%b %d, %Y at %I:%M %p')
        except:
            pass
        return 'Recently'
