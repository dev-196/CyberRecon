import { logger } from '../config/logger.js';
import { AppError } from '../middleware/errorHandler.js';

export class AIAssistantService {
  constructor() {
    this.conversationHistory = new Map();
    this.knowledgeBase = {
      pentesting: {
        reconnaissance: 'Reconnaissance is the first phase of penetration testing...',
        scanning: 'Scanning involves identifying live hosts, open ports, and services...',
        exploitation: 'Exploitation is the process of taking advantage of vulnerabilities...',
        postExploitation: 'Post-exploitation involves maintaining access and gathering data...'
      },
      vulnerabilities: {
        sqlinjection: 'SQL Injection allows attackers to interfere with database queries...',
        xss: 'Cross-Site Scripting (XSS) allows injection of malicious scripts...',
        rce: 'Remote Code Execution (RCE) allows running arbitrary code on target...',
        lfi: 'Local File Inclusion allows reading local files on the server...'
      },
      tools: {
        nmap: 'Nmap is a network scanner used for security auditing...',
        metasploit: 'Metasploit is a penetration testing framework...',
        burpsuite: 'Burp Suite is a web application security testing tool...',
        wireshark: 'Wireshark is a network protocol analyzer...'
      }
    };
  }

  async chat(message, sessionId = 'default') {
    try {
      logger.info(`AI Chat: ${message.substring(0, 50)}...`);
      
      // Get or create conversation history
      if (!this.conversationHistory.has(sessionId)) {
        this.conversationHistory.set(sessionId, []);
      }
      
      const history = this.conversationHistory.get(sessionId);
      history.push({ role: 'user', content: message, timestamp: new Date() });

      // Generate response based on message content
      const response = this.generateResponse(message.toLowerCase());
      
      history.push({ role: 'assistant', content: response, timestamp: new Date() });

      // Keep only last 20 messages
      if (history.length > 20) {
        history.splice(0, history.length - 20);
      }

      return {
        sessionId,
        message: response,
        timestamp: new Date().toISOString(),
        suggestions: this.getSuggestions(message.toLowerCase())
      };
    } catch (error) {
      logger.error(`AI chat failed: ${error.message}`);
      throw new AppError(`AI chat failed: ${error.message}`, 500);
    }
  }

  generateResponse(message) {
    // Basic keyword-based response generation
    if (message.includes('sql injection') || message.includes('sqli')) {
      return 'SQL Injection is a serious vulnerability that allows attackers to interfere with database queries. To test for SQL injection:\n\n1. Try basic payloads like \' OR \'1\'=\'1\n2. Use UNION-based techniques\n3. Try time-based blind injection\n4. Consider using tools like sqlmap\n\nAlways ensure you have proper authorization before testing!';
    }
    
    if (message.includes('xss') || message.includes('cross-site scripting')) {
      return 'Cross-Site Scripting (XSS) vulnerabilities allow injection of malicious scripts. Common types:\n\n1. Reflected XSS - payload in URL\n2. Stored XSS - payload saved in database\n3. DOM-based XSS - client-side vulnerability\n\nTest with payloads like <script>alert(1)</script> or <img src=x onerror=alert(1)>';
    }
    
    if (message.includes('port scan') || message.includes('nmap')) {
      return 'Port scanning helps identify open ports and services:\n\n1. nmap -sV target.com (service detection)\n2. nmap -sS target.com (stealth SYN scan)\n3. nmap -p- target.com (scan all ports)\n4. nmap -A target.com (aggressive scan)\n\nUse our Port Scanner tool for quick results!';
    }
    
    if (message.includes('privilege escalation') || message.includes('privesc')) {
      return 'Privilege escalation techniques vary by OS:\n\nLinux:\n- SUID binaries\n- Kernel exploits\n- Sudo misconfigurations\n- Cron jobs\n\nWindows:\n- UAC bypass\n- Token impersonation\n- Unquoted service paths\n- AlwaysInstallElevated\n\nUse our Privilege Escalation tool for automated suggestions!';
    }
    
    if (message.includes('hello') || message.includes('hi')) {
      return 'Hello! I\'m your AI pentesting assistant. I can help you with:\n\n- Understanding vulnerabilities\n- Suggesting attack vectors\n- Explaining security concepts\n- Recommending tools and techniques\n- Generating payloads\n\nWhat would you like to know?';
    }

    if (message.includes('help')) {
      return 'I can assist you with various cybersecurity topics:\n\n🔍 Reconnaissance & OSINT\n🔐 Vulnerability Assessment\n💉 Exploitation Techniques\n📱 Mobile Security\n🌐 Web Application Security\n🛡️ Post-Exploitation\n🔧 Tools & Payloads\n\nAsk me anything about penetration testing!';
    }

    return 'I understand you\'re asking about: "' + message + '"\n\nI\'m here to help with penetration testing and cybersecurity. Could you provide more specific details about what you\'d like to know? For example:\n\n- What vulnerability are you investigating?\n- What tool do you need help with?\n- What technique do you want to understand?\n\nFeel free to explore our various scanning and analysis tools!';
  }

  getSuggestions(message) {
    const suggestions = [];
    
    if (message.includes('scan')) {
      suggestions.push('Run a port scan', 'Try web application scanner', 'Check for vulnerabilities');
    } else if (message.includes('exploit')) {
      suggestions.push('Search exploit database', 'Generate payload', 'List available exploits');
    } else {
      suggestions.push('Tell me about SQL injection', 'How to scan for open ports?', 'Explain XSS vulnerabilities');
    }
    
    return suggestions;
  }

  async getConversationHistory(sessionId) {
    try {
      const history = this.conversationHistory.get(sessionId) || [];
      
      return {
        sessionId,
        messages: history,
        totalMessages: history.length,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Get conversation history failed: ${error.message}`);
      throw new AppError(`Failed to get conversation history: ${error.message}`, 500);
    }
  }

  async clearConversation(sessionId) {
    try {
      this.conversationHistory.delete(sessionId);
      
      return {
        sessionId,
        status: 'cleared',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error(`Clear conversation failed: ${error.message}`);
      throw new AppError(`Failed to clear conversation: ${error.message}`, 500);
    }
  }
}

export default new AIAssistantService();
