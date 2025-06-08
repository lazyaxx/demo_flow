#!/usr/bin/env python
import sys
import warnings
from crews.security_crew.security_crew import SecurityCrew

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

def run():
    """
    Run the security crew with a test URL
    """
    # Test URLs with different threat levels
    test_urls = [
        "https://malware.com/download.exe",  # High threat
        "https://suspicious-download.org/file.zip",  # Medium threat  
        "https://google.com",  # Low threat
    ]
    
    print("🛡️ Starting Security Analysis Crew 🛡️\n")
    
    for url in test_urls:
        print(f"\n{'='*60}")
        print(f"🔍 ANALYZING: {url}")
        print(f"{'='*60}")
        
        try:
            # Initialize the crew
            security_crew = SecurityCrew()
            
            # Run the analysis
            result = security_crew.crew().kickoff(inputs={'url': url})
            
            print(f"\n✅ Analysis Complete for {url}")
            print(f"📋 Result: {result}")
            
        except Exception as e:
            print(f"❌ Error analyzing {url}: {str(e)}")
        
        print(f"\n{'='*60}\n")

if __name__ == "__main__":
    run()
