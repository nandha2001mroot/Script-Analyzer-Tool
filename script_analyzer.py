import os
import re
import sys
from pathlib import Path
from datetime import datetime

class ScriptAnalyzer:
    def __init__(self):
        # PowerShell suspicious commands
        self.powershell_suspicious = [
            'Move-Item', 'Invoke-WebRequest', 'Start-Process', 'Remove-Item',
            'Invoke-Expression', 'IEX', 'New-Object', 'DownloadString',
            'Add-Type', 'Compress-Archive', 'Expand-Archive', 'Set-ItemProperty',
            'New-NetFirewallRule', 'Enable-PSRemoting', 'Set-ExecutionPolicy',
            'Get-WmiObject', 'Get-CimInstance', 'Register-ScheduledTask',
            'Start-Job', 'Invoke-Command', 'Netsh', 'Bypass', 'ExecutionPolicy'
        ]
        
        # Python suspicious commands
        self.python_suspicious = [
            'os.system', 'subprocess', 'requests', 'eval', 'exec',
            'compile', 'execfile', 'fileinput', 'pickle', 'shelve',
            'marshal', 'ctypes', 'cffi', 'cython', 'platform',
            'subprocess.call', 'subprocess.run', 'subprocess.Popen',
            'os.remove', 'os.rename', 'shutil', 'tempfile'
        ]
        
        # PowerShell common commands
        self.powershell_common = [
            'Get-Process', 'Get-Service', 'Get-Content', 'Set-Content',
            'Write-Host', 'Write-Output', 'Write-Error', 'Write-Warning',
            'Get-ChildItem', 'Get-Location', 'Set-Location', 'New-Item',
            'Test-Path', 'Copy-Item', 'Clear-Host', 'Get-Date'
        ]
        
        # Python common commands
        self.python_common = [
            'print', 'len', 'range', 'list', 'dict', 'str', 'int', 'float',
            'input', 'open', 'read', 'write', 'close', 'import',
            'def', 'class', 'if', 'else', 'for', 'while', 'try', 'except'
        ]

    def analyze_script(self, script_path):
        """Main analysis function"""
        script_path = Path(script_path)
        
        if not script_path.exists():
            raise FileNotFoundError(f"Script file not found: {script_path}")
        
        # Determine script type
        if script_path.suffix.lower() == '.ps1':
            script_type = 'PowerShell'
        elif script_path.suffix.lower() == '.py':
            script_type = 'Python'
        else:
            raise ValueError("Unsupported file type. Only .ps1 and .py files are supported.")
        
        with open(script_path, 'r', encoding='utf-8', errors='ignore') as f:
            script_content = f.read()
        
        # Perform analysis
        analysis_results = self._perform_analysis(script_content, script_type)
        
        # Generate report
        report = self._generate_report(script_path, script_type, analysis_results)
        
        # Save report
        output_path = Path(r"C:\Users\my pc\Downloads\script_analysis_report.txt")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"Analysis report saved to: {output_path}")
        return str(output_path)

    def _perform_analysis(self, script_content, script_type):
        """Perform detailed analysis of the script"""
        lines = script_content.split('\n')
        
        if script_type == 'PowerShell':
            return self._analyze_powershell(lines)
        else:
            return self._analyze_python(lines)

    def _analyze_powershell(self, lines):
        """Analyze PowerShell script"""
        functions = set()
        suspicious_found = set()
        total_risk_score = 0
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            # Find PowerShell commands (Cmdlets)
            cmdlet_pattern = r'\b([A-Z][a-z]+-[A-Z][a-z]+)\b'
            matches = re.findall(cmdlet_pattern, line)
            functions.update(matches)
            
            # Check for suspicious commands
            for cmd in self.powershell_suspicious:
                if cmd in line:
                    suspicious_found.add(cmd)
                    total_risk_score += 10 if cmd in ['Invoke-Expression', 'IEX', 'Remove-Item'] else 5
        
        return {
            'functions': list(functions),
            'suspicious': list(suspicious_found),
            'risk_score': total_risk_score,
            'lines': len(lines)
        }

    def _analyze_python(self, lines):
        """Analyze Python script"""
        functions = set()
        suspicious_found = set()
        total_risk_score = 0
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Find Python functions and imports
            import_pattern = r'import\s+([a-zA-Z_][a-zA-Z0-9_]*)'
            func_pattern = r'def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
            module_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\.'
            
            imports = re.findall(import_pattern, line)
            functions.update(imports)
            
            funcs = re.findall(func_pattern, line)
            functions.update(funcs)
            
            modules = re.findall(module_pattern, line)
            functions.update(modules)
            
            # Check for suspicious commands
            for cmd in self.python_suspicious:
                if cmd in line:
                    suspicious_found.add(cmd)
                    total_risk_score += 10 if cmd in ['eval', 'exec', 'subprocess'] else 5
        
        return {
            'functions': list(functions),
            'suspicious': list(suspicious_found),
            'risk_score': total_risk_score,
            'lines': len(lines)
        }

    def _generate_report(self, script_path, script_type, analysis):
        """Generate the analysis report"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Determine risk level
        risk_level = self._determine_risk_level(analysis['risk_score'])
        
        # Generate scope and functionality description
        scope_desc = self._describe_scope(analysis['functions'], script_type)
        
        # Generate execution summary
        exec_summary = self._describe_execution(analysis['functions'], analysis['suspicious'], script_type)
        
        # Generate non-technical summary
        non_tech_summary = self._generate_non_tech_summary(analysis['functions'], analysis['suspicious'], script_type)
        
        # Technical notes for suspicious items
        tech_notes = self._generate_tech_notes(analysis['suspicious'], script_type)
        
        report = f"""SCRIPT ANALYSIS REPORT
====================

File: {script_path}
Type: {script_type}
Analysis Time: {now}
Lines of Code: {analysis['lines']}

SCOPE & FUNCTIONALITY
---------------------
{scope_desc}

EXECUTION SUMMARY
-----------------
{exec_summary}

DETECTED FUNCTIONS/COMMANDS
---------------------------
{', '.join(analysis['functions']) if analysis['functions'] else 'No functions detected'}

SUSPICIOUS BEHAVIOR
-------------------
{', '.join(analysis['suspicious']) if analysis['suspicious'] else 'No suspicious behavior detected'}

RISK RATING: {risk_level}

TECHNICAL NOTES
---------------
{tech_notes}

NON-TECHNICAL SUMMARY
---------------------
{non_tech_summary}

ANALYSIS COMPLETE
"""
        return report

    def _determine_risk_level(self, risk_score):
        """Determine risk level based on score"""
        if risk_score >= 20:
            return "HIGH"
        elif risk_score >= 10:
            return "MEDIUM"
        else:
            return "LOW"

    def _describe_scope(self, functions, script_type):
        """Describe the general scope of the script"""
        if script_type == 'PowerShell':
            if any(f in functions for f in ['Get-Process', 'Get-Service']):
                return "System monitoring and management script - likely checks system processes or services."
            elif any(f in functions for f in ['Invoke-WebRequest', 'DownloadString']):
                return "Network communication script - likely downloads or sends data over the internet."
            elif any(f in functions for f in ['New-Item', 'Set-Content', 'Copy-Item']):
                return "File system manipulation script - likely creates, modifies, or moves files."
            else:
                return "General PowerShell script with basic system operations."
        else:  # Python
            if any(f in functions for f in ['requests', 'urllib']):
                return "Network communication script - likely downloads or sends data over the internet."
            elif any(f in functions for f in ['os', 'shutil']):
                return "File system manipulation script - likely creates, modifies, or moves files."
            elif any(f in functions for f in ['subprocess', 'os.system']):
                return "System command execution script - likely runs external programs or commands."
            else:
                return "General Python script with basic operations."

    def _describe_execution(self, functions, suspicious, script_type):
        """Describe what will happen if executed"""
        actions = []
        
        if script_type == 'PowerShell':
            if 'Invoke-WebRequest' in suspicious:
                actions.append("Downloads files or sends requests to remote servers")
            if 'Remove-Item' in suspicious:
                actions.append("Deletes files or folders from your system")
            if 'Start-Process' in suspicious:
                actions.append("Launches other programs or processes")
            if 'Move-Item' in suspicious:
                actions.append("Moves files or folders to different locations")
        else:  # Python
            if 'requests' in suspicious:
                actions.append("Downloads files or sends requests to remote servers")
            if 'subprocess' in suspicious:
                actions.append("Runs external programs or system commands")
            if 'os.system' in suspicious:
                actions.append("Executes system commands directly")
            if 'eval' in suspicious:
                actions.append("Executes dynamically generated code (highly dangerous)")
        
        if not actions:
            return "The script performs basic operations like calculations, data processing, or simple file reading/writing."
        else:
            return "If executed, this script will: " + "; ".join(actions) + "."

    def _generate_non_tech_summary(self, functions, suspicious, script_type):
        """Generate a non-technical summary"""
        if script_type == 'PowerShell':
            if 'Invoke-WebRequest' in suspicious or 'requests' in suspicious:
                return f"This {script_type} script connects to the internet, which means it can download files or send information online. Be cautious if you don't trust the source."
            elif 'Remove-Item' in suspicious or 'os.remove' in suspicious:
                return f"This {script_type} script can delete files from your computer. Make sure you trust this script before running it."
            elif 'Start-Process' in suspicious or 'subprocess' in suspicious:
                return f"This {script_type} script can run other programs on your computer. The safety depends on what those programs do."
            else:
                return f"This {script_type} script performs basic tasks like reading files or processing data. It appears relatively safe."
        else:  # Python
            if 'eval' in suspicious or 'exec' in suspicious:
                return f"WARNING: This Python script can execute arbitrary code, which is extremely dangerous. Do not run unless you completely trust the source."
            elif 'requests' in suspicious:
                return f"This Python script connects to the internet, which means it can download files or send information online. Be cautious if you don't trust the source."
            elif 'subprocess' in suspicious or 'os.system' in suspicious:
                return f"This Python script can run system commands, which could potentially harm your system. Verify the source before execution."
            else:
                return f"This Python script performs basic tasks like calculations or file operations. It appears relatively safe."

    def _generate_tech_notes(self, suspicious, script_type):
        """Generate technical notes for suspicious items"""
        if not suspicious:
            return "No technical notes - no suspicious patterns detected."
        
        notes = []
        for item in suspicious:
            if item in ['Invoke-WebRequest', 'requests']:
                notes.append(f"- {item}: Used for network requests. Could download malicious content or send sensitive data.")
            elif item in ['Remove-Item', 'os.remove']:
                notes.append(f"- {item}: File deletion command. Could remove important system files.")
            elif item in ['Start-Process', 'subprocess']:
                notes.append(f"- {item}: Process execution. Could run malicious executables.")
            elif item in ['eval', 'exec']:
                notes.append(f"- {item}: Dynamic code execution. Extremely dangerous - can execute arbitrary code.")
            else:
                notes.append(f"- {item}: Potentially risky command detected.")
        
        return '\n'.join(notes)

def main():
    """Main function to run the analyzer"""
    if len(sys.argv) != 2:
        print("Usage: python script_analyzer.py <path_to_script>")
        print("Example: python script_analyzer.py C:\\path\\to\\script.ps1")
        return
    
    script_path = sys.argv[1]
    
    analyzer = ScriptAnalyzer()
    
    try:
        output_path = analyzer.analyze_script(script_path)
        print(f"Analysis complete. Report saved to: {output_path}")
    except Exception as e:
        print(f"Error during analysis: {str(e)}")

if __name__ == "__main__":
    main()