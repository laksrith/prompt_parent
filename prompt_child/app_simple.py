import os
import logging
import tempfile
import json
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from github_scanner import GitHubScanner

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

ALLOWED_EXTENSIONS = {'py', 'java', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '' or file.filename is None:
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not supported. Please upload .py, .java, or .txt files'}), 400
        
        # Save uploaded file temporarily
        filename = secure_filename(file.filename)
        content = file.read().decode('utf-8')
        
        # Determine file type
        file_extension = filename.rsplit('.', 1)[1].lower()
        language = 'python' if file_extension == 'py' else 'java' if file_extension == 'java' else 'unknown'
        
        # Simple static analysis
        vulnerabilities = analyze_code_simple(content, language)
        
        return jsonify({
            'success': True,
            'filename': filename,
            'language': language,
            'vulnerabilities': vulnerabilities,
            'remediation_suggestions': generate_remediations(vulnerabilities),
            'categories': list(set(v.get('category', 'security') for v in vulnerabilities)),
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'high_severity': len([v for v in vulnerabilities if v.get('severity') == 'high']),
                'medium_severity': len([v for v in vulnerabilities if v.get('severity') == 'medium']),
                'low_severity': len([v for v in vulnerabilities if v.get('severity') == 'low']),
                'categories_found': list(set(v.get('category', 'security') for v in vulnerabilities))
            }
        })
    
    except Exception as e:
        logger.error(f"Error processing file upload: {str(e)}")
        return jsonify({'error': f'Error processing file: {str(e)}'}), 500

@app.route('/scan-github', methods=['POST'])
def scan_github_repository():
    try:
        data = request.get_json()
        if not data or 'github_url' not in data:
            return jsonify({'error': 'GitHub URL is required'}), 400
        
        github_url = data['github_url'].strip()
        if not github_url:
            return jsonify({'error': 'GitHub URL cannot be empty'}), 400
        
        # Initialize GitHub scanner
        scanner = GitHubScanner()
        
        # Scan the repository
        scan_results = scanner.scan_repository(github_url)
        
        return jsonify({
            'success': True,
            'scan_type': 'repository',
            'repository_url': scan_results['repository_url'],
            'summary': scan_results['scan_summary'],
            'files_analyzed': scan_results['files_analyzed'],
            'vulnerabilities_by_file': scan_results['vulnerabilities_by_file'],
            'remediation_suggestions': scan_results['remediations'],
            'categories': scan_results['categories_found'],
            'languages_detected': scan_results['languages_detected']
        })
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error scanning GitHub repository: {str(e)}")
        return jsonify({'error': f'Error scanning repository: {str(e)}'}), 500

def analyze_code_simple(code, language):
    """Simple static code analysis"""
    vulnerabilities = []
    lines = code.split('\n')
    
    if language == 'python':
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Check for eval usage
            if 'eval(' in line_stripped:
                vulnerabilities.append({
                    'type': 'code_injection',
                    'severity': 'high',
                    'line': i,
                    'description': 'Use of eval() function can lead to code injection vulnerabilities',
                    'category': 'security',
                    'cwe_id': 'CWE-95',
                    'source': 'static_analysis'
                })
            
            # Check for exec usage
            if 'exec(' in line_stripped:
                vulnerabilities.append({
                    'type': 'code_injection',
                    'severity': 'high',
                    'line': i,
                    'description': 'Use of exec() function can lead to code injection vulnerabilities',
                    'category': 'security',
                    'cwe_id': 'CWE-95',
                    'source': 'static_analysis'
                })
            
            # Check for subprocess with shell=True
            if 'subprocess' in line_stripped and 'shell=True' in line_stripped:
                vulnerabilities.append({
                    'type': 'command_injection',
                    'severity': 'high',
                    'line': i,
                    'description': 'subprocess with shell=True can lead to command injection',
                    'category': 'security',
                    'cwe_id': 'CWE-78',
                    'source': 'static_analysis'
                })
            
            # Check for pickle.loads
            if 'pickle.loads(' in line_stripped:
                vulnerabilities.append({
                    'type': 'deserialization',
                    'severity': 'high',
                    'line': i,
                    'description': 'Unsafe pickle deserialization can lead to code execution',
                    'category': 'security',
                    'cwe_id': 'CWE-502',
                    'source': 'static_analysis'
                })
            
            # Check for hardcoded secrets
            if any(keyword in line_stripped.lower() for keyword in ['password =', 'secret =', 'api_key =']):
                if '"' in line_stripped or "'" in line_stripped:
                    vulnerabilities.append({
                        'type': 'hardcoded_secret',
                        'severity': 'medium',
                        'line': i,
                        'description': 'Hardcoded password or secret detected',
                        'category': 'security',
                        'cwe_id': 'CWE-798',
                        'source': 'static_analysis'
                    })
    
    elif language == 'java':
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Check for Runtime.exec
            if 'Runtime.getRuntime().exec(' in line_stripped:
                vulnerabilities.append({
                    'type': 'command_injection',
                    'severity': 'high',
                    'line': i,
                    'description': 'Runtime.exec() can lead to command injection vulnerabilities',
                    'category': 'security',
                    'cwe_id': 'CWE-78',
                    'source': 'static_analysis'
                })
            
            # Check for SQL injection patterns
            if 'Statement' in line_stripped and 'executeQuery(' in line_stripped and '+' in line_stripped:
                vulnerabilities.append({
                    'type': 'sql_injection',
                    'severity': 'high',
                    'line': i,
                    'description': 'Potential SQL injection through string concatenation',
                    'category': 'security',
                    'cwe_id': 'CWE-89',
                    'source': 'static_analysis'
                })
            
            # Check for ObjectInputStream
            if 'ObjectInputStream' in line_stripped and 'readObject(' in line_stripped:
                vulnerabilities.append({
                    'type': 'deserialization',
                    'severity': 'high',
                    'line': i,
                    'description': 'Unsafe object deserialization can lead to code execution',
                    'category': 'security',
                    'cwe_id': 'CWE-502',
                    'source': 'static_analysis'
                })
    
    return vulnerabilities

def generate_remediations(vulnerabilities):
    """Generate remediation suggestions for vulnerabilities"""
    remediations = []
    
    for vuln in vulnerabilities:
        vuln_type = vuln.get('type', '')
        
        if vuln_type == 'code_injection':
            remediations.append({
                'title': 'Remove or Replace Dangerous Code Execution',
                'description': 'Replace eval() or exec() with safer alternatives',
                'code_example': 'import ast\nresult = ast.literal_eval(user_input)  # Safe for literals only',
                'priority': 'high',
                'category': 'security'
            })
        
        elif vuln_type == 'command_injection':
            remediations.append({
                'title': 'Use Safe Command Execution',
                'description': 'Use subprocess with shell=False and validate inputs',
                'code_example': 'subprocess.run([command, arg1, arg2], shell=False)  # Safer approach',
                'priority': 'high',
                'category': 'security'
            })
        
        elif vuln_type == 'sql_injection':
            remediations.append({
                'title': 'Use Parameterized Queries',
                'description': 'Replace string concatenation with prepared statements',
                'code_example': 'PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\nstmt.setString(1, userId);',
                'priority': 'high',
                'category': 'security'
            })
        
        elif vuln_type == 'deserialization':
            remediations.append({
                'title': 'Use Safe Deserialization',
                'description': 'Avoid unsafe deserialization or implement validation',
                'code_example': 'Use JSON for simple data structures or implement custom validation',
                'priority': 'high',
                'category': 'security'
            })
        
        elif vuln_type == 'hardcoded_secret':
            remediations.append({
                'title': 'Use Environment Variables',
                'description': 'Move secrets to environment variables or secure storage',
                'code_example': 'password = os.getenv("DB_PASSWORD")  # Use environment variable',
                'priority': 'medium',
                'category': 'security'
            })
    
    return remediations

@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy', 'version': '1.0.0'})

if __name__ == '__main__':
    logger.info("Starting Code Vulnerability Analysis Server")
    app.run(host='0.0.0.0', port=5000, debug=False)