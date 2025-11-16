# PowerShell helper to activate venv and start the Flask app with ngrok tunnel
# Usage: .\start-with-tunnel.ps1

$venv = ".venv\Scripts\Activate.ps1"
if (Test-Path $venv) {
    Write-Host "Activating virtual environment..."
    . $venv
} else {
    Write-Host "Virtual environment not found. Consider creating one with: python -m venv .venv"
}

Write-Host "Installing requirements (if needed)..."
pip install -r requirements.txt

Write-Host "Starting app with ngrok tunnel..."
python .\start_tunnel.py
