
from flask import Flask, request, render_template_string
from urllib.parse import urlparse
import ipaddress

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishGuard</title>
<style>
body {
    font-family: Arial, sans-serif;
    background: #101827;
    color: white;
    text-align: center;
    padding: 30px 15px;
}
.container {
    max-width: 550px;
    margin: 40px auto;
    background: #1e293b;
    padding: 25px;
    border-radius: 18px;
}
h1 { color: #38bdf8; }
input {
    width: 90%;
    padding: 13px;
    margin: 12px 0;
    border-radius: 8px;
    border: none;
}
button {
    padding: 12px 24px;
    border: none;
    border-radius: 8px;
    background: #0284c7;
    color: white;
    cursor: pointer;
}
.result {
    margin-top: 20px;
    padding: 15px;
    background: #334155;
    border-radius: 10px;
}
small { color: #cbd5e1; }
</style>
</head>
<body>
<div class="container">
    <h1>🛡️ PhishGuard</h1>
    <p>Pemeriksa awal URL mencurigakan</p>
    <form method="POST">
        <input type="text" name="url"
        placeholder="Masukkan URL untuk diperiksa" required>
        <br>
        <button type="submit">Periksa URL</button>
    </form>
    {% if result %}
    <div class="result">
        <h3>{{ result }}</h3>
        <p>{{ detail }}</p>
    </div>
    {% endif %}
    <p><small>Hasil pemeriksaan awal, bukan jaminan keamanan.</small></p>
</div>
</body>
</html>
"""

def check_url(value):
    value = value.strip()

    if not value or any(c.isspace() for c in value):
        return "INPUT TIDAK VALID", "Masukkan satu URL yang benar."

    if "://" not in value:
        value = "https://" + value

    try:
        parsed = urlparse(value)
        host = parsed.hostname

        if parsed.scheme not in ("http", "https") or not host:
            return "INPUT TIDAK VALID", "Format URL tidak dikenali."

        reasons = []

        try:
            ipaddress.ip_address(host)
            reasons.append("Menggunakan alamat IP langsung")
        except ValueError:
            pass

        if host.startswith("xn--") or ".xn--" in host:
            reasons.append("Domain menggunakan format IDN")

        if parsed.username or parsed.password:
            reasons.append("Ada informasi pengguna dalam URL")

        if reasons:
            return "PERLU DIWASPADAI", "; ".join(reasons)

        return (
            "BELUM TERDETEKSI INDIKATOR DASAR",
            "Ini bukan berarti URL pasti aman. "
            "Pemeriksaan ini belum memakai database ancaman."
        )

    except ValueError:
        return "INPUT TIDAK VALID", "URL gagal diperiksa."

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    detail = ""

    if request.method == "POST":
        result, detail = check_url(request.form.get("url", ""))

    return render_template_string(
        HTML, result=result, detail=detail
    )

if __name__ == "__main__":
    app.run(debug=False)
