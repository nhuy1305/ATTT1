from flask import Flask, render_template_string, request
import os
from aes import aes_encrypt, aes_decrypt

app = Flask(__name__)

BASE_DIR = os.path.dirname(__file__)
with open(os.path.join(BASE_DIR, "templates", "index.html"), "r", encoding="utf-8") as f:
    HTML = f.read()

@app.route("/", methods=["GET", "POST"])
def index():
    result = "" 
    if request.method == "POST":
        text = request.form.get("text","")
        key = request.form.get("key","")
        action = request.form.get("action","")
        if text and key:
            try:
                if action=="encrypt":
                    result = aes_encrypt(text,key)
                elif action=="decrypt":
                    result = aes_decrypt(text,key)
            except Exception as e:
                result = f"Lỗi: {e}"
        else:
            result = "Vui lòng nhập chuỗi và khóa!"
    return render_template_string(HTML, result=result, request=request)

@app.route("/favicon.ico")
def favicon():
    return "", 204

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
