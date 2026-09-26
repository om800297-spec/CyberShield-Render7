from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3, os, re
from datetime import datetime
from model import predict_scam, analyze_url, analyze_job, analyze_phone, analyze_email, analyze_bank_message

app = Flask(__name__)
app.secret_key = "cybershield-major-demo-secret"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, "cybershield.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

def db():
    con = sqlite3.connect(DB, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout=15000")
    con.execute("PRAGMA journal_mode=WAL")
    return con

def init_db():
    con=db()
    con.execute("""CREATE TABLE IF NOT EXISTS analyses(
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_name TEXT, content TEXT,
        score INTEGER, level TEXT, category TEXT, reasons TEXT, source TEXT, created_at TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS reports(
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_name TEXT, category TEXT,
        description TEXT, created_at TEXT)""")
    con.commit(); con.close()

def save_analysis(content,result,source):
    con=db(); con.execute("INSERT INTO analyses(user_name,content,score,level,category,reasons,source,created_at) VALUES(?,?,?,?,?,?,?,?)",
        ("Student",content[:4000],result["score"],result["level"],result.get("category","General Scam")," | ".join(result["reasons"]),source,datetime.now().strftime("%Y-%m-%d %H:%M")))
    con.commit(); con.close()

@app.route("/",methods=["GET","POST"])
def home():
    result=None; text=""
    if request.method=="POST":
        text=request.form.get("message","").strip()
        if text: result=predict_scam(text); save_analysis(text,result,"Message")
    return render_template("home.html",result=result,text=text)

@app.route("/contact-checker",methods=["GET","POST"])
def contact_checker():
    result=None; value=""
    kind=request.form.get("kind") or request.args.get("kind") or "phone"
    if kind not in ("phone","email"):
        kind="phone"
    if request.method=="POST":
        value=request.form.get("value","").strip()
        if value:
            result=analyze_phone(value) if kind=="phone" else analyze_email(value)
            save_analysis(value,result,"Mobile Number" if kind=="phone" else "Email Address")
    return render_template("contact_checker.html",result=result,value=value,kind=kind)

@app.route("/email-checker",methods=["GET","POST"])
def email_checker():
    result=None; value=""
    if request.method=="POST":
        value=request.form.get("email","").strip()
        if value:
            result=analyze_email(value)
            save_analysis(value,result,"Email Address")
    return render_template("email_checker.html",result=result,value=value)

@app.route("/mobile-checker",methods=["GET","POST"])
def mobile_checker():
    result=None; value=""
    if request.method=="POST":
        value=request.form.get("phone","").strip()
        if value:
            result=analyze_phone(value)
            save_analysis(value,result,"Mobile Number")
    return render_template("mobile_checker.html",result=result,value=value)

@app.route("/bank-checker",methods=["GET","POST"])
def bank_checker():
    result=None; text=""
    if request.method=="POST":
        text=request.form.get("message","").strip()
        if text: result=analyze_bank_message(text); save_analysis(text,result,"Bank/SMS Message")
    return render_template("bank_checker.html",result=result,text=text)

@app.route("/screenshot",methods=["GET","POST"])
def screenshot():
    result=None; extracted=""
    if request.method=="POST":
        image=request.files.get("image")
        if image and image.filename:
            try:
                from PIL import Image
                safe=re.sub(r"[^A-Za-z0-9_.-]","_",image.filename); path=os.path.join(UPLOAD_DIR,safe); image.save(path)

                # Render/Linux-friendly OCR: use RapidOCR first, with pytesseract
                # only as a local fallback when a Tesseract executable exists.
                extracted = ""
                try:
                    from rapidocr_onnxruntime import RapidOCR
                    ocr = RapidOCR()
                    ocr_result, _ = ocr(path)
                    if ocr_result:
                        extracted = "\n".join(str(item[1]) for item in ocr_result).strip()
                except Exception:
                    try:
                        import pytesseract
                        extracted = pytesseract.image_to_string(Image.open(path)).strip()
                    except Exception:
                        extracted = ""

                if extracted:
                    result=predict_scam(extracted); save_analysis(extracted,result,"Screenshot OCR")
                else:
                    flash("Screenshot uploaded, but no readable text was detected. Try a clearer screenshot.")
            except Exception as exc:
                flash("Screenshot OCR could not process this image. Try a clearer screenshot.")
    return render_template("screenshot.html",result=result,extracted=extracted)

@app.route("/url-checker",methods=["GET","POST"])
def url_checker():
    result=None; value=""
    if request.method=="POST":
        value=request.form.get("url","").strip()
        if value: result=analyze_url(value); save_analysis(value,result,"URL Checker")
    return render_template("url_checker.html",result=result,value=value)

@app.route("/job-checker",methods=["GET","POST"])
def job_checker():
    result=None
    if request.method=="POST":
        data={k:request.form.get(k,"").strip() for k in ["company","role","website","message"]}; combined=" ".join(data.values())
        if combined.strip(): result=analyze_job(data); save_analysis(combined,result,"Job/Internship")
    return render_template("job_checker.html",result=result)

@app.route("/dashboard")
def dashboard():
    con=db(); rows=con.execute("SELECT * FROM analyses ORDER BY id DESC LIMIT 15").fetchall(); total=con.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
    high=con.execute("SELECT COUNT(*) FROM analyses WHERE score>=55").fetchone()[0]; medium=con.execute("SELECT COUNT(*) FROM analyses WHERE score>=30 AND score<55").fetchone()[0]; low=con.execute("SELECT COUNT(*) FROM analyses WHERE score<30").fetchone()[0]; reports=con.execute("SELECT COUNT(*) FROM reports").fetchone()[0]; con.close()
    awareness=min(100,45+min(total*3,35)+min(max(low-high,0)*2,20))
    return render_template("dashboard.html",rows=rows,total=total,high=high,medium=medium,low=low,reports=reports,awareness=awareness)

@app.route("/quiz",methods=["GET","POST"])
def quiz():
    score=None; correct={"q1":"b","q2":"c","q3":"a","q4":"b","q5":"c"}
    if request.method=="POST": score=sum(request.form.get(k)==v for k,v in correct.items())
    return render_template("quiz.html",score=score)

@app.route("/report",methods=["GET","POST"])
def report():
    if request.method=="POST":
        con=db(); con.execute("INSERT INTO reports(user_name,category,description,created_at) VALUES(?,?,?,?)",("Student",request.form["category"],request.form["description"],datetime.now().strftime("%Y-%m-%d %H:%M"))); con.commit(); con.close(); flash("Suspicious content report saved successfully."); return redirect(url_for("report"))
    return render_template("report.html")

@app.route("/awareness")
def awareness(): return render_template("awareness.html")

if __name__=="__main__": init_db(); app.run(debug=True)
