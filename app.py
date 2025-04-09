from flask import Flask, render_template, request, redirect, url_for, session, flash 
import sqlite3
import secrets
from defenses import check_brute_force, log_login_attempt
from utils import init_db

app = Flask(__name__)
app.secret_key = "supersecreto"
DATABASE = "database.db"

# Inicializa la base de datos
init_db(DATABASE)

@app.route("/", methods=["GET", "POST"])
def login():
    ip = request.remote_addr

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Check de fuerza bruta
        if check_brute_force(ip):
            flash("Demasiados intentos. Tu IP ha sido bloqueada temporalmente.", "danger")
            return render_template("login.html")

        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = cur.fetchone()
        conn.close()

        if user:
            session["username"] = username
            flash("Login exitoso", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Credenciales incorrectas", "danger")
            log_login_attempt(ip, success=False)
            return render_template("login.html")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "username" in session:
        return render_template("dashboard.html", username=session['username'])
    else:
        return redirect(url_for("login"))


@app.route("/buscar", methods=["GET", "POST"])
def buscar():
    resultados = None
    if request.method == "POST":
        termino = request.form["termino"]
        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()

        # 🛡️ SEGURO contra SQLi
        query = "SELECT username FROM users WHERE username LIKE ?"
        try:
            cur.execute(query, (f"%{termino}%",))
            resultados = cur.fetchall()
        except:
            resultados = [("Error en la consulta SQL",)]

        conn.close()

    return render_template("busqueda.html", resultados=resultados)


@app.route("/comentarios", methods=["GET", "POST"])
def comentarios():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()

    if request.method == "POST":
        username = request.form["username"]
        content = request.form["content"]
        cur.execute("INSERT INTO comments (username, content) VALUES (?, ?)", (username, content))
        conn.commit()

    cur.execute("SELECT username, content FROM comments")
    comentarios = cur.fetchall()
    conn.close()

    # Modo: vulnerable o seguro
    modo = request.args.get("modo", "vulnerable")

    return render_template("comentarios.html", comentarios=comentarios, modo=modo)


@app.route("/configurar", methods=["GET", "POST"])
def configurar():
    if "username" not in session:
        return redirect(url_for("login"))

    mensaje = None

    if request.method == "GET":
        # Generar token y guardarlo en sesión
        session["csrf_token"] = secrets.token_hex(16)

    if request.method == "POST":
        token_form = request.form.get("csrf_token")
        token_session = session.get("csrf_token")

        if not token_form or token_form != token_session:
            return "Posible ataque CSRF detectado", 403

        nueva_password = request.form["nueva_password"]
        username = session["username"]

        conn = sqlite3.connect(DATABASE)
        cur = conn.cursor()
        cur.execute("UPDATE users SET password=? WHERE username=?", (nueva_password, username))
        conn.commit()
        conn.close()

        mensaje = "Contraseña cambiada exitosamente"

    return render_template("configurar.html", mensaje=mensaje, csrf_token=session.get("csrf_token"))


if __name__ == "__main__":
    app.run(debug=True)