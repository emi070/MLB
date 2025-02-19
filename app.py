import os
from flask import Flask, request, jsonify, session, redirect, url_for, flash, render_template
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Optional
from datetime import datetime, timedelta
from sqlalchemy import inspect, text
import random
import string
from datetime import datetime
from sqlalchemy import text
import sqlite3

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Configuración para permitir cargar archivos
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')  # Carpeta dentro del proyecto
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png', 'gif'}

# Función para verificar las extensiones de los archivos
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/subir_comprobante', methods=['POST'])
def subir_comprobante():
    if 'comprobante' not in request.files:
        flash('No se ha seleccionado un archivo.', 'danger')
        return redirect(url_for('depositos'))

    archivo = request.files['comprobante']
    if archivo.filename == '':
        flash('No se seleccionó archivo para subir.', 'danger')
        return redirect(url_for('depositos'))

    if archivo and allowed_file(archivo.filename):
        # Obtener el nombre del usuario y la fecha actual
        usuario = request.form['usuarioPagador']
        fecha = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Construir el nombre del archivo
        filename = f"{usuario}_{fecha}.{archivo.filename.rsplit('.', 1)[1].lower()}"

        # Guardar el archivo en la carpeta de uploads
        archivo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Flash de éxito y redirección con parámetro adicional
        flash('Su comprobante fue sometido a revisión. En las próximas 4 horas su saldo será actualizado.', 'success')
        return redirect(url_for('depositos')) # Pasar el parámetro

    flash('Tipo de archivo no permitido.', 'danger')
    return redirect(url_for('depositos'))

@app.route('/subir_comprobante_usdt', methods=['POST'])
def subir_comprobante_usdt():
    if 'comprobanteUSDT' not in request.files:
        flash('No se ha seleccionado un archivo.', 'danger')
        return redirect(url_for('depositos'))

    archivo = request.files['comprobanteUSDT']
    if archivo.filename == '':
        flash('No se seleccionó archivo para subir.', 'danger')
        return redirect(url_for('depositos'))

    if archivo and allowed_file(archivo.filename):
        # Obtener el nombre del usuario y la fecha actual
        usuario = request.form['usuarioPagadorUSDT']
        fecha = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Construir el nombre del archivo con la extensión correcta
        filename = f"{usuario}_USDT_{fecha}.{archivo.filename.rsplit('.', 1)[1].lower()}"

        # Guardar el archivo en la carpeta de uploads
        archivo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Flash de éxito y redirección
        flash('Su comprobante de pago USDT fue sometido a revisión. En las próximas 4 horas su saldo será actualizado.', 'success')
        return redirect(url_for('depositos'))

    flash('Tipo de archivo no permitido.', 'danger')
    return redirect(url_for('depositos'))

#######################################################################################################

# Obtén la ruta completa del archivo de la base de datos
basedir = os.path.abspath(os.path.dirname(__file__))  # Obtiene el directorio actual
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "database.db")}'
app.config['SECRET_KEY'] = 'tu_clave_secreta'
db = SQLAlchemy(app)

# Esta función crea las tablas y verifica las tablas existentes usando inspect()
def create_tables():
    # Verifica si el archivo de la base de datos existe
    if os.path.exists(os.path.join(basedir, 'database.db')):
        print("Base de datos encontrada.")
    else:
        print("Base de datos no encontrada. Creando base de datos...")
        db.create_all()  # Crear las tablas si no existen

    # Verificamos si la tabla 'User' existe y si no, la creamos
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()  # Obtenemos los nombres de las tablas
    print("Tablas actuales en la base de datos:", tables)

    if 'user' not in tables:  # Si no existe la tabla 'user', la creamos
        print("Tabla 'user' no encontrada. Creando la tabla...")
        db.create_all()  # Si no existe, la crea
    else:
        print("La tabla 'user' ya existe.")    

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # Redirigir a la página de login si el usuario no está autenticado

@app.route('/')
def home():
    return redirect(url_for('login'))

class User(db.Model, UserMixin):  # ✅ Agregar UserMixin
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    saldo = db.Column(db.Float, default=0.0)

    codigo_referido = db.Column(db.String(10), unique=True, nullable=False)
    referido_por = db.Column(db.String(10), nullable=True)
    saldo_referidos = db.Column(db.Float, default=0.0)

class Suscripcion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    nivel = db.Column(db.Integer, nullable=False)
    nombre = db.Column(db.String(100), nullable=False)
    costo = db.Column(db.String(100), nullable=False)
    comision = db.Column(db.String(100), nullable=False)
    ganancia = db.Column(db.String(100), nullable=False)
    ganancia_diaria = db.Column(db.Float, default=0.0)
    ultimo_pago = db.Column(db.DateTime, default=datetime.utcnow)  # Fecha del último pago
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)  # ✅ Fecha real de creación

class Retiros(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    cuenta_bancaria = db.Column(db.String(50), nullable=False)
    banco = db.Column(db.String(20), nullable=False)
    monto = db.Column(db.Float, nullable=False)
    fecha = db.Column(db.DateTime, nullable=False)
    estado = db.Column(db.String(20), nullable=False, default="Pendiente")  # Puede ser "Pendiente", "Aprobado", "Rechazado"

def actualizar_ganancia(self):
    """ Sumar ganancia diaria cuando han pasado 24 horas desde el último pago """
    ahora = datetime.utcnow()  # Obtener la hora actual en UTC
    
    # Comprobar si han pasado 24 horas exactas desde el último pago
    if ahora >= self.ultimo_pago + timedelta(days=1):
        self.ganancia_diaria += float(self.ganancia.split('RD$')[1].split()[0])  # Extraer valor numérico de la ganancia
        self.ultimo_pago = ahora  # Actualizar el último pago
        db.session.commit()

usuario = db.relationship('User', backref=db.backref('suscripciones', lazy=True))

with app.app_context():
    db.create_all()

class LoginForm(FlaskForm):
    username = StringField('Usuario', validators=[InputRequired(), Length(min=4, max=150)])
    password = PasswordField('Contraseña', validators=[InputRequired(), Length(min=6, max=150)])
    submit = SubmitField('Iniciar sesión')

class RegisterForm(FlaskForm):
    username = StringField('Usuario', validators=[InputRequired(), Length(min=4, max=150)])
    password = PasswordField('Contraseña', validators=[InputRequired(), Length(min=6, max=150)])
    referido_por = StringField('Código de referido (opcional)', validators=[Optional()])  # Nuevo campo
    submit = SubmitField('Registrarse')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def generar_codigo_referido():
    """Genera un código aleatorio de 6 caracteres para referidos."""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Verificamos si el usuario ya existe antes de crearlo
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('El usuario ya existe. Por favor, usa otro nombre de usuario.', 'warning')
            return redirect(url_for('register'))

        # Generamos el hash de la contraseña
        hashed_password = generate_password_hash(form.password.data)

        # Generamos un código de referido único
        codigo_referido = generar_codigo_referido()

        # Verificamos si el usuario ingresó un código de referido válido
        referido_por = None
        if form.referido_por.data:
            usuario_referente = User.query.filter_by(codigo_referido=form.referido_por.data).first()
            if usuario_referente:
                referido_por = usuario_referente.codigo_referido
            else:
                flash('Código de referido inválido. Se ignorará.', 'warning')

        # Crear el usuario
        new_user = User(
            username=form.username.data,
            password=hashed_password,
            codigo_referido=codigo_referido,
            referido_por=referido_por
        )

        db.session.add(new_user)
        db.session.commit()

        flash('Registro exitoso. Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form, bootstrap=True)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        print("✔ Formulario validado")  # ✅ Agregar print para depurar
        user = User.query.filter_by(username=form.username.data).first()
        
        if user:
            print(f"🔹 Usuario encontrado: {user.username}")
            print(f"🔑 Hash en BD: {user.password}")
            print(f"🔑 Contraseña ingresada: {form.password.data}")
            print(f"🔍 Comparación: {check_password_hash(user.password, form.password.data)}")
        else:
            print("❌ Usuario no encontrado en la BD")
        
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            print("✅ Usuario autenticado")
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            print("❌ Error en usuario o contraseña")
            flash('Usuario o contraseña incorrectos', 'danger')

    return render_template('login.html', form=form, bootstrap=True)


@app.route('/dashboard')
@login_required 
def dashboard():
    suscripciones_usuario = [s.nivel for s in Suscripcion.query.filter_by(user_id=current_user.id).all()]
    return render_template(
        'dashboard.html',
        user_name=current_user.username,
        saldo=current_user.saldo, user_suscripciones=suscripciones_usuario
    )

@app.route('/depositos')
@login_required
def depositos():
    return render_template('depositos.html', bootstrap=True)

@app.route('/logout')
@login_required
def logout():
    logout_user()  # ✅ Cierra sesión correctamente
    flash('Has cerrado sesión.', 'success')
    return redirect(url_for('login'))

@app.route('/suscribirse', methods=['POST'])
def suscribirse():
    nivel_elegido = request.form.get('nivel')
    costo = float(request.form.get('costo'))  # Asegúrate de que el costo sea un número
    comision = request.form.get('comision')
    ganancia = request.form.get('ganancia')

    if current_user.saldo < costo:
        return jsonify({'message': 'Saldo insuficiente'}), 400

    # Verificar si el usuario ya está suscrito a este nivel
    suscripcion_existente = Suscripcion.query.filter_by(user_id=current_user.id, nivel=nivel_elegido).first()
    if suscripcion_existente:
        flash("Ya estás suscrito a este nivel.", "warning")
        return redirect(url_for('dashboard'))  # Redirigimos a dashboard

    # Verificamos si el usuario tiene suficiente saldo
    if current_user.saldo >= costo:
        ahora = datetime.now()  # Usar hora local

        # Crear la nueva suscripción
        nueva_suscripcion = Suscripcion(
            user_id=current_user.id,
            nivel=nivel_elegido,
            nombre=f"Nivel {nivel_elegido}",
            costo=costo,
            comision=comision,
            ganancia=ganancia,
            fecha_creacion=ahora,   # Asegúrate de tener este campo en el modelo
            ultimo_pago=ahora       # Inicia el conteo desde el momento de suscripción
        )

        # Agregar la suscripción a la base de datos
        db.session.add(nueva_suscripcion)

        # Descontamos el costo de la suscripción del saldo del usuario
        current_user.saldo -= costo
        db.session.commit()
        return jsonify({
        'message': 'Suscripción exitosa',
        'nuevo_saldo': current_user.saldo  })
        flash("¡Te has suscrito con éxito! El saldo ha sido actualizado.", "success")
    else:
        flash("Saldo insuficiente para suscribirse a este nivel.", "danger")
        return redirect(url_for('dashboard'))  # Redirigimos a dashboard si el saldo es insuficiente

    return redirect(url_for('dashboard'))  # Aseguramos que siempre volvemos al dashboard

@app.route('/get_saldo', methods=['GET'])
def get_saldo():
    return jsonify({'saldo': current_user.saldo})

@app.route('/ganancias', methods=['GET'])
@login_required
def ganancias():
    suscripciones = Suscripcion.query.filter_by(user_id=current_user.id).all()
    ahora = datetime.now()  # Usar hora local

    for suscripcion in suscripciones:
        # Si por alguna razón 'ultimo_pago' es None, lo forzamos
        if not suscripcion.ultimo_pago:
            suscripcion.ultimo_pago = ahora - timedelta(days=1)  # Aseguramos que siempre haya un valor inicial

        # Calcula la diferencia en horas entre ahora y el último pago
        diferencia = (ahora - suscripcion.ultimo_pago).total_seconds() / 3600  # Diferencia en horas

        # Si han pasado al menos 24 horas
        if diferencia >= 24:
            # Extraemos el número de ganancia inicial de forma segura
            try:
                ganancia_num = float(suscripcion.ganancia.replace('RD$', '').strip().split()[0])
            except Exception:
                ganancia_num = 0.0

            # Calcula la ganancia acumulada sumando la ganancia base por cada 24 horas
            ganancia_acumulada = ganancia_num * int(diferencia / 24)  # Sumar la ganancia base cada 24 horas

            # Acumula la ganancia a la ganancia diaria
            suscripcion.ganancia_diaria += ganancia_acumulada  # Acumulando en lugar de sobrescribir
            suscripcion.ultimo_pago = ahora  # Reiniciamos el tiempo de último pago
            db.session.commit()

    return render_template('ganancias.html', suscripciones=suscripciones)

@app.route('/cancelar_suscripcion/<int:nivel>', methods=['POST'])
@login_required
def cancelar_suscripcion(nivel):
    # Buscar la suscripción del usuario por el nivel
    suscripcion = Suscripcion.query.filter_by(user_id=current_user.id, nivel=nivel).first()

    if not suscripcion:
        return jsonify({"error": "Suscripción no encontrada"}), 404

    # Obtener los fondos invertidos y la ganancia diaria acumulada
    fondos_invertidos = float(suscripcion.costo)  # Asegurarse de que 'costo' sea numérico
    ganancia_diaria = float(suscripcion.ganancia_diaria)  # Asegurarse de que 'ganancia_diaria' sea numérico

    # Actualizar el saldo del usuario
    usuario = current_user  # Usuario actual
    # Convertir el saldo actual del usuario a float antes de sumarle
    usuario.saldo = float(usuario.saldo) + fondos_invertidos + ganancia_diaria

    # Eliminar o marcar como cancelada la suscripción
    db.session.delete(suscripcion)  # Esto eliminará la suscripción; si prefieres solo marcarla como cancelada, puedes hacer algo como suscripcion.cancelada = True
    db.session.commit()

    # Confirmar la actualización
    return jsonify({
        "message": f"Suscripción nivel {nivel} cancelada. RD$ {fondos_invertidos} invertidos y RD$ {ganancia_diaria} de ganancia diaria fueron devueltos a tu saldo.",
        "nuevo_saldo": usuario.saldo
    }), 200

@app.route('/transferir_ganancia/<int:nivel>', methods=['POST'])
@login_required
def transferir_ganancia(nivel):
    # Buscar la suscripción del usuario por el nivel
    suscripcion = Suscripcion.query.filter_by(user_id=current_user.id, nivel=nivel).first()

    if not suscripcion:
        return jsonify({"error": "Suscripción no encontrada"}), 404

    # Obtener la ganancia diaria acumulada
    ganancia_diaria = float(suscripcion.ganancia_diaria)  # Asegurarse de que 'ganancia_diaria' sea numérico

    # Verificar si la ganancia diaria es 0.0
    if ganancia_diaria == 0.0:
        return jsonify({"error": "No tienes ganancia diaria acumulada para transferir."}), 400

    # Actualizar el saldo del usuario
    usuario = current_user  # Usuario actual
    usuario.saldo = float(usuario.saldo) + ganancia_diaria  # Transferir ganancia diaria al saldo del usuario

    # Restar la ganancia diaria acumulada de la suscripción (opcional, si deseas que la ganancia se resetee)
    suscripcion.ganancia_diaria = 0.0  # Resetear la ganancia diaria acumulada a 0

    db.session.commit()

    # Confirmar la transferencia
    return jsonify({
        "message": f"Ganancia diaria de RD$ {ganancia_diaria} transferida al saldo.",
        "nuevo_saldo": usuario.saldo
    }), 200

@app.route('/datos_dashboard')
@login_required
def datos_dashboard():
    # Obtener datos reales desde la base de datos
    inversion_total = db.session.query(db.func.sum(Suscripcion.costo)).scalar() or 0.0
    total_usuarios = db.session.query(db.func.count(User.id)).scalar() or 0

    return jsonify({
        "inversion": float(inversion_total),
        "usuarios": total_usuarios
    })

@app.route('/solicitar_retiro', methods=['POST'])
@login_required
def solicitar_retiro():
    data = request.json
    monto = float(data.get('monto'))
    
    if monto > current_user.saldo:
        return jsonify({'error': 'Saldo insuficiente'}), 400  # Error si no hay saldo suficiente

    # Crear un nuevo retiro en la BD
    nuevo_retiro = Retiros(
        usuario_id=current_user.id,
        cuenta_bancaria=data.get('cuenta_bancaria'),
        banco=data.get('banco'),
        monto=monto,
        fecha=datetime.utcnow(),
        estado='Pendiente'  # Estado inicial
    )
    
    # Descontar saldo del usuario
    current_user.saldo -= monto

    db.session.add(nuevo_retiro)
    db.session.commit()

    return jsonify({'mensaje': 'Retiro solicitado con éxito'})

@app.route('/get_historial_retiros', methods=['GET'])
@login_required
def get_historial_retiros():
    retiros = Retiros.query.filter_by(usuario_id=current_user.id).order_by(Retiros.fecha.desc()).all()
    
    historial = [{
        'cuenta_bancaria': retiro.cuenta_bancaria,
        'banco': retiro.banco,
        'monto': retiro.monto,
        'fecha': retiro.fecha.strftime('%Y-%m-%d %H:%M'),
        'estado': retiro.estado
    } for retiro in retiros]

    return jsonify(historial)

if __name__ == '__main__':
         # Usamos el contexto de la aplicación para crear las tablas
    with app.app_context():
        create_tables()
    app.run(host='0.0.0.0', port=5000, debug=True)
