from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///crm.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='admin')
    is_approved = db.Column(db.Boolean, default=True)
    monthly_goal = db.Column(db.Integer, default=10)

class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    birth_date = db.Column(db.Date)
    follow_up_date = db.Column(db.Date)
    status = db.Column(db.String(50), default='nowy')
    source = db.Column(db.String(100))
    potential_value = db.Column(db.Float, default=0)
    sale_value = db.Column(db.Float, default=0)
    commission = db.Column(db.Float, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    lead_id = db.Column(db.Integer, db.ForeignKey('lead.id'), nullable=False)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_status_color(status):
    colors = {'nowy': 'secondary', 'umówione spotkanie': 'warning', 'oczekiwanie': 'warning', 'odezwać się': 'info', 'klient': 'success', 'spadł': 'danger'}
    return colors.get(status, 'secondary')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Zalogowano!', 'success')
            return redirect(url_for('index'))
        flash('Błędne dane', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    leads = Lead.query.filter_by(user_id=session['user_id']).all()
    stats = {'total': len(leads), 'nowy': len([l for l in leads if l.status == 'nowy']), 'klient': len([l for l in leads if l.status == 'klient'])}
    return render_template('index.html', leads=leads, stats=stats, get_status_color=get_status_color)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_lead():
    if request.method == 'POST':
        birth_date = None
        follow_up = None
        if request.form.get('birth_date'):
            try:
                birth_date = datetime.strptime(request.form.get('birth_date'), '%Y-%m-%d').date()
            except:
                pass
        if request.form.get('follow_up_date'):
            try:
                follow_up = datetime.strptime(request.form.get('follow_up_date'), '%Y-%m-%d').date()
            except:
                pass
        lead = Lead(first_name=request.form.get('first_name'), last_name=request.form.get('last_name'), phone=request.form.get('phone'), email=request.form.get('email'), birth_date=birth_date, follow_up_date=follow_up, status=request.form.get('status', 'nowy'), source=request.form.get('source'), potential_value=float(request.form.get('potential_value', 0) or 0), user_id=session['user_id'])
        db.session.add(lead)
        db.session.commit()
        flash('Lead dodany!', 'success')
        return redirect(url_for('index'))
    return render_template('add_lead.html')

@app.route('/lead/<int:lead_id>')
@login_required
def lead_detail(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    notes = Note.query.filter_by(lead_id=lead_id).order_by(Note.created_at.desc()).all()
    return render_template('lead_detail.html', lead=lead, notes=notes, get_status_color=get_status_color)

@app.route('/add_note/<int:lead_id>', methods=['POST'])
@login_required
def add_note(lead_id):
    content = request.form.get('content')
    if content:
        note = Note(content=content, lead_id=lead_id)
        db.session.add(note)
        db.session.commit()
        flash('Notatka dodana!', 'success')
    return redirect(url_for('lead_detail', lead_id=lead_id))

@app.route('/delete/<int:lead_id>', methods=['POST'])
@login_required
def delete_lead(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    db.session.delete(lead)
    db.session.commit()
    flash('Lead usunięty', 'info')
    return redirect(url_for('index'))
@app.route('/edit/<int:lead_id>', methods=['GET', 'POST'])
@login_required
def edit_lead(lead_id):
    lead = Lead.query.get_or_404(lead_id)
    if request.method == 'POST':
        lead.first_name = request.form.get('first_name')
        lead.last_name = request.form.get('last_name')
        lead.phone = request.form.get('phone')
        lead.email = request.form.get('email')
        lead.status = request.form.get('status')
        lead.source = request.form.get('source')
        if request.form.get('birth_date'):
            try:
                lead.birth_date = datetime.strptime(request.form.get('birth_date'), '%Y-%m-%d').date()
            except:
                pass
        if request.form.get('follow_up_date'):
            try:
                lead.follow_up_date = datetime.strptime(request.form.get('follow_up_date'), '%Y-%m-%d').date()
            except:
                pass
        try:
            lead.potential_value = float(request.form.get('potential_value', 0) or 0)
            lead.sale_value = float(request.form.get('sale_value', 0) or 0)
            lead.commission = float(request.form.get('commission', 0) or 0)
        except:
            pass
        db.session.commit()
        flash('Lead zaktualizowany!', 'success')
        return redirect(url_for('lead_detail', lead_id=lead.id))
    return render_template('edit_lead.html', lead=lead)

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    status = request.args.get('status', '')
    leads_query = Lead.query.filter_by(user_id=session['user_id'])
    if query:
        pattern = f"%{query}%"
        leads_query = leads_query.filter(db.or_(Lead.first_name.like(pattern), Lead.last_name.like(pattern), Lead.phone.like(pattern), Lead.email.like(pattern)))
    if status:
        leads_query = leads_query.filter_by(status=status)
    leads = leads_query.order_by(Lead.created_at.desc()).all()
    stats = {'total': len(leads), 'nowy': len([l for l in leads if l.status == 'nowy']), 'klient': len([l for l in leads if l.status == 'klient'])}
    return render_template('index.html', leads=leads, stats=stats, get_status_color=get_status_color, search_query=query, status_filter=status)

@app.route('/export')
@login_required
def export_csv():
    import csv, io
    from flask import make_response
    leads = Lead.query.filter_by(user_id=session['user_id']).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Imię', 'Nazwisko', 'Telefon', 'Email', 'Status', 'Źródło', 'Wartość'])
    for lead in leads:
        writer.writerow([lead.first_name, lead.last_name, lead.phone or '', lead.email or '', lead.status, lead.source or '', lead.potential_value])
    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=leady.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response

def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@crm.com', password_hash=generate_password_hash('admin123'), role='admin', is_approved=True)
            db.session.add(admin)
            db.session.commit()
            print("✓ Admin: admin / admin123")

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
