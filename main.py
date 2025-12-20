from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import csv
import io
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'ADMIN' or 'USER'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Product(db.Model):
    id = db.Column(db.String(50), primary_key=True)  # User-defined ID
    create_date = db.Column(db.DateTime, default=datetime.utcnow)
    plant = db.Column(db.String(100), nullable=False)
    product = db.Column(db.String(100), nullable=False)
    moisture_min = db.Column(db.Float, nullable=False)
    moisture_max = db.Column(db.Float, nullable=False)
    weight_min = db.Column(db.Float, nullable=False)
    weight_max = db.Column(db.Float, nullable=False)
    thickness_min = db.Column(db.Float, nullable=False)
    thickness_max = db.Column(db.Float, nullable=False)
    breadth_min = db.Column(db.Float, nullable=False)
    breadth_max = db.Column(db.Float, nullable=False)
    length_min = db.Column(db.Float, nullable=False)
    length_max = db.Column(db.Float, nullable=False)
    diameter_min = db.Column(db.Float, nullable=False)
    diameter_max = db.Column(db.Float, nullable=False)
    username = db.Column(db.String(80), nullable=False)
    quality_checks = db.relationship('QualityCheck', backref='product', lazy=True)

class QualityCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.String(50), db.ForeignKey('product.id'), nullable=False)
    check_date = db.Column(db.DateTime, default=datetime.utcnow)
    moisture = db.Column(db.Float, nullable=False)
    weight = db.Column(db.Float, nullable=False)
    thickness = db.Column(db.Float, nullable=False)
    breadth = db.Column(db.Float, nullable=False)
    length = db.Column(db.Float, nullable=False)
    diameter = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), nullable=False)  # 'PASS' or 'FAIL'
    notes = db.Column(db.String(500))
    username = db.Column(db.String(80), nullable=False)

# Initialize database and create default admin
def init_db():
    with app.app_context():
        db.create_all()
        # Create default admin if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password=generate_password_hash('admin123'),
                role='ADMIN'
            )
            db.session.add(admin)
            db.session.commit()
            print("Default admin created - username: admin, password: admin123")

# Decorators
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'danger')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.role != 'ADMIN':
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash(f'Welcome {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        user = User.query.get(session['user_id'])
        
        if not check_password_hash(user.password, current_password):
            flash('Current password is incorrect', 'danger')
        elif new_password != confirm_password:
            flash('New passwords do not match', 'danger')
        elif len(new_password) < 6:
            flash('Password must be at least 6 characters', 'danger')
        else:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Password changed successfully', 'success')
            return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

@app.route('/users')
@admin_required
def users():
    all_users = User.query.all()
    return render_template('users.html', users=all_users)

@app.route('/create-user', methods=['GET', 'POST'])
@admin_required
def create_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
        elif len(password) < 6:
            flash('Password must be at least 6 characters', 'danger')
        else:
            new_user = User(
                username=username,
                password=generate_password_hash(password),
                role=role
            )
            db.session.add(new_user)
            db.session.commit()
            flash('User created successfully', 'success')
            return redirect(url_for('users'))
    
    return render_template('create_user.html')

@app.route('/edit-user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        
        if username != user.username and User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
        else:
            user.username = username
            user.role = role
            if password:
                if len(password) < 6:
                    flash('Password must be at least 6 characters', 'danger')
                    return render_template('edit_user.html', user=user)
                user.password = generate_password_hash(password)
            db.session.commit()
            flash('User updated successfully', 'success')
            return redirect(url_for('users'))
    
    return render_template('edit_user.html', user=user)

@app.route('/delete-user/<int:user_id>')
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == session['user_id']:
        flash('Cannot delete your own account', 'danger')
    else:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully', 'success')
    return redirect(url_for('users'))

@app.route('/products')
@login_required
def products():
    # Get filter parameters
    plant = request.args.get('plant', '')
    product = request.args.get('product', '')
    username = request.args.get('username', '')
    
    query = Product.query
    
    if plant:
        query = query.filter(Product.plant.contains(plant))
    if product:
        query = query.filter(Product.product.contains(product))
    if username:
        query = query.filter(Product.username.contains(username))
    
    all_products = query.order_by(Product.create_date.desc()).all()
    return render_template('products.html', products=all_products)

@app.route('/create-product', methods=['GET', 'POST'])
@admin_required
def create_product():
    if request.method == 'POST':
        try:
            # Get and validate product ID
            product_id = request.form.get('id')
            if not product_id:
                flash('Product ID cannot be empty', 'danger')
                return render_template('create_product.html')
            
            product_id = product_id.strip()
            
            # Check if ID is empty after stripping
            if not product_id:
                flash('Product ID cannot be empty', 'danger')
                return render_template('create_product.html')
            
            # Check for duplicate ID
            if Product.query.get(product_id):
                flash(f'Product ID "{product_id}" already exists! Please use a different ID.', 'danger')
                return render_template('create_product.html')
            
            new_product = Product(
                id=product_id,
                plant=request.form.get('plant'),
                product=request.form.get('product'),
                moisture_min=float(request.form.get('moisture_min')),
                moisture_max=float(request.form.get('moisture_max')),
                weight_min=float(request.form.get('weight_min')),
                weight_max=float(request.form.get('weight_max')),
                thickness_min=float(request.form.get('thickness_min')),
                thickness_max=float(request.form.get('thickness_max')),
                breadth_min=float(request.form.get('breadth_min')),
                breadth_max=float(request.form.get('breadth_max')),
                length_min=float(request.form.get('length_min')),
                length_max=float(request.form.get('length_max')),
                diameter_min=float(request.form.get('diameter_min')),
                diameter_max=float(request.form.get('diameter_max')),
                username=session['username']
            )
            db.session.add(new_product)
            db.session.commit()
            flash(f'Product "{product_id}" created successfully', 'success')
            return redirect(url_for('products'))
        except ValueError:
            flash('All numeric fields must be valid numbers', 'danger')
        except Exception as e:
            flash(f'Error creating product: {str(e)}', 'danger')
    
    return render_template('create_product.html')

@app.route('/edit-product/<product_id>', methods=['GET', 'POST'])
@admin_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    if request.method == 'POST':
        try:
            product.plant = request.form.get('plant')
            product.product = request.form.get('product')
            product.moisture_min = float(request.form.get('moisture_min'))
            product.moisture_max = float(request.form.get('moisture_max'))
            product.weight_min = float(request.form.get('weight_min'))
            product.weight_max = float(request.form.get('weight_max'))
            product.thickness_min = float(request.form.get('thickness_min'))
            product.thickness_max = float(request.form.get('thickness_max'))
            product.breadth_min = float(request.form.get('breadth_min'))
            product.breadth_max = float(request.form.get('breadth_max'))
            product.length_min = float(request.form.get('length_min'))
            product.length_max = float(request.form.get('length_max'))
            product.diameter_min = float(request.form.get('diameter_min'))
            product.diameter_max = float(request.form.get('diameter_max'))
            
            db.session.commit()
            flash('Product updated successfully', 'success')
            return redirect(url_for('products'))
        except ValueError:
            flash('All numeric fields must be valid numbers', 'danger')
    
    return render_template('edit_product.html', product=product)

@app.route('/delete-product/<product_id>')
@admin_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully', 'success')
    return redirect(url_for('products'))

@app.route('/export-csv')
@login_required
def export_csv():
    plant = request.args.get('plant', '')
    product = request.args.get('product', '')
    username = request.args.get('username', '')
    
    query = Product.query
    
    if plant:
        query = query.filter(Product.plant.contains(plant))
    if product:
        query = query.filter(Product.product.contains(product))
    if username:
        query = query.filter(Product.username.contains(username))
    
    products = query.all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(['ID', 'Create Date', 'Plant', 'Product', 'Moisture Min', 'Moisture Max', 
                     'Weight Min', 'Weight Max', 'Thickness Min', 'Thickness Max', 
                     'Breadth Min', 'Breadth Max', 'Length Min', 'Length Max', 
                     'Diameter Min', 'Diameter Max', 'Username'])
    
    for p in products:
        writer.writerow([p.id, p.create_date.strftime('%Y-%m-%d %H:%M:%S'), p.plant, p.product,
                        p.moisture_min, p.moisture_max, p.weight_min, p.weight_max,
                        p.thickness_min, p.thickness_max, p.breadth_min, p.breadth_max,
                        p.length_min, p.length_max, p.diameter_min, p.diameter_max, p.username])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'products_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

@app.route('/quality-check', methods=['GET', 'POST'])
@login_required
def quality_check():
    if request.method == 'POST':
        try:
            product_id = request.form.get('product_id')
            
            measurement = QualityCheck(
                product_id=product_id,
                moisture=float(request.form.get('moisture')),
                weight=float(request.form.get('weight')),
                thickness=float(request.form.get('thickness')),
                breadth=float(request.form.get('breadth')),
                length=float(request.form.get('length')),
                diameter=float(request.form.get('diameter')),
                username=session['username']
            )
            
            # Get product specs for validation
            product = Product.query.get(product_id)
            
            # Check if measurements are within specs
            issues = []
            if not (product.moisture_min <= measurement.moisture <= product.moisture_max):
                issues.append('Moisture')
            if not (product.weight_min <= measurement.weight <= product.weight_max):
                issues.append('Weight')
            if not (product.thickness_min <= measurement.thickness <= product.thickness_max):
                issues.append('Thickness')
            if not (product.breadth_min <= measurement.breadth <= product.breadth_max):
                issues.append('Breadth')
            if not (product.length_min <= measurement.length <= product.length_max):
                issues.append('Length')
            if not (product.diameter_min <= measurement.diameter <= product.diameter_max):
                issues.append('Diameter')
            
            measurement.status = 'FAIL' if issues else 'PASS'
            measurement.notes = f"Out of spec: {', '.join(issues)}" if issues else 'All measurements within spec'
            
            db.session.add(measurement)
            db.session.commit()
            
            if issues:
                flash(f'Quality Check FAILED - Out of spec: {", ".join(issues)}', 'danger')
            else:
                flash('Quality Check PASSED - All measurements within spec', 'success')
                
            return redirect(url_for('quality_history'))
        except ValueError:
            flash('All fields must be valid numbers', 'danger')
    
    products = Product.query.all()
    return render_template('quality_check.html', products=products)

@app.route('/get-product-specs/<product_id>')
@login_required
def get_product_specs(product_id):
    product = Product.query.get_or_404(product_id)
    return {
        'plant': product.plant,
        'product': product.product,
        'moisture_min': product.moisture_min,
        'moisture_max': product.moisture_max,
        'weight_min': product.weight_min,
        'weight_max': product.weight_max,
        'thickness_min': product.thickness_min,
        'thickness_max': product.thickness_max,
        'breadth_min': product.breadth_min,
        'breadth_max': product.breadth_max,
        'length_min': product.length_min,
        'length_max': product.length_max,
        'diameter_min': product.diameter_min,
        'diameter_max': product.diameter_max
    }

@app.route('/quality-history')
@login_required
def quality_history():
    # Get filter parameters
    product = request.args.get('product', '')
    status = request.args.get('status', '')
    username = request.args.get('username', '')
    
    query = QualityCheck.query
    
    if product:
        query = query.join(Product).filter(Product.product.contains(product))
    if status:
        query = query.filter(QualityCheck.status == status)
    if username:
        query = query.filter(QualityCheck.username.contains(username))
    
    checks = query.order_by(QualityCheck.check_date.desc()).all()
    return render_template('quality_history.html', checks=checks)

@app.route('/export-quality-csv')
@login_required
def export_quality_csv():
    product = request.args.get('product', '')
    status = request.args.get('status', '')
    username = request.args.get('username', '')
    
    query = QualityCheck.query
    
    if product:
        query = query.join(Product).filter(Product.product.contains(product))
    if status:
        query = query.filter(QualityCheck.status == status)
    if username:
        query = query.filter(QualityCheck.username.contains(username))
    
    checks = query.all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(['ID', 'Check Date', 'Plant', 'Product', 'Moisture', 'Weight', 'Thickness',
                     'Breadth', 'Length', 'Diameter', 'Status', 'Notes', 'Username'])
    
    for c in checks:
        writer.writerow([
            c.id, c.check_date.strftime('%Y-%m-%d %H:%M:%S'),
            c.product.plant, c.product.product,
            c.moisture, c.weight, c.thickness, c.breadth, c.length, c.diameter,
            c.status, c.notes, c.username
        ])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'quality_checks_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

if __name__ == '__main__':
    init_db()
    app.run(debug=True)