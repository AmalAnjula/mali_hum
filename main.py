from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import csv
import io
import os
import json

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
    moisture_min = db.Column(db.String(20), nullable=False)  # Can be number or "-"
    moisture_max = db.Column(db.String(20), nullable=False)
    weight_min = db.Column(db.String(20), nullable=False)
    weight_max = db.Column(db.String(20), nullable=False)
    thickness_min = db.Column(db.String(20), nullable=False)
    thickness_max = db.Column(db.String(20), nullable=False)
    breadth_min = db.Column(db.String(20), nullable=False)
    breadth_max = db.Column(db.String(20), nullable=False)
    length_min = db.Column(db.String(20), nullable=False)
    length_max = db.Column(db.String(20), nullable=False)
    diameter_min = db.Column(db.String(20), nullable=False)
    diameter_max = db.Column(db.String(20), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    quality_checks = db.relationship('QualityCheck', backref='product', lazy=True)

class QualityCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.String(50), db.ForeignKey('product.id'), nullable=False)
    check_date = db.Column(db.DateTime, default=datetime.utcnow)
    moisture = db.Column(db.String(20), nullable=False)  # Can be number or "-"
    weight = db.Column(db.String(20), nullable=False)
    thickness = db.Column(db.String(20), nullable=False)
    breadth = db.Column(db.String(20), nullable=False)
    length = db.Column(db.String(20), nullable=False)
    diameter = db.Column(db.String(20), nullable=False)
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
        
        # Create json_data folder if it doesn't exist
        if not os.path.exists('json_data'):
            os.makedirs('json_data')
            print("Created json_data folder for quality check JSON files")

def save_quality_check_json(quality_check, product):
    """Save quality check data to JSON file for the plant"""
    try:
        # Create filename based on plant name
        plant_name = product.plant.replace(' ', '_').lower()
        filename = f'json_data/{plant_name}_quality_checks.json'
        
        # Helper to convert value
        def convert_value(val):
            if val == '-':
                return '-'
            try:
                return float(val)
            except:
                return '-'
        
        # Prepare the data
        check_data = {
            'check_id': quality_check.id,
            'check_date': quality_check.check_date.strftime('%Y-%m-%d %H:%M:%S'),
            'inspector': quality_check.username,
            'product': {
                'id': product.id,
                'plant': product.plant,
                'product_name': product.product
            },
            'specifications': {
                'moisture': {'min': convert_value(product.moisture_min), 'max': convert_value(product.moisture_max)},
                'weight': {'min': convert_value(product.weight_min), 'max': convert_value(product.weight_max)},
                'thickness': {'min': convert_value(product.thickness_min), 'max': convert_value(product.thickness_max)},
                'breadth': {'min': convert_value(product.breadth_min), 'max': convert_value(product.breadth_max)},
                'length': {'min': convert_value(product.length_min), 'max': convert_value(product.length_max)},
                'diameter': {'min': convert_value(product.diameter_min), 'max': convert_value(product.diameter_max)}
            },
            'measurements': {
                'moisture': convert_value(quality_check.moisture),
                'weight': convert_value(quality_check.weight),
                'thickness': convert_value(quality_check.thickness),
                'breadth': convert_value(quality_check.breadth),
                'length': convert_value(quality_check.length),
                'diameter': convert_value(quality_check.diameter)
            },
            'status': quality_check.status,
            'notes': quality_check.notes
        }
        
        # Read existing data or create new list
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                data = json.load(f)
        else:
            data = []
        
        # Append new check
        data.append(check_data)
        
        # Write back to file
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        
        print(f"Quality check saved to {filename}")
        return True
    except Exception as e:
        print(f"Error saving JSON: {str(e)}")
        return False

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
            
            # Validate all numeric fields (can be number or "-")
            def validate_field(value, field_name):
                value = value.strip()
                if not value:
                    raise ValueError(f'{field_name} cannot be empty')
                if value != '-':
                    try:
                        float(value)
                    except ValueError:
                        raise ValueError(f'{field_name} must be a number or "-"')
                return value
            
            new_product = Product(
                id=product_id,
                plant=request.form.get('plant'),
                product=request.form.get('product'),
                moisture_min=validate_field(request.form.get('moisture_min'), 'Moisture Min'),
                moisture_max=validate_field(request.form.get('moisture_max'), 'Moisture Max'),
                weight_min=validate_field(request.form.get('weight_min'), 'Weight Min'),
                weight_max=validate_field(request.form.get('weight_max'), 'Weight Max'),
                thickness_min=validate_field(request.form.get('thickness_min'), 'Thickness Min'),
                thickness_max=validate_field(request.form.get('thickness_max'), 'Thickness Max'),
                breadth_min=validate_field(request.form.get('breadth_min'), 'Breadth Min'),
                breadth_max=validate_field(request.form.get('breadth_max'), 'Breadth Max'),
                length_min=validate_field(request.form.get('length_min'), 'Length Min'),
                length_max=validate_field(request.form.get('length_max'), 'Length Max'),
                diameter_min=validate_field(request.form.get('diameter_min'), 'Diameter Min'),
                diameter_max=validate_field(request.form.get('diameter_max'), 'Diameter Max'),
                username=session['username']
            )
            db.session.add(new_product)
            db.session.commit()
            flash(f'Product "{product_id}" created successfully', 'success')
            return redirect(url_for('products'))
        except ValueError as e:
            flash(str(e), 'danger')
        except Exception as e:
            flash(f'Error creating product: {str(e)}', 'danger')
    
    return render_template('create_product.html')

@app.route('/edit-product/<product_id>', methods=['GET', 'POST'])
@admin_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    if request.method == 'POST':
        try:
            # Validate all numeric fields (can be number or "-")
            def validate_field(value, field_name):
                value = value.strip()
                if not value:
                    raise ValueError(f'{field_name} cannot be empty')
                if value != '-':
                    try:
                        float(value)
                    except ValueError:
                        raise ValueError(f'{field_name} must be a number or "-"')
                return value
            
            product.plant = request.form.get('plant')
            product.product = request.form.get('product')
            product.moisture_min = validate_field(request.form.get('moisture_min'), 'Moisture Min')
            product.moisture_max = validate_field(request.form.get('moisture_max'), 'Moisture Max')
            product.weight_min = validate_field(request.form.get('weight_min'), 'Weight Min')
            product.weight_max = validate_field(request.form.get('weight_max'), 'Weight Max')
            product.thickness_min = validate_field(request.form.get('thickness_min'), 'Thickness Min')
            product.thickness_max = validate_field(request.form.get('thickness_max'), 'Thickness Max')
            product.breadth_min = validate_field(request.form.get('breadth_min'), 'Breadth Min')
            product.breadth_max = validate_field(request.form.get('breadth_max'), 'Breadth Max')
            product.length_min = validate_field(request.form.get('length_min'), 'Length Min')
            product.length_max = validate_field(request.form.get('length_max'), 'Length Max')
            product.diameter_min = validate_field(request.form.get('diameter_min'), 'Diameter Min')
            product.diameter_max = validate_field(request.form.get('diameter_max'), 'Diameter Max')
            
            db.session.commit()
            flash('Product updated successfully', 'success')
            return redirect(url_for('products'))
        except ValueError as e:
            flash(str(e), 'danger')
    
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
            product = Product.query.get(product_id)
            
            if not product:
                flash('Product not found', 'danger')
                return redirect(url_for('quality_check'))
            
            # Helper function to get measurement value or "-"
            def get_measurement(field_name):
                value = request.form.get(field_name, '').strip()
                if value == '-' or value == '':
                    return '-'
                try:
                    return float(value)
                except ValueError:
                    return '-'
            
            measurement = QualityCheck(
                product_id=product_id,
                moisture=get_measurement('moisture'),
                weight=get_measurement('weight'),
                thickness=get_measurement('thickness'),
                breadth=get_measurement('breadth'),
                length=get_measurement('length'),
                diameter=get_measurement('diameter'),
                username=session['username']
            )
            
            # Check if measurements are within specs (skip "-" values)
            issues = []
            
            def check_spec(param_name, measurement_val, min_val, max_val):
                if measurement_val == '-' or min_val == '-' or max_val == '-':
                    return True  # Skip validation
                try:
                    m = float(measurement_val)
                    min_v = float(min_val)
                    max_v = float(max_val)
                    return min_v <= m <= max_v
                except:
                    return True  # Skip if conversion fails
            
            if not check_spec('Moisture', measurement.moisture, product.moisture_min, product.moisture_max):
                issues.append('Moisture')
            if not check_spec('Weight', measurement.weight, product.weight_min, product.weight_max):
                issues.append('Weight')
            if not check_spec('Thickness', measurement.thickness, product.thickness_min, product.thickness_max):
                issues.append('Thickness')
            if not check_spec('Breadth', measurement.breadth, product.breadth_min, product.breadth_max):
                issues.append('Breadth')
            if not check_spec('Length', measurement.length, product.length_min, product.length_max):
                issues.append('Length')
            if not check_spec('Diameter', measurement.diameter, product.diameter_min, product.diameter_max):
                issues.append('Diameter')
            
            measurement.status = 'FAIL' if issues else 'PASS'
            measurement.notes = f"Out of spec: {', '.join(issues)}" if issues else 'All measurements within spec'
            
            db.session.add(measurement)
            db.session.commit()
            
            # Save to JSON file
            save_quality_check_json(measurement, product)
            
            if issues:
                flash(f'Quality Check FAILED - Out of spec: {", ".join(issues)}', 'danger')
            else:
                flash('Quality Check PASSED - All measurements within spec', 'success')
                
            return redirect(url_for('quality_history'))
        except ValueError as e:
            flash(f'Error: {str(e)}', 'danger')
        except Exception as e:
            flash(f'Error submitting quality check: {str(e)}', 'danger')
    
    products = Product.query.all()
    return render_template('quality_check.html', products=products)

@app.route('/get-product-specs/<product_id>')
@login_required
def get_product_specs(product_id):
    product = Product.query.get_or_404(product_id)
    
    def convert_value(val):
        if val == '-':
            return '-'
        try:
            return float(val)
        except:
            return '-'
    
    return {
        'plant': product.plant,
        'product': product.product,
        'moisture_min': convert_value(product.moisture_min),
        'moisture_max': convert_value(product.moisture_max),
        'weight_min': convert_value(product.weight_min),
        'weight_max': convert_value(product.weight_max),
        'thickness_min': convert_value(product.thickness_min),
        'thickness_max': convert_value(product.thickness_max),
        'breadth_min': convert_value(product.breadth_min),
        'breadth_max': convert_value(product.breadth_max),
        'length_min': convert_value(product.length_min),
        'length_max': convert_value(product.length_max),
        'diameter_min': convert_value(product.diameter_min),
        'diameter_max': convert_value(product.diameter_max)
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

@app.route('/display-dashboard2')
def display_dashboard():
    plants = ['Plant 1', 'Plant 2','Plant 3', 'Plant 4']
    return render_template('display_dashboard2.html' )

@app.route('/display-dashboard2')
def display_dashboard2():
    return render_template('display_dashboard2.html')

@app.route('/get-latest-check/<plant>')
def get_latest_check(plant):
    # Convert plant name to filename format
    plant_name = plant.replace(' ', '_').lower()
    filename = f'json_data/{plant_name}_quality_checks.json'
    
    # Check if file exists
    if not os.path.exists(filename):
        return {'error': f'No data available for {plant}'}, 404
    
    try:
        # Read JSON file
        with open(filename, 'r') as f:
            data = json.load(f)
        
        # Get the latest check (last item in array)
        if not data or len(data) == 0:
            return {'error': f'No quality checks found for {plant}'}, 404
        
        latest_check = data[-1]  # Last item is the latest
        
        def get_spec_value(spec_dict, key):
            val = spec_dict.get(key, '-')
            return val if val != '-' else '-'
        
        def get_measurement_value(meas_dict, key):
            val = meas_dict.get(key, '-')
            return val if val != '-' else '-'
        
        return {
            'check_date': latest_check['check_date'],
            'product_name': latest_check['product']['product_name'],
            'plant': latest_check['product']['plant'],
            'status': latest_check['status'],
            'data': {
                'moisture': {
                    'value': get_measurement_value(latest_check['measurements'], 'moisture'),
                    'min': get_spec_value(latest_check['specifications']['moisture'], 'min'),
                    'max': get_spec_value(latest_check['specifications']['moisture'], 'max')
                },
                'weight': {
                    'value': get_measurement_value(latest_check['measurements'], 'weight'),
                    'min': get_spec_value(latest_check['specifications']['weight'], 'min'),
                    'max': get_spec_value(latest_check['specifications']['weight'], 'max')
                },
                'thickness': {
                    'value': get_measurement_value(latest_check['measurements'], 'thickness'),
                    'min': get_spec_value(latest_check['specifications']['thickness'], 'min'),
                    'max': get_spec_value(latest_check['specifications']['thickness'], 'max')
                },
                'breadth': {
                    'value': get_measurement_value(latest_check['measurements'], 'breadth'),
                    'min': get_spec_value(latest_check['specifications']['breadth'], 'min'),
                    'max': get_spec_value(latest_check['specifications']['breadth'], 'max')
                },
                'length': {
                    'value': get_measurement_value(latest_check['measurements'], 'length'),
                    'min': get_spec_value(latest_check['specifications']['length'], 'min'),
                    'max': get_spec_value(latest_check['specifications']['length'], 'max')
                },
                'diameter': {
                    'value': get_measurement_value(latest_check['measurements'], 'diameter'),
                    'min': get_spec_value(latest_check['specifications']['diameter'], 'min'),
                    'max': get_spec_value(latest_check['specifications']['diameter'], 'max')
                }
            }
        }
    except json.JSONDecodeError:
        return {'error': f'Invalid JSON file for {plant}'}, 500
    except Exception as e:
        return {'error': f'Error reading data: {str(e)}'}, 500

@app.route('/get-moisture-history/<plant>')
def get_moisture_history(plant):
    # Convert plant name to filename format
    plant_name = plant.replace(' ', '_').lower()
    filename = f'json_data/{plant_name}_quality_checks.json'
    
    # Check if file exists
    if not os.path.exists(filename):
        return {'error': f'No data available for {plant}'}, 404
    
    try:
        # Read JSON file
        with open(filename, 'r') as f:
            data = json.load(f)
        
        if not data or len(data) == 0:
            return {'error': f'No quality checks found for {plant}'}, 404
        
        # Get last 5 moisture readings
        last_5 = data[-5:] if len(data) >= 5 else data
        
        moisture_history = []
        for check in last_5:
            moisture_history.append({
                'check_date': check['check_date'],
                'moisture': check['measurements']['moisture'],
                'min': check['specifications']['moisture']['min'],
                'max': check['specifications']['moisture']['max'],
                'status': 'In Spec' if check['specifications']['moisture']['min'] <= check['measurements']['moisture'] <= check['specifications']['moisture']['max'] else 'Out of Spec'
            })
        
        return {'history': moisture_history}
    except json.JSONDecodeError:
        return {'error': f'Invalid JSON file for {plant}'}, 500
    except Exception as e:
        return {'error': f'Error reading data: {str(e)}'}, 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True,host='0.0.0.0', port=5000)