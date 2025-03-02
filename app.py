from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, g
import sqlite3
from datetime import datetime, timedelta
import os
from werkzeug.security import generate_password_hash, check_password_hash
import json
import calendar
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)
DATABASE = 'expenses.db'

# Color palette for charts (muted, professional)
CHART_COLORS = [
    '#4A5568', '#718096', '#A0AEC0', '#CBD5E0', '#4299E1'
]

# Database helper functions
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def modify_db(query, args=()):
    conn = get_db()
    conn.execute(query, args)
    conn.commit()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Context processor to inject 'now' globally for templates
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# Initialize database
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Routes for user authentication
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
       
        error = None
        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif password != confirm_password:
            error = 'Passwords do not match.'
        elif query_db('SELECT id FROM users WHERE username = ?', [username], one=True) is not None:
            error = f"User {username} is already registered."
           
        if error is None:
            modify_db(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                (username, generate_password_hash(password))
            )
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
           
        flash(error, 'error')
       
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
       
        user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)
       
        error = None
        if user is None:
            error = 'Invalid username.'
        elif not check_password_hash(user['password'], password):
            error = 'Invalid password.'
           
        if error is None:
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
           
            # Check if user has profile info
            profile = query_db('SELECT * FROM user_profiles WHERE user_id = ?', [user['id']], one=True)
            if profile is None:
                return redirect(url_for('setup_profile'))
               
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
           
        flash(error, 'error')
       
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/setup_profile', methods=['GET', 'POST'])
@login_required
def setup_profile():
    if request.method == 'POST':
        salary = float(request.form['salary'])
        savings_target = float(request.form['savings_target'])
        currency = request.form['currency']
       
        modify_db(
            'INSERT OR REPLACE INTO user_profiles (user_id, salary, savings_target, currency) VALUES (?, ?, ?, ?)',
            (session['user_id'], salary, savings_target, currency)
        )
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('index'))
       
    return render_template('setup_profile.html')

# Main application routes
@app.route('/')
@login_required
def index():
    # Fetch yearly totals
    now = datetime.now()
    current_year = now.year
    total_expenses = query_db(
        'SELECT SUM(amount) as total FROM expenses WHERE user_id = ? AND date >= ? AND date < ?',
        [session['user_id'], f"{current_year}-01-01", f"{current_year+1}-01-01"], one=True
    )['total'] or 0
    total_income = query_db(
        'SELECT SUM(amount) as total FROM incomes WHERE user_id = ? AND date >= ? AND date < ?',
        [session['user_id'], f"{current_year}-01-01", f"{current_year+1}-01-01"], one=True
    )['total'] or 0
    
    return render_template('index.html', username=session['username'], 
                          total_expenses=total_expenses, total_income=total_income)

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user profile
    profile = query_db('SELECT * FROM user_profiles WHERE user_id = ?', [session['user_id']], one=True)
   
    if profile is None:
        return redirect(url_for('setup_profile'))
   
    # Define now for this function
    now = datetime.now()
    # Get current month and year
    current_month = now.month
    current_year = now.year
   
    # Calculate date range for current month
    start_date = f"{current_year}-{current_month:02d}-01"
    if current_month == 12:
        end_date = f"{current_year+1}-01-01"
    else:
        end_date = f"{current_year}-{current_month+1:02d}-01"
   
    # Get total expenses for current month
    total_expenses = query_db(
        'SELECT SUM(amount) as total FROM expenses WHERE user_id = ? AND date >= ? AND date < ?',
        [session['user_id'], start_date, end_date], one=True
    )
    monthly_expenses = total_expenses['total'] if total_expenses['total'] else 0
   
    # Category-wise data for current month
    category_data = query_db(
        '''SELECT c.name as category, COALESCE(SUM(e.amount), 0) as amount
           FROM categories c
           LEFT JOIN expenses e ON c.id = e.category_id AND e.user_id = ? AND e.date >= ? AND e.date < ?
           WHERE c.user_id = ? OR c.user_id IS NULL
           GROUP BY c.id
           ORDER BY amount DESC''',
        [session['user_id'], start_date, end_date, session['user_id']]
    )
   
    # Prepare data for charts
    categories = []
    amounts = []
    for item in category_data:
        if item['amount'] > 0:  # Only include categories with expenses
            categories.append(item['category'])
            amounts.append(float(item['amount']))
   
    # Monthly trend data (last 6 months)
    trend_data = []
    for i in range(5, -1, -1):
        month_date = now - timedelta(days=30*i)
        month_start = f"{month_date.year}-{month_date.month:02d}-01"
       
        if month_date.month == 12:
            month_end = f"{month_date.year+1}-01-01"
        else:
            month_end = f"{month_date.year}-{month_date.month+1:02d}-01"
           
        month_expense = query_db(
            'SELECT SUM(amount) as total FROM expenses WHERE user_id = ? AND date >= ? AND date < ?',
            [session['user_id'], month_start, month_end], one=True
        )
       
        trend_data.append({
            'month': calendar.month_name[month_date.month][:3],
            'amount': float(month_expense['total']) if month_expense['total'] else 0
        })
   
    # Budget calculations
    salary = float(profile['salary'])
    savings_target = float(profile['savings_target'])
    currency = profile['currency']
   
    spent_percent = round((monthly_expenses / salary * 100), 1) if salary > 0 else 0
    warning = spent_percent > 80
    remaining_budget = salary - monthly_expenses
    savings_progress = round(((salary - monthly_expenses) / savings_target * 100), 1) if savings_target > 0 else 0
   
    # Recent transactions
    recent_transactions = query_db(
        '''SELECT e.id, e.amount, c.name as category, e.date, e.note
           FROM expenses e
           JOIN categories c ON e.category_id = c.id
           WHERE e.user_id = ?
           ORDER BY e.date DESC LIMIT 5''',
        [session['user_id']]
    )
   
    # Get all categories for dropdown
    all_categories = query_db(
        'SELECT id, name FROM categories WHERE user_id = ? OR user_id IS NULL ORDER BY name',
        [session['user_id']]
    )
   
    return render_template(
        'dashboard.html',
        username=session['username'],
        salary=salary,
        savings_target=savings_target,
        monthly_expenses=monthly_expenses,
        remaining_budget=remaining_budget,
        spent_percent=spent_percent,
        warning=warning,
        savings_progress=savings_progress,
        categories=categories,
        amounts=amounts,
        trend_data=trend_data,
        recent_transactions=recent_transactions,
        all_categories=all_categories,
        currency=currency,
        chart_colors=CHART_COLORS
    )

@app.route('/expenses')
@login_required
def expenses():
    # Get all expenses
    all_expenses = query_db(
        '''SELECT e.id, e.amount, c.name as category, e.date, e.note
           FROM expenses e
           JOIN categories c ON e.category_id = c.id
           WHERE e.user_id = ?
           ORDER BY e.date DESC''',
        [session['user_id']]
    )
   
    # Get currency
    profile = query_db('SELECT currency FROM user_profiles WHERE user_id = ?', [session['user_id']], one=True)
    currency = profile['currency'] if profile else '₹'
   
    # Get all categories for filter
    all_categories = query_db(
        'SELECT id, name FROM categories WHERE user_id = ? OR user_id IS NULL ORDER BY name',
        [session['user_id']]
    )
   
    return render_template(
        'expenses.html',
        expenses=all_expenses,
        categories=all_categories,
        currency=currency
    )

@app.route('/add_expense', methods=['POST'])
@login_required
def add_expense():
    amount = float(request.form['amount'])
    category_id = int(request.form['category'])
    date = request.form['date']
    note = request.form.get('note', '')
   
    modify_db(
        'INSERT INTO expenses (user_id, amount, category_id, date, note) VALUES (?, ?, ?, ?, ?)',
        (session['user_id'], amount, category_id, date, note)
    )
   
    flash('Expense added successfully!', 'success')
    if request.form.get('source') == 'expenses':
        return redirect(url_for('expenses'))
    return redirect(url_for('dashboard'))

@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):
    expense = query_db(
        'SELECT e.id, e.amount, e.category_id, e.date, e.note, c.name as category_name '
        'FROM expenses e JOIN categories c ON e.category_id = c.id '
        'WHERE e.id = ? AND e.user_id = ?', [expense_id, session['user_id']], one=True
    )
    if not expense:
        flash('Expense not found or you do not have permission to edit it.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        amount = float(request.form['amount'])
        category_id = int(request.form['category'])
        date = request.form['date']
        note = request.form.get('note', '')
        
        modify_db(
            'UPDATE expenses SET amount = ?, category_id = ?, date = ?, note = ? WHERE id = ?',
            (amount, category_id, date, note, expense_id)
        )
        flash('Expense updated successfully!', 'success')
        if request.form.get('source') == 'expenses':
            return redirect(url_for('expenses'))
        return redirect(url_for('dashboard'))
    
    categories = query_db('SELECT id, name FROM categories WHERE user_id = ? OR user_id IS NULL ORDER BY name', [session['user_id']])
    return render_template('edit_expense.html', expense=expense, categories=categories, currency=expense['category_name'])

@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
@login_required
def delete_expense(expense_id):
    # Check if expense belongs to user
    expense = query_db(
        'SELECT * FROM expenses WHERE id = ? AND user_id = ?',
        [expense_id, session['user_id']], one=True
    )
   
    if expense:
        modify_db('DELETE FROM expenses WHERE id = ?', [expense_id])
        flash('Expense deleted successfully!', 'success')
    else:
        flash('Expense not found or you do not have permission to delete it.', 'error')
   
    if request.form.get('source') == 'expenses':
        return redirect(url_for('expenses'))
    return redirect(url_for('dashboard'))

@app.route('/add_income', methods=['POST'])
@login_required
def add_income():
    amount = float(request.form['amount'])
    date = request.form['date']
    source = request.form.get('source', '')
    note = request.form.get('note', '')
   
    modify_db(
        'INSERT INTO incomes (user_id, amount, date, source, note) VALUES (?, ?, ?, ?, ?)',
        (session['user_id'], amount, date, source, note)
    )
   
    flash('Income added successfully!', 'success')
    if request.form.get('source') == 'settings':
        return redirect(url_for('settings'))
    return redirect(url_for('dashboard'))

@app.route('/edit_income/<int:income_id>', methods=['GET', 'POST'])
@login_required
def edit_income(income_id):
    income = query_db(
        'SELECT id, amount, date, source, note FROM incomes WHERE id = ? AND user_id = ?',
        [income_id, session['user_id']], one=True
    )
    if not income:
        flash('Income not found or you do not have permission to edit it.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        amount = float(request.form['amount'])
        date = request.form['date']
        source = request.form.get('source', '')
        note = request.form.get('note', '')
        
        modify_db(
            'UPDATE incomes SET amount = ?, date = ?, source = ?, note = ? WHERE id = ?',
            (amount, date, source, note, income_id)
        )
        flash('Income updated successfully!', 'success')
        return redirect(url_for('settings'))
    
    return render_template('edit_income.html', income=income)

@app.route('/delete_income/<int:income_id>', methods=['POST'])
@login_required
def delete_income(income_id):
    income = query_db(
        'SELECT * FROM incomes WHERE id = ? AND user_id = ?',
        [income_id, session['user_id']], one=True
    )
    if income:
        modify_db('DELETE FROM incomes WHERE id = ?', [income_id])
        flash('Income deleted successfully!', 'success')
    else:
        flash('Income not found or you do not have permission to delete it.', 'error')
    return redirect(url_for('settings'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        action = request.form.get('action')
       
        if action == 'update_profile':
            salary = float(request.form['salary'])
            savings_target = float(request.form['savings_target'])
            currency = request.form['currency']
           
            modify_db(
                'UPDATE user_profiles SET salary = ?, savings_target = ?, currency = ? WHERE user_id = ?',
                (salary, savings_target, currency, session['user_id'])
            )
            flash('Profile updated successfully!', 'success')
           
        elif action == 'add_category':
            category_name = request.form['category_name'].strip()
            if category_name:
                # Check if category already exists
                existing = query_db(
                    'SELECT * FROM categories WHERE name = ? AND (user_id = ? OR user_id IS NULL)',
                    [category_name, session['user_id']], one=True
                )
               
                if not existing:
                    modify_db(
                        'INSERT INTO categories (name, user_id) VALUES (?, ?)',
                        (category_name, session['user_id'])
                    )
                    flash(f'Category "{category_name}" added successfully!', 'success')
                else:
                    flash(f'Category "{category_name}" already exists!', 'error')
       
        return redirect(url_for('settings'))
       
    # Get user profile
    profile = query_db('SELECT * FROM user_profiles WHERE user_id = ?', [session['user_id']], one=True)
   
    # Get user categories and incomes
    categories = query_db(
        'SELECT * FROM categories WHERE user_id = ? OR user_id IS NULL ORDER BY name',
        [session['user_id']]
    )
    incomes = query_db(
        'SELECT id, amount, date, source, note FROM incomes WHERE user_id = ? ORDER BY date DESC',
        [session['user_id']]
    )
   
    return render_template(
        'settings.html',
        profile=profile,
        categories=categories,
        incomes=incomes
    )

@app.route('/edit_category/<int:category_id>', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    category = query_db(
        'SELECT id, name FROM categories WHERE id = ? AND (user_id = ? OR user_id IS NULL)',
        [category_id, session['user_id']], one=True
    )
    if not category:
        flash('Category not found or you do not have permission to edit it.', 'error')
        return redirect(url_for('settings'))
    
    if request.method == 'POST':
        new_name = request.form['category_name'].strip()
        if new_name:
            # Check if the new name already exists for this user (or globally)
            existing = query_db(
                'SELECT * FROM categories WHERE name = ? AND (user_id = ? OR user_id IS NULL) AND id != ?',
                [new_name, session['user_id'], category_id], one=True
            )
            if not existing:
                modify_db(
                    'UPDATE categories SET name = ? WHERE id = ?',
                    (new_name, category_id)
                )
                flash(f'Category updated to "{new_name}" successfully!', 'success')
            else:
                flash(f'Category "{new_name}" already exists!', 'error')
        return redirect(url_for('settings'))
    
    return render_template('edit_category.html', category=category)

@app.route('/delete_category/<int:category_id>', methods=['POST'])
@login_required
def delete_category(category_id):
    category = query_db(
        'SELECT * FROM categories WHERE id = ? AND user_id = ?',
        [category_id, session['user_id']], one=True
    )
    if category:
        # Check if category is used in any expenses
        used = query_db(
            'SELECT COUNT(*) as count FROM expenses WHERE category_id = ? AND user_id = ?',
            [category_id, session['user_id']], one=True
        )
        if used['count'] > 0:
            flash('Cannot delete category: It is used in existing expenses.', 'error')
        else:
            modify_db('DELETE FROM categories WHERE id = ?', [category_id])
            flash('Category deleted successfully!', 'success')
    else:
        flash('Category not found or you do not have permission to delete it.', 'error')
    return redirect(url_for('settings'))

@app.route('/reports')
@login_required
def reports():
    # Get user profile for currency
    profile = query_db('SELECT currency FROM user_profiles WHERE user_id = ?', [session['user_id']], one=True)
    currency = profile['currency'] if profile else '₹'
   
    # Define now for this function
    now = datetime.now()
    # Get current year
    current_year = now.year
   
    # Monthly data for current year (expenses)
    monthly_expenses = []
    for month in range(1, 13):
        start_date = f"{current_year}-{month:02d}-01"
        if month == 12:
            end_date = f"{current_year+1}-01-01"
        else:
            end_date = f"{current_year}-{month+1:02d}-01"
           
        month_expense = query_db(
            'SELECT SUM(amount) as total FROM expenses WHERE user_id = ? AND date >= ? AND date < ?',
            [session['user_id'], start_date, end_date], one=True
        )
        monthly_expenses.append({
            'month': calendar.month_name[month],
            'amount': float(month_expense['total']) if month_expense['total'] else 0
        })
    
    # Monthly data for current year (incomes)
    monthly_incomes = []
    for month in range(1, 13):
        start_date = f"{current_year}-{month:02d}-01"
        if month == 12:
            end_date = f"{current_year+1}-01-01"
        else:
            end_date = f"{current_year}-{month+1:02d}-01"
           
        month_income = query_db(
            'SELECT SUM(amount) as total FROM incomes WHERE user_id = ? AND date >= ? AND date < ?',
            [session['user_id'], start_date, end_date], one=True
        )
        monthly_incomes.append({
            'month': calendar.month_name[month],
            'amount': float(month_income['total']) if month_income['total'] else 0
        })
   
    # Category breakdown for the year (expenses)
    category_expenses = query_db(
        '''SELECT c.name as category, COALESCE(SUM(e.amount), 0) as amount
           FROM categories c
           LEFT JOIN expenses e ON c.id = e.category_id AND e.user_id = ?
                                AND e.date >= ? AND e.date < ?
           WHERE c.user_id = ? OR c.user_id IS NULL
           GROUP BY c.id
           ORDER BY amount DESC''',
        [session['user_id'], f"{current_year}-01-01", f"{current_year+1}-01-01", session['user_id']]
    )
   
    # Prepare category data for charts
    categories = []
    amounts = []
    for item in category_expenses:
        if item['amount'] > 0:  # Only include categories with expenses
            categories.append(item['category'])
            amounts.append(float(item['amount']))
   
    return render_template(
        'reports.html',
        monthly_expenses=monthly_expenses,
        monthly_incomes=monthly_incomes,
        categories=categories,
        amounts=amounts,
        currency=currency,
        chart_colors=CHART_COLORS
    )

if __name__ == '__main__':
    # Create tables if they don't exist
    if not os.path.exists(DATABASE):
        with app.app_context():
            init_db()
   
    app.run(debug=True)
