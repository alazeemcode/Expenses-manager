from flask import Flask, render_template, request, redirect, url_for, flash, session, g, send_file
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, SelectField, DateField, DecimalField
from wtforms.validators import DataRequired, Length, EqualTo, NumberRange
import sqlite3
from datetime import datetime, timedelta
import os
from werkzeug.security import generate_password_hash, check_password_hash
import json
import calendar
import logging
from functools import wraps
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
app.logger = logging.getLogger(__name__)

# Set secret key from environment variable or default
app.secret_key = os.environ.get('SECRET_KEY', 'your-secure-random-key-here')
csrf = CSRFProtect(app)

DATABASE = 'expenses.db'

# Color palette for charts (muted, professional)
CHART_COLORS = [
    '#4A5568', '#718096', '#A0AEC0', '#CBD5E0', '#4299E1'
]

def get_db():
    """Get or create a database connection."""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_connection(exception):
    """Close the database connection at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    """Execute a database query with parameters to prevent SQL injection."""
    try:
        db = get_db()
        cur = db.execute(query, args)
        rv = cur.fetchall()
        cur.close()
        return (rv[0] if rv else None) if one else rv
    except sqlite3.Error as e:
        app.logger.error(f"Query error: {str(e)}")
        raise

def modify_db(query, args=()):
    """Execute a database modification with parameters."""
    try:
        db = get_db()
        db.execute(query, args)
        db.commit()
    except sqlite3.Error as e:
        app.logger.error(f"Modification error: {str(e)}")
        db.rollback()
        raise

# Login required decorator
def login_required(f):
    """Decorator to restrict access to logged-in users only.
    
    Args:
        f: Function to decorate.
    
    Returns:
        Wrapped function requiring user authentication.
    """
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
    """Inject the current datetime into templates."""
    return {'now': datetime.now()}

# Initialize database
def init_db():
    """Initialize the database with the schema from schema.sql."""
    try:
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
    except sqlite3.Error as e:
        app.logger.error(f"Database initialization error: {str(e)}")
        raise

# Forms
class LoginForm(FlaskForm):
    """Form for user login."""
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    """Form for user registration."""
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class SetupProfileForm(FlaskForm):
    """Form for user profile setup."""
    salary = DecimalField('Monthly Income', validators=[DataRequired(), NumberRange(min=0)])
    savings_target = DecimalField('Monthly Savings Goal', validators=[DataRequired(), NumberRange(min=0)])
    currency = SelectField('Currency', choices=[('₹', '₹'), ('$', '$'), ('€', '€'), ('£', '£'), ('¥', '¥')], default='₹')
    submit = SubmitField('Save Profile')

# Routes for user authentication
@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    app.logger.debug("Handling register request")
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        try:
            if query_db('SELECT id FROM users WHERE username = ?', [username], one=True) is not None:
                flash(f"User {username} is already registered.", 'error')
                return render_template('register.html', form=form)
            
            modify_db(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                (username, generate_password_hash(password, method='sha256'))
            )
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'An error occurred during registration: {str(e)}', 'error')
            app.logger.error(f"Registration error for {username}: {str(e)}")
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    app.logger.debug("Handling login request")
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        try:
            user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)
            if user is None:
                flash('Invalid username.', 'error')
            elif not check_password_hash(user['password'], password):
                flash('Invalid password.', 'error')
            else:
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']
                profile = query_db('SELECT * FROM user_profiles WHERE user_id = ?', [user['id']], one=True)
                if profile is None:
                    return redirect(url_for('setup_profile'))
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
        except Exception as e:
            flash(f'Login error: {str(e)}', 'error')
            app.logger.error(f"Login error for {username}: {str(e)}")
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    """Handle user logout."""
    app.logger.debug("Handling logout request")
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/setup_profile', methods=['GET', 'POST'])
@login_required
def setup_profile():
    """Handle user profile setup."""
    app.logger.debug("Handling setup_profile request")
    form = SetupProfileForm()
    if form.validate_on_submit():
        try:
            modify_db(
                'INSERT OR REPLACE INTO user_profiles (user_id, salary, savings_target, currency) VALUES (?, ?, ?, ?)',
                (session['user_id'], form.salary.data, form.savings_target.data, form.currency.data)
            )
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f'Profile setup error: {str(e)}', 'error')
            app.logger.error(f"Profile setup error for user {session['username']}: {str(e)}")
    
    return render_template('setup_profile.html', form=form)

# Main application routes
@app.route('/')
@login_required
def index():
    """Render the homepage with yearly financial overview."""
    app.logger.debug("Rendering homepage")
    now = datetime.now()
    current_year = now.year
    try:
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
    except Exception as e:
        flash(f'Error loading homepage: {str(e)}', 'error')
        app.logger.error(f"Homepage error for user {session['username']}: {str(e)}")
        return render_template('index.html', username=session['username'], total_expenses=0, total_income=0)

@app.route('/dashboard')
@login_required
def dashboard():
    """Render the dashboard with monthly financial overview."""
    app.logger.debug("Rendering dashboard")
    profile = query_db('SELECT * FROM user_profiles WHERE user_id = ?', [session['user_id']], one=True)
    if profile is None:
        return redirect(url_for('setup_profile'))
    
    now = datetime.now()
    current_month = now.month
    current_year = now.year
    start_date = f"{current_year}-{current_month:02d}-01"
    end_date = f"{current_year}-{current_month+1:02d}-01" if current_month < 12 else f"{current_year+1}-01-01"
    
    try:
        total_expenses = query_db(
            'SELECT SUM(amount) as total FROM expenses WHERE user_id = ? AND date >= ? AND date < ?',
            [session['user_id'], start_date, end_date], one=True
        )['total'] or 0
        category_data = query_db(
            '''SELECT c.name as category, COALESCE(SUM(e.amount), 0) as amount
               FROM categories c
               LEFT JOIN expenses e ON c.id = e.category_id AND e.user_id = ? AND e.date >= ? AND e.date < ?
               WHERE c.user_id = ? OR c.user_id IS NULL
               GROUP BY c.id
               ORDER BY amount DESC''',
            [session['user_id'], start_date, end_date, session['user_id']]
        )
        categories = [item['category'] for item in category_data if item['amount'] > 0]
        amounts = [float(item['amount']) for item in category_data if item['amount'] > 0]
        
        trend_data = []
        for i in range(5, -1, -1):
            month_date = now - timedelta(days=30*i)
            month_start = f"{month_date.year}-{month_date.month:02d}-01"
            month_end = f"{month_date.year}-{month_date.month+1:02d}-01" if month_date.month < 12 else f"{month_date.year+1}-01-01"
            month_expense = query_db(
                'SELECT SUM(amount) as total FROM expenses WHERE user_id = ? AND date >= ? AND date < ?',
                [session['user_id'], month_start, month_end], one=True
            )['total'] or 0
            trend_data.append({
                'month': calendar.month_name[month_date.month][:3],
                'amount': float(month_expense)
            })
        
        salary = float(profile['salary'])
        savings_target = float(profile['savings_target'])
        currency = profile['currency']
        
        spent_percent = round((total_expenses / salary * 100), 1) if salary > 0 else 0
        warning = spent_percent > 80
        remaining_budget = salary - total_expenses
        savings_progress = round(((salary - total_expenses) / savings_target * 100), 1) if savings_target > 0 else 0
        
        recent_transactions = query_db(
            '''SELECT e.id, e.amount, c.name as category, e.date, e.note
               FROM expenses e
               JOIN categories c ON e.category_id = c.id
               WHERE e.user_id = ?
               ORDER BY e.date DESC LIMIT 5''',
            [session['user_id']]
        )
        
        all_categories = query_db(
            'SELECT id, name FROM categories WHERE user_id = ? OR user_id IS NULL ORDER BY name',
            [session['user_id']]
        )
        
        return render_template(
            'dashboard.html',
            username=session['username'],
            salary=salary,
            savings_target=savings_target,
            monthly_expenses=total_expenses,
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
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        app.logger.error(f"Dashboard error for user {session['username']}: {str(e)}")
        return render_template('dashboard.html', username=session['username'], monthly_expenses=0, ...)

@app.route('/expenses')
@login_required
def expenses():
    """Render the expenses page with pagination and filtering."""
    app.logger.debug("Rendering expenses page")
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Items per page
    offset = (page - 1) * per_page
    
    # Basic query for all expenses (can be filtered later)
    try:
        all_expenses = query_db(
            '''SELECT e.id, e.amount, c.name as category, e.date, e.note
               FROM expenses e
               JOIN categories c ON e.category_id = c.id
               WHERE e.user_id = ?
               ORDER BY e.date DESC LIMIT ? OFFSET ?''',
            [session['user_id'], per_page, offset]
        )
        total_expenses = query_db(
            'SELECT COUNT(*) as count FROM expenses WHERE user_id = ?',
            [session['user_id']], one=True
        )['count']
        
        profile = query_db('SELECT currency FROM user_profiles WHERE user_id = ?', [session['user_id']], one=True)
        currency = profile['currency'] if profile else '₹'
        
        all_categories = query_db(
            'SELECT id, name FROM categories WHERE user_id = ? OR user_id IS NULL ORDER BY name',
            [session['user_id']]
        )
        
        return render_template(
            'expenses.html',
            expenses=all_expenses,
            categories=all_categories,
            currency=currency,
            page=page,
            per_page=per_page,
            total=total_expenses
        )
    except Exception as e:
        flash(f'Error loading expenses: {str(e)}', 'error')
        app.logger.error(f"Expenses error for user {session['username']}: {str(e)}")
        return render_template('expenses.html', expenses=[], categories=[], currency='₹', page=1, per_page=10, total=0)

@app.route('/add_expense', methods=['POST'])
@login_required
def add_expense():
    """Handle adding a new expense."""
    app.logger.debug("Adding new expense")
    form = FlaskForm()  # Simple form for now, can add WTForms later
    if request.method == 'POST':
        try:
            amount = float(request.form['amount'])
            category_id = int(request.form['category'])
            date = request.form['date']
            note = request.form.get('note', '')
            
            if amount <= 0:
                flash('Amount must be positive.', 'error')
                return redirect(url_for('dashboard'))
            
            modify_db(
                'INSERT INTO expenses (user_id, amount, category_id, date, note) VALUES (?, ?, ?, ?, ?)',
                (session['user_id'], amount, category_id, date, note)
            )
            flash('Expense added successfully!', 'success')
            if request.form.get('source') == 'expenses':
                return redirect(url_for('expenses'))
            return redirect(url_for('dashboard'))
        except ValueError as e:
            flash('Invalid input: Amount must be a number.', 'error')
            app.logger.error(f"Invalid expense input: {str(e)}")
        except Exception as e:
            flash(f'Error adding expense: {str(e)}', 'error')
            app.logger.error(f"Expense addition error: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):
    """Handle editing an existing expense."""
    app.logger.debug(f"Editing expense {expense_id}")
    expense = query_db(
        'SELECT e.id, e.amount, e.category_id, e.date, e.note, c.name as category_name '
        'FROM expenses e JOIN categories c ON e.category_id = c.id '
        'WHERE e.id = ? AND e.user_id = ?', [expense_id, session['user_id']], one=True
    )
    if not expense:
        flash('Expense not found or you do not have permission to edit it.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            amount = float(request.form['amount'])
            category_id = int(request.form['category'])
            date = request.form['date']
            note = request.form.get('note', '')
            
            if amount <= 0:
                flash('Amount must be positive.', 'error')
                return render_template('edit_expense.html', expense=expense, categories=[])
            
            modify_db(
                'UPDATE expenses SET amount = ?, category_id = ?, date = ?, note = ? WHERE id = ?',
                (amount, category_id, date, note, expense_id)
            )
            flash('Expense updated successfully!', 'success')
            if request.form.get('source') == 'expenses':
                return redirect(url_for('expenses'))
            return redirect(url_for('dashboard'))
        except ValueError as e:
            flash('Invalid input: Amount must be a number.', 'error')
            app.logger.error(f"Invalid expense edit input: {str(e)}")
        except Exception as e:
            flash(f'Error updating expense: {str(e)}', 'error')
            app.logger.error(f"Expense update error for ID {expense_id}: {str(e)}")
    
    categories = query_db('SELECT id, name FROM categories WHERE user_id = ? OR user_id IS NULL ORDER BY name', [session['user_id']])
    return render_template('edit_expense.html', expense=expense, categories=categories)

@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
@login_required
def delete_expense(expense_id):
    """Handle deleting an expense."""
    app.logger.debug(f"Deleting expense {expense_id}")
    try:
        expense = query_db(
            'SELECT * FROM expenses WHERE id = ? AND user_id = ?',
            [expense_id, session['user_id']], one=True
        )
        if expense:
            modify_db('DELETE FROM expenses WHERE id = ?', [expense_id])
            flash('Expense deleted successfully!', 'success')
        else:
            flash('Expense not found or you do not have permission to delete it.', 'error')
    except Exception as e:
        flash(f'Error deleting expense: {str(e)}', 'error')
        app.logger.error(f"Expense deletion error for ID {expense_id}: {str(e)}")
    
    if request.form.get('source') == 'expenses':
        return redirect(url_for('expenses'))
    return redirect(url_for('dashboard'))

@app.route('/add_income', methods=['POST'])
@login_required
def add_income():
    """Handle adding a new income."""
    app.logger.debug("Adding new income")
    if request.method == 'POST':
        try:
            amount = float(request.form['amount'])
            date = request.form['date']
            source = request.form.get('source', '')
            note = request.form.get('note', '')
            
            if amount <= 0:
                flash('Amount must be positive.', 'error')
                return redirect(url_for('dashboard'))
            
            modify_db(
                'INSERT INTO incomes (user_id, amount, date, source, note) VALUES (?, ?, ?, ?, ?)',
                (session['user_id'], amount, date, source, note)
            )
            flash('Income added successfully!', 'success')
            if request.form.get('source') == 'settings':
                return redirect(url_for('settings'))
            return redirect(url_for('dashboard'))
        except ValueError as e:
            flash('Invalid input: Amount must be a number.', 'error')
            app.logger.error(f"Invalid income input: {str(e)}")
        except Exception as e:
            flash(f'Error adding income: {str(e)}', 'error')
            app.logger.error(f"Income addition error: {str(e)}")
    
    return redirect(url_for('dashboard'))

@app.route('/edit_income/<int:income_id>', methods=['GET', 'POST'])
@login_required
def edit_income(income_id):
    """Handle editing an existing income."""
    app.logger.debug(f"Editing income {income_id}")
    income = query_db(
        'SELECT id, amount, date, source, note FROM incomes WHERE id = ? AND user_id = ?',
        [income_id, session['user_id']], one=True
    )
    if not income:
        flash('Income not found or you do not have permission to edit it.', 'error')
        return redirect(url_for('settings'))
    
    if request.method == 'POST':
        try:
            amount = float(request.form['amount'])
            date = request.form['date']
            source = request.form.get('source', '')
            note = request.form.get('note', '')
            
            if amount <= 0:
                flash('Amount must be positive.', 'error')
                return render_template('edit_income.html', income=income)
            
            modify_db(
                'UPDATE incomes SET amount = ?, date = ?, source = ?, note = ? WHERE id = ?',
                (amount, date, source, note, income_id)
            )
            flash('Income updated successfully!', 'success')
            return redirect(url_for('settings'))
        except ValueError as e:
            flash('Invalid input: Amount must be a number.', 'error')
            app.logger.error(f"Invalid income edit input: {str(e)}")
        except Exception as e:
            flash(f'Error updating income: {str(e)}', 'error')
            app.logger.error(f"Income update error for ID {income_id}: {str(e)}")
    
    return render_template('edit_income.html', income=income)

@app.route('/delete_income/<int:income_id>', methods=['POST'])
@login_required
def delete_income(income_id):
    """Handle deleting an income."""
    app.logger.debug(f"Deleting income {income_id}")
    try:
        income = query_db(
            'SELECT * FROM incomes WHERE id = ? AND user_id = ?',
            [income_id, session['user_id']], one=True
        )
        if income:
            modify_db('DELETE FROM incomes WHERE id = ?', [income_id])
            flash('Income deleted successfully!', 'success')
        else:
            flash('Income not found or you do not have permission to delete it.', 'error')
    except Exception as e:
        flash(f'Error deleting income: {str(e)}', 'error')
        app.logger.error(f"Income deletion error for ID {income_id}: {str(e)}")
    return redirect(url_for('settings'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """Handle user settings for profile, categories, and incomes."""
    app.logger.debug("Rendering settings page")
    form = FlaskForm()  # Placeholder, can add WTForms later
    if request.method == 'POST':
        action = request.form.get('action')
        try:
            if action == 'update_profile':
                salary = float(request.form['salary'])
                savings_target = float(request.form['savings_target'])
                currency = request.form['currency']
                if salary < 0 or savings_target < 0:
                    flash('Salary and savings target must be positive.', 'error')
                    return render_template('settings.html', profile=profile, categories=categories, incomes=incomes)
                modify_db(
                    'UPDATE user_profiles SET salary = ?, savings_target = ?, currency = ? WHERE user_id = ?',
                    (salary, savings_target, currency, session['user_id'])
                )
                flash('Profile updated successfully!', 'success')
            
            elif action == 'add_category':
                category_name = request.form['category_name'].strip()
                if not category_name or len(category_name) > 50:
                    flash('Category name must be non-empty and less than 50 characters.', 'error')
                    return render_template('settings.html', profile=profile, categories=categories, incomes=incomes)
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
        except ValueError as e:
            flash('Invalid input: Numbers must be valid.', 'error')
            app.logger.error(f"Settings input error: {str(e)}")
        except Exception as e:
            flash(f'Error updating settings: {str(e)}', 'error')
            app.logger.error(f"Settings error for user {session['username']}: {str(e)}")
        return redirect(url_for('settings'))
    
    try:
        profile = query_db('SELECT * FROM user_profiles WHERE user_id = ?', [session['user_id']], one=True)
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
    except Exception as e:
        flash(f'Error loading settings: {str(e)}', 'error')
        app.logger.error(f"Settings load error for user {session['username']}: {str(e)}")
        return render_template('settings.html', profile=None, categories=[], incomes=[])

@app.route('/edit_category/<int:category_id>', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    """Handle editing an existing category."""
    app.logger.debug(f"Editing category {category_id}")
    category = query_db(
        'SELECT id, name FROM categories WHERE id = ? AND (user_id = ? OR user_id IS NULL)',
        [category_id, session['user_id']], one=True
    )
    if not category:
        flash('Category not found or you do not have permission to edit it.', 'error')
        return redirect(url_for('settings'))
    
    if request.method == 'POST':
        try:
            new_name = request.form['category_name'].strip()
            if not new_name or len(new_name) > 50:
                flash('Category name must be non-empty and less than 50 characters.', 'error')
                return render_template('edit_category.html', category=category)
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
        except Exception as e:
            flash(f'Error updating category: {str(e)}', 'error')
            app.logger.error(f"Category update error for ID {category_id}: {str(e)}")
    
    return render_template('edit_category.html', category=category)

@app.route('/delete_category/<int:category_id>', methods=['POST'])
@login_required
def delete_category(category_id):
    """Handle deleting a category."""
    app.logger.debug(f"Deleting category {category_id}")
    try:
        category = query_db(
            'SELECT * FROM categories WHERE id = ? AND user_id = ?',
            [category_id, session['user_id']], one=True
        )
        if category:
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
    except Exception as e:
        flash(f'Error deleting category: {str(e)}', 'error')
        app.logger.error(f"Category deletion error for ID {category_id}: {str(e)}")
    return redirect(url_for('settings'))

@app.route('/reports')
@login_required
def reports():
    """Render the reports page with date range filtering."""
    app.logger.debug("Rendering reports page")
    start_date = request.args.get('start_date', f"{datetime.now().year}-01-01")
    end_date = request.args.get('end_date', f"{datetime.now().year+1}-01-01")
    
    try:
        profile = query_db('SELECT currency FROM user_profiles WHERE user_id = ?', [session['user_id']], one=True)
        currency = profile['currency'] if profile else '₹'
        
        # Monthly expenses for the date range
        monthly_expenses = []
        current_year = datetime.now().year
        for month in range(1, 13):
            month_start = f"{current_year}-{month:02d}-01"
            month_end = f"{current_year}-{month+1:02d}-01" if month < 12 else f"{current_year+1}-01-01"
            if month_start >= start_date and month_end <= end_date:
                month_expense = query_db(
                    'SELECT SUM(amount) as total FROM expenses WHERE user_id = ? AND date >= ? AND date < ?',
                    [session['user_id'], month_start, month_end], one=True
                )
                monthly_expenses.append({
                    'month': calendar.month_name[month],
                    'amount': float(month_expense['total']) if month_expense['total'] else 0
                })
        
        # Monthly incomes for the date range
        monthly_incomes = []
        for month in range(1, 13):
            month_start = f"{current_year}-{month:02d}-01"
            month_end = f"{current_year}-{month+1:02d}-01" if month < 12 else f"{current_year+1}-01-01"
            if month_start >= start_date and month_end <= end_date:
                month_income = query_db(
                    'SELECT SUM(amount) as total FROM incomes WHERE user_id = ? AND date >= ? AND date < ?',
                    [session['user_id'], month_start, month_end], one=True
                )
                monthly_incomes.append({
                    'month': calendar.month_name[month],
                    'amount': float(month_income['total']) if month_income['total'] else 0
                })
        
        # Category breakdown for the date range
        category_expenses = query_db(
            '''SELECT c.name as category, COALESCE(SUM(e.amount), 0) as amount
               FROM categories c
               LEFT JOIN expenses e ON c.id = e.category_id AND e.user_id = ?
                                    AND e.date >= ? AND e.date < ?
               WHERE c.user_id = ? OR c.user_id IS NULL
               GROUP BY c.id
               ORDER BY amount DESC''',
            [session['user_id'], start_date, end_date, session['user_id']]
        )
        
        categories = [item['category'] for item in category_expenses if item['amount'] > 0]
        amounts = [float(item['amount']) for item in category_expenses if item['amount'] > 0]
        
        return render_template(
            'reports.html',
            monthly_expenses=monthly_expenses,
            monthly_incomes=monthly_incomes,
            categories=categories,
            amounts=amounts,
            currency=currency,
            chart_colors=CHART_COLORS,
            start_date=start_date,
            end_date=end_date
        )
    except Exception as e:
        flash(f'Error loading reports: {str(e)}', 'error')
        app.logger.error(f"Reports error for user {session['username']}: {str(e)}")
        return render_template('reports.html', monthly_expenses=[], monthly_incomes=[], categories=[], amounts=[], currency='₹', start_date=start_date, end_date=end_date)

if __name__ == '__main__':
    # Create tables if they don't exist
    if not os.path.exists(DATABASE):
        with app.app_context():
            init_db()
    app.run(debug=True)
