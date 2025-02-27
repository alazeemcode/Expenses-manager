from flask import Flask, render_template, request, jsonify
import sqlite3

app = Flask(__name__)


# Initialize database
def init_db():
    conn = sqlite3.connect('database.db')
    conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, salary REAL, savings_target REAL)')
    conn.execute(
        'CREATE TABLE IF NOT EXISTS expenses (id INTEGER PRIMARY KEY, user_id INTEGER, amount REAL, category TEXT, date TEXT, note TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY, name TEXT UNIQUE)')
    # Insert default categories if they don't exist
    default_categories = ['Food', 'Transport', 'Bills', 'Entertainment']
    for cat in default_categories:
        conn.execute('INSERT OR IGNORE INTO categories (name) VALUES (?)', (cat,))
    conn.commit()
    conn.close()


@app.route('/')
def index():
    conn = sqlite3.connect('database.db')
    user = conn.execute('SELECT salary, savings_target FROM users WHERE id = 1').fetchone()
    if not user:
        conn.execute('INSERT INTO users (id, salary, savings_target) VALUES (1, 0, 0)')
        conn.commit()
        user = (0, 0)

    # Total expenses
    expenses = conn.execute('SELECT SUM(amount) FROM expenses WHERE user_id = 1').fetchone()[0] or 0

    # Category-wise data
    category_data = conn.execute(
        'SELECT category, SUM(amount) FROM expenses WHERE user_id = 1 GROUP BY category').fetchall()
    categories_list = [row[0] for row in category_data if row[0]]  # For chart
    amounts = [float(row[1]) for row in category_data if row[1]]  # For chart

    # Get all categories for dropdown
    all_categories = [row[0] for row in conn.execute('SELECT name FROM categories ORDER BY name')]

    salary, savings_target = user
    spent_percent = (expenses / salary * 100) if salary > 0 else 0
    warning = spent_percent > 80
    savings_progress = ((salary - expenses) / savings_target * 100) if savings_target > 0 else 0

    conn.close()
    return render_template('index.html', salary=salary, savings_target=savings_target,
                           expenses=expenses, warning=warning, savings_progress=savings_progress,
                           categories=categories_list, amounts=amounts, all_categories=all_categories)


@app.route('/add_expense', methods=['POST'])
def add_expense():
    amount = float(request.form['amount'])
    category = request.form['category']
    date = request.form['date']
    note = request.form.get('note', '')
    conn = sqlite3.connect('database.db')
    conn.execute('INSERT INTO expenses (user_id, amount, category, date, note) VALUES (1, ?, ?, ?, ?)',
                 (amount, category, date, note))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})


@app.route('/update_user', methods=['POST'])
def update_user():
    salary = float(request.form['salary'])
    savings_target = float(request.form['savings_target'])
    conn = sqlite3.connect('database.db')
    conn.execute('INSERT OR REPLACE INTO users (id, salary, savings_target) VALUES (1, ?, ?)',
                 (salary, savings_target))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})


@app.route('/add_category', methods=['POST'])
def add_category():
    category = request.form['category'].strip()
    if category:
        conn = sqlite3.connect('database.db')
        try:
            conn.execute('INSERT OR IGNORE INTO categories (name) VALUES (?)', (category,))
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # Ignore if category already exists
        finally:
            conn.close()
    return jsonify({'status': 'success'})


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
