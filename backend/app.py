from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import yfinance as yf
import MySQLdb # Ensure this is imported for specific error handling
from functools import wraps # Import wraps for decorators
from datetime import datetime, timedelta
from flask import flash, redirect, url_for, session, render_template, request

app = Flask(__name__)

import os


# Upload folder config
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


app.secret_key = os.environ.get("FLASK_SECRET_KEY", "your_dev_secret_key_here")
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'kamal@123'
app.config['MYSQL_DB'] = 'your_database'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# Decorator to check if the user is an admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session['username'] != 'admin':
            flash('Unauthorized access. Admin privileges required.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Please enter both username and password.', 'warning')
            return render_template('login.html')

        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            cur.close()

            if user:
                stored_password = user['password']

                # Supports both hashed and plain text passwords
                if check_password_hash(stored_password, password) or stored_password == password:
                    session['username'] = user['username']
                    session['user_id'] = user['id']

                    if user['username'] == 'admin':
                        flash('Admin login successful!', 'success')
                        return redirect(url_for('admin'))

                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Incorrect password.', 'danger')
            else:
                flash('User not found.', 'danger')
        except Exception as e:
            print(f"[ERROR] Login failed: {e}")
            flash('Server error during login. Try again later.', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        mobile = request.form['mobile']
        email = request.form['email']
        account_number = request.form['account_number']
        ifsc = request.form['ifsc']

        files = {
            'passbook_photo': request.files.get('passbook_photo'),
            'aadhaar_front': request.files.get('aadhaar_front'),
            'aadhaar_back': request.files.get('aadhaar_back'),
            'pan_photo': request.files.get('pan_photo'),
        }

        save_paths = {}
        for field, file in files.items():
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{field}_{mobile}.png")
                path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(path)
                save_paths[field] = filename
            else:
                flash(f"Invalid or missing file for {field}", 'danger')
                return redirect(url_for('register'))

        try:
            cur = mysql.connection.cursor()
            cur.execute("""
                INSERT INTO registrations (
                    full_name, mobile, email, account_number, ifsc,
                    passbook_photo, aadhaar_front, aadhaar_back, pan_photo
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                full_name, mobile, email, account_number, ifsc,
                save_paths['passbook_photo'], save_paths['aadhaar_front'],
                save_paths['aadhaar_back'], save_paths['pan_photo']
            ))
            mysql.connection.commit()
            cur.close()
            flash("Registration successful!", "success")
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Database error during registration: {e}")
            flash(f"Database error: {e}", "danger")
            return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Please login first.', 'warning')
        return redirect(url_for('login'))

    username = session['username']

    # Fetch balance and profit/loss from database
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT balance, profit_loss FROM users WHERE username = %s", (username,))
        result = cur.fetchone()
        if result:
            balance, profit_loss = result
        else:
            balance, profit_loss = 0, 0
        cur.close()
    except Exception as e:
        print(f"Error fetching user data: {e}")
        balance, profit_loss = 0, 0

    # Index dictionary with TradingView symbols
    indices = {
        'NIFTY 50': {'symbol': '^NSEI', 'tv_symbol': 'NSE-NIFTY'},
        'SENSEX': {'symbol': '^BSESN', 'tv_symbol': 'BSE-SENSEX'},
        'BANKNIFTY': {'symbol': '^NSEBANK', 'tv_symbol': 'NSE-BANKNIFTY'},
        'MIDCPNIFTY': {'symbol': '^NSEMDCP50', 'tv_symbol': 'NIFTY_MID_SELECT'}
    }

    live_data = []
    for name, info in indices.items():
        symbol = info['symbol']
        tv_symbol = info['tv_symbol']
        tv_url = f"https://www.tradingview.com/symbols/{tv_symbol}/"

        try:
            ticker = yf.Ticker(symbol)
            data = ticker.history(period='1d', interval='1m')
            if not data.empty:
                last_price = data['Close'].dropna().iloc[-1]
                open_price = data['Open'].iloc[0]
                change_percent = round(((last_price - open_price) / open_price) * 100, 2)
                live_data.append({
                    'name': name,
                    'symbol': symbol,
                    'last_price': round(last_price, 2),
                    'change': change_percent,
                    'tv_url': tv_url
                })
            else:
                raise ValueError("No data returned.")
        except Exception as e:
            print(f"Error fetching data for {name}: {e}")
            live_data.append({
                'name': name,
                'symbol': symbol,
                'last_price': 'N/A',
                'change': 0,
                'tv_url': tv_url
            })

    return render_template('home.html',
                           username=username,
                           balance=balance,
                           profit_loss=profit_loss,
                           index_data=live_data)

from MySQLdb.cursors import DictCursor

@app.route("/profile")
def profile():
    if 'username' not in session:
        flash("You must be logged in to view your profile.", "danger")
        return redirect(url_for("login"))

    username = session['username']
    cur = mysql.connection.cursor(DictCursor)  # Use DictCursor for dict results

    cur.execute("""
        SELECT id, balance, profit_loss, full_name, email, phone, pan_number, location, 
               demat_account_number, dp_id, dp_name, depository, tax_charges, 
               brokerage_charges, bank_name, bank_account_number, ifsc_code, 
               account_holder_name, subscribed_plan, subscribed_on 
        FROM users WHERE username = %s
    """, (username,))
    user_row = cur.fetchone()

    if not user_row:
        flash("User not found", "danger")
        return redirect(url_for("login"))

    user_id = user_row['id']
    base_balance = float(user_row['balance'] or 0)

    # Fix your orders query based on your DB schema for margin_used or replace with correct column
    cur.execute("SELECT order_type, margin_used FROM orders WHERE user_id = %s AND status = 'Executed'", (user_id,))
    executed_orders = cur.fetchall()

    for order in executed_orders:
        order_type = order['order_type']
        margin_used = order['margin_used'] # <-- Corrected indentation
        margin = float(margin_used or 0)    # <-- Corrected indentation
        if order_type.upper() == "BUY":     # <-- Corrected indentation
            base_balance -= margin
        elif order_type.upper() == "SELL":  # <-- Corrected indentation
            base_balance += margin

    cur.execute("SELECT date, amount, status FROM deposit_history WHERE user_id = %s ORDER BY date DESC", (user_id,))
    deposit_history = cur.fetchall()

    cur.execute("SELECT date, amount, status FROM withdraw_history WHERE user_id = %s ORDER BY date DESC", (user_id,))
    withdraw_history = cur.fetchall()

    user_details = {
        "full_name": user_row['full_name'],
        "email": user_row['email'],
        "phone": user_row['phone'],
        "pan_number": user_row['pan_number'],
        "location": user_row['location'],
        "demat_account_number": user_row['demat_account_number'],
        "dp_id": user_row['dp_id'],
        "dp_name": user_row['dp_name'],
        "depository": user_row['depository'],
        "tax_charges": float(user_row['tax_charges'] or 0),
        "brokerage_charges": float(user_row['brokerage_charges'] or 0),
        "bank_name": user_row['bank_name'],
        "bank_account_number": user_row['bank_account_number'],
        "ifsc_code": user_row['ifsc_code'],
        "account_holder_name": user_row['account_holder_name'],
        "subscribed_plan": user_row['subscribed_plan'],
        "subscribed_on": user_row['subscribed_on']
    }

    return render_template("profile.html",
                           username=username,
                           balance=round(base_balance, 2),
                           profit_loss=float(user_row['profit_loss'] or 0),
                           tax_charges=user_details["tax_charges"],
                           brokerage_charges=user_details["brokerage_charges"],
                           user_details=user_details,
                           deposit_history=deposit_history,
                           withdraw_history=withdraw_history)


@app.route('/confirm_payment', methods=['POST'])
def confirm_payment():
    if 'username' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

    username = session['username']
    amount = float(request.form.get('amount'))

    cur = mysql.connection.cursor()

    # Get the user ID
    cur.execute("SELECT id FROM users WHERE username = %s", (username,))
    user = cur.fetchone()

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('profile'))

    user_id = user['id']

    # Insert into deposit_history table with status = Pending
    cur.execute("""
        INSERT INTO deposit_history (user_id, amount, status)
        VALUES (%s, %s, 'Pending')
    """, (user_id, amount))
    mysql.connection.commit()
    cur.close()

    flash("Payment request sent. Please wait for admin approval.", "success")
    return redirect(url_for('profile'))


@app.route('/admin/deposit_history', methods=['GET', 'POST'])
@admin_required
def deposit_history():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        deposit_id = request.form.get('save_deposit_id')
        status_field = f"status_{deposit_id}"
        new_status = request.form.get(status_field)

        if not deposit_id or not new_status:
            flash("Missing deposit ID or status.", "danger")
        else:
            try:
                cur.execute("UPDATE deposit_history SET status = %s WHERE id = %s", (new_status, deposit_id))
                mysql.connection.commit()
                flash("Deposit status updated successfully.", "success")
            except Exception as e:
                mysql.connection.rollback()
                flash(f"Error updating deposit: {e}", "danger")

    # Fetch deposit history
    cur.execute("""
        SELECT dh.id, u.username, dh.amount, dh.payment_date AS deposit_date, dh.status
        FROM deposit_history dh
        JOIN users u ON dh.user_id = u.id
        ORDER BY dh.payment_date DESC
    """)
    deposits = cur.fetchall()
    cur.close()

    return render_template("admin.html", deposits=deposits)

@app.route('/portfolio')
def portfolio():
    if 'username' not in session:
        flash("Please log in first.", "danger")
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
    user = cur.fetchone()

    if not user:
        flash("User not found.", "danger")
        cur.close()
        return redirect(url_for('login'))
    user_id = user['id']

    # Pending & cancelled
    cur.execute("""
        SELECT * FROM orders 
        WHERE user_id = %s AND status IN ('pending', 'cancelled')
        ORDER BY id DESC
    """, (user_id,))
    pending_orders = cur.fetchall()

    # Open buy & executed
    cur.execute("""
        SELECT * FROM orders 
        WHERE user_id = %s AND order_type = 'buy' AND status = 'executed'
        ORDER BY id DESC
    """, (user_id,))
    open_orders = cur.fetchall()

    # Executed and booked
    cur.execute("""
        SELECT * FROM orders 
        WHERE user_id = %s AND status IN ('executed', 'booked')
        ORDER BY id DESC
    """, (user_id,))
    executed_orders = cur.fetchall()

     # Total profit/loss (executed + booked)
    cur.execute("""
    SELECT SUM(profit_loss) AS total_pl 
    FROM orders 
    WHERE user_id = %s AND status IN ('executed', 'booked')
""", (user_id,))
    result = cur.fetchone()
    total_profit_loss = result['total_pl'] if result and result['total_pl'] is not None else 0.0
    print(f"[DEBUG] Total Profit/Loss: {total_profit_loss}")


    # Total margin used (executed + booked)
    cur.execute("""
        SELECT SUM(price * quantity) AS total_margin 
        FROM orders 
        WHERE user_id = %s AND status IN ('executed', 'booked')
    """, (user_id,))
    margin_result = cur.fetchone()
    total_margin_used = margin_result['total_margin'] if margin_result and margin_result['total_margin'] is not None else 0.0

    cur.close()

    return render_template(
        'portfolio.html',
        pending_orders=pending_orders,
        open_orders=open_orders,
        executed_orders=executed_orders,
        total_profit_loss=total_profit_loss,
        total_margin_used=total_margin_used
    )


@app.route('/markets')
def markets():
    stocks = {
        'Tata Consultancy Services': 'TCS.NS',
        'Reliance Industries': 'RELIANCE.NS',
        'Infosys': 'INFY.NS'
    }

    market_data = []
    for name, symbol in stocks.items():
        try:
            ticker = yf.Ticker(symbol)
            data = ticker.history(period='1d', interval='1m')
            if data.empty:
                raise Exception("No data")
            open_price = round(data['Open'][0], 2)
            high = round(data['High'].max(), 2)
            low = round(data['Low'].min(), 2)
            last_price = round(data['Close'].dropna().iloc[-1], 2)
            change_percent = round(((last_price - open_price) / open_price) * 100, 2)
            market_data.append({
                'name': name,
                'symbol': symbol.split('.')[0],
                'open': open_price,
                'high': high,
                'low': low,
                'last_price': last_price,
                'change': change_percent
            })
        except Exception as e:
            print(f"Error fetching {name}: {e}")
            market_data.append({
                'name': name,
                'symbol': symbol,
                'open': 'N/A',
                'high': 'N/A',
                'low': 'N/A',
                'last_price': 'N/A',
                'change': 0
            })

    return render_template('markets.html', market_data=market_data)

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/admin')
@admin_required # Apply the admin_required decorator
def admin():
    cur = mysql.connection.cursor()
    # Also fetch user IDs for the dropdown in the 'Add Order' form
    cur.execute("SELECT id, username, balance, profit_loss, full_name, email, phone, pan_number, location FROM users")
    users = cur.fetchall()
    cur.close()
    return render_template('admin.html', users=users)
@app.route('/admin/admin_add_order', methods=['POST'])
@admin_required
def admin_add_order():
    cur = None
    try:
        username = request.form['username'].strip()
        stock_symbol = request.form.get('stock_symbol', '').strip()
        order_type = request.form['order_type'].strip().upper()
        quantity = int(request.form['quantity'])
        price = float(request.form['price'])
        status = request.form['status'].strip().capitalize()
        
        # ✅ Safely handle profit_loss
        profit_loss_str = request.form.get('profit_loss', '').strip()
        profit_loss = float(profit_loss_str) if profit_loss_str else 0.0

        margin_used = quantity * price

        cur = mysql.connection.cursor(DictCursor)
        cur.execute("SELECT id, balance FROM users WHERE username = %s", (username,))
        user = cur.fetchone()

        if not user:
            flash("User not found", "danger")
            return redirect(url_for('admin_orders'))

        user_id = user['id']
        user_balance = float(user['balance'] or 0)

        if margin_used > user_balance:
            flash("Insufficient balance to place this order.", "warning")
            return redirect(url_for('admin_orders'))

        cur.execute("""
            INSERT INTO orders (user_id, stock_symbol, order_type, quantity, price, margin_used, status, profit_loss)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (user_id, stock_symbol, order_type, quantity, price, margin_used, status, profit_loss))

        mysql.connection.commit()
        flash('Order added successfully!', 'success')

    except Exception as e:
        if cur:
            mysql.connection.rollback()
        flash(f"Error adding order: {repr(e)}", "danger")

    finally:
        if cur:
            cur.close()

    return redirect(url_for('admin_orders'))


@app.route('/admin/orders', methods=['GET', 'POST'])
@admin_required
def admin_orders():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Get all users for the dropdown
    cur.execute("SELECT id, username FROM users ORDER BY username")
    users = cur.fetchall()

    selected_user_id = request.form.get('user_id') or request.args.get('user_id')
    orders = []
    message = None

    if selected_user_id:
        # If this is a POST with order update info
        if 'save_order_id' in request.form:
            order_id = int(request.form['save_order_id'])
            order_type = request.form.get(f'order_type_{order_id}', '').strip().upper()
            price = float(request.form.get(f'price_{order_id}', 0))
            status = request.form.get(f'status_{order_id}', '').strip().capitalize()
            profit_loss = float(request.form.get(f'profit_loss_{order_id}', 0))

            # Fetch quantity to recalc margin_used
            cur.execute("SELECT quantity FROM orders WHERE id = %s", (order_id,))
            order = cur.fetchone()
            if order:
                quantity = order['quantity']
                margin_used = quantity * price
                try:
                    cur.execute("""
                        UPDATE orders SET order_type=%s, price=%s, margin_used=%s, status=%s, profit_loss=%s
                        WHERE id=%s
                    """, (order_type, price, margin_used, status, profit_loss, order_id))
                    mysql.connection.commit()
                    message = f"Order #{order_id} updated successfully!"
                except Exception as e:
                    mysql.connection.rollback()
                    message = f"Error updating order #{order_id}: {repr(e)}"

        # Fetch orders of the selected user
        cur.execute("SELECT * FROM orders WHERE user_id = %s", (selected_user_id,))
        orders = cur.fetchall()

    cur.close()

    return render_template('admin.html', users=users, orders=orders,
                           selected_user_id=selected_user_id, message=message)


from flask import request, redirect, url_for, flash
import MySQLdb.cursors

@app.route('/admin_update_user/<int:user_id>', methods=['POST'])
@admin_required
def admin_update_user(user_id):
    try:
        # Convert numeric values safely
        try:
            balance = float(request.form.get('balance'))
        except ValueError:
            balance = 0.0

        try:
            profit_loss = float(request.form.get('profit_loss'))
        except ValueError:
            profit_loss = 0.0

        try:
            tax_charges = float(request.form.get('tax_charges'))
        except ValueError:
            tax_charges = 0.0

        try:
            brokerage_charges = float(request.form.get('brokerage_charges'))
        except ValueError:
            brokerage_charges = 0.0

        # Get subscription data
        subscribed_plan = request.form.get('subscribed_plan') or None
        subscribed_on = request.form.get('subscribed_on') or None  # Expecting 'YYYY-MM-DD' format

        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE users
            SET balance=%s,
                profit_loss=%s,
                tax_charges=%s,
                brokerage_charges=%s,
                subscribed_plan=%s,
                subscribed_on=%s
            WHERE id=%s
        """, (
            balance, profit_loss, tax_charges, brokerage_charges,
            subscribed_plan, subscribed_on, user_id
        ))
        mysql.connection.commit()
        cur.close()

        flash('User financial and subscription details updated successfully.', 'success')

    except Exception as e:
        print(f"Error in admin_update_user: {e}")
        flash(f"Error updating user: {str(e)}", 'danger')

    return redirect(url_for('admin'))



@app.route('/admin_add_user', methods=['POST'])
@admin_required
def admin_add_user():
    try:
        # Text inputs
        username = request.form.get('username') or ''
        full_name = request.form.get('full_name') or ''
        email = request.form.get('email') or ''
        phone = request.form.get('phone') or ''
        pan_number = request.form.get('pan_number') or ''
        location = request.form.get('location') or ''
        demat_account_number = request.form.get('demat_account_number') or ''
        dp_id = request.form.get('dp_id') or ''
        dp_name = request.form.get('dp_name') or ''
        depository = request.form.get('depository') or ''
        password = request.form.get('password') or ''

        # Bank detail inputs
        bank_name = request.form.get('bank_name') or ''
        bank_account_number = request.form.get('bank_account_number') or ''
        ifsc_code = request.form.get('ifsc_code') or ''
        account_holder_name = request.form.get('account_holder_name') or ''

        # Numeric inputs with safe fallback
        try:
            balance = float(request.form.get('balance', 0))
        except ValueError:
            balance = 0.0

        try:
            profit_loss = float(request.form.get('profit_loss', 0))
        except ValueError:
            profit_loss = 0.0

        try:
            tax_charges = float(request.form.get('tax_charges', 0))
        except ValueError:
            tax_charges = 0.0

        try:
            brokerage_charges = float(request.form.get('brokerage_charges', 0))
        except ValueError:
            brokerage_charges = 0.0

        # Basic validation
        if not username or not email or not password:
            flash("Username, email, and password are required.", "warning")
            return redirect(url_for('admin'))

        # Insert into database
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO users (
                username, full_name, email, phone, balance, profit_loss,
                pan_number, location, tax_charges, brokerage_charges,
                demat_account_number, dp_id, dp_name, depository, password,
                bank_name, bank_account_number, ifsc_code, account_holder_name
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            username, full_name, email, phone, balance, profit_loss,
            pan_number, location, tax_charges, brokerage_charges,
            demat_account_number, dp_id, dp_name, depository, password,
            bank_name, bank_account_number, ifsc_code, account_holder_name
        ))
        mysql.connection.commit()
        cur.close()

        flash("User added successfully.", "success")

    except Exception as e:
        print(f"Error in admin_add_user: {e}")
        flash(f"Error adding user: {e}", "danger")

    return redirect(url_for('admin'))


@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

from datetime import datetime

@app.context_processor
def inject_now():
    return {'now': datetime.now}


# Subscription plans info (price, duration in days)
SUBSCRIPTION_PLANS = {
    'basic': {'price': 25000, 'duration_days': 30},
    'hni': {'price': 74999, 'duration_days': 30},
    'pms': {'price': 99999, 'duration_days': 30}
}
from flask import request, jsonify

# Subscription route for each plan
from datetime import datetime
from flask import session, request, jsonify

@app.route('/subscribe/<plan>', methods=['POST'])
def subscribe(plan):
    valid_plans = ['basic', 'hni', 'pms']
    if plan not in valid_plans:
        return jsonify({'status': 'error', 'message': 'Invalid subscription plan.'}), 400

    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'You must be logged in to subscribe.'}), 401

    username = session['username']
    requested_on = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    try:
        cur = mysql.connection.cursor()

        # Check if there is already a pending request for this user and plan
        cur.execute("""
            SELECT id FROM subscription_requests 
            WHERE username = %s AND plan = %s AND status = 'pending'
        """, (username, plan))
        existing_request = cur.fetchone()

        if existing_request:
            return jsonify({'status': 'error', 'message': 'You already have a pending subscription request for this plan.'}), 400

        # Insert a new subscription request with status pending
        cur.execute("""
            INSERT INTO subscription_requests (username, plan, status, request_date)
            VALUES (%s, %s, %s, %s)
        """, (username, plan, 'pending', requested_on))

        mysql.connection.commit()
        cur.close()

        return jsonify({'status': 'success', 'message': f'Subscription request for {plan.upper()} plan submitted. Await admin approval.'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error: {str(e)}'}), 500
# def allowed_file(filename):
#     return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/admin/orders/delete', methods=['POST'])
@admin_required
def admin_delete_order():
    order_id = request.form.get('order_id')

    if not order_id:
        flash("Order ID is required to delete.", "danger")
        return redirect(url_for('admin_orders'))

    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM orders WHERE id = %s", (order_id,))
        mysql.connection.commit()
        cur.close()
        flash(f"Order ID {order_id} deleted successfully.", "success")
    except Exception as e:
        flash(f"Failed to delete order: {str(e)}", "danger")

    return redirect(url_for('admin_orders'))

import os
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload_qr_code', methods=['POST'])
def upload_qr_code():
    if 'qr_code' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.referrer)

    file = request.files['qr_code']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(request.referrer)

    if file and allowed_file(file.filename):
        filename = 'qr_code.png'  # Overwrite the existing QR code
        file_path = os.path.join(app.static_folder, filename)
        file.save(file_path)
        flash('QR Code updated successfully!', 'success')
    else:
        flash('Invalid file type. Please upload an image.', 'danger')

    return redirect(request.referrer)

@app.route('/admin/withdraw', methods=['GET', 'POST'])
@admin_required
def admin_withdraw_history():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Fetch all users for dropdown
    cur.execute("SELECT id, username FROM users ORDER BY username")
    users = cur.fetchall()
    message = None

    if request.method == 'POST':
        # Update existing record
        withdraw_id = request.form.get('save_withdraw_id')
        if withdraw_id:
            new_status = request.form.get(f"status_{withdraw_id}")
            if not new_status:
                message = "Missing status for withdraw update."
            else:
                try:
                    cur.execute("UPDATE withdraw_history SET status = %s WHERE id = %s", (new_status, withdraw_id))
                    mysql.connection.commit()
                    message = f"Withdraw ID {withdraw_id} status updated successfully."
                except Exception as e:
                    mysql.connection.rollback()
                    message = f"Error updating withdraw: {e}"
        else:
            # Add new withdraw record
            user_id = request.form.get('user_id')
            amount = request.form.get('amount')
            status = request.form.get('status')

            if not user_id or not amount or not status:
                message = "Please fill all required fields."
            else:
                try:
                    cur.execute("""
                        INSERT INTO withdraw_history (user_id, amount, status)
                        VALUES (%s, %s, %s)
                    """, (user_id, amount, status))
                    mysql.connection.commit()
                    message = "Withdraw record added successfully."
                except Exception as e:
                    mysql.connection.rollback()
                    message = f"Error: {str(e)}"

    # Fetch withdraw history (latest 100)
    cur.execute("""
        SELECT wh.*, u.username 
        FROM withdraw_history wh
        JOIN users u ON wh.user_id = u.id
        ORDER BY date DESC

        LIMIT 100
    """)
    withdraws = cur.fetchall()
    cur.close()

    return render_template('admin.html', users=users, withdraws=withdraws, message=message)


@app.route('/admin/clear_orders', methods=['POST'])
@admin_required
def clear_orders():
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM orders")
        mysql.connection.commit()
        flash("All orders have been deleted successfully.", "success")
    except Exception as e:
        mysql.connection.rollback()
        flash(f"Error deleting orders: {str(e)}", "danger")
    finally:
        cur.close()
    return redirect(url_for('admin'))  # Update to your admin panel route

@app.route('/admin/summary')
def admin_user_summary():
    # Ensure user is logged in
    username = session.get('username')
    user_type = session.get('admin')

   

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Fetch all users and their financials
    cur.execute("""
        SELECT id, username, balance, profit_loss, brokerage_charges, tax_charges
        FROM users
    """)
    users = cur.fetchall()

    user_data = []
    for user in users:
        user_id = user['id']

        # Get total trading value and total profit/loss from orders
        cur.execute("""
            SELECT 
                IFNULL(SUM(price * quantity), 0) AS trading_value,
                IFNULL(SUM(profit_loss), 0) AS total_pl
            FROM orders
            WHERE user_id = %s AND status IN ('executed', 'booked')
        """, (user_id,))
        result = cur.fetchone()

        user_info = {
            'username': user['username'],
            'balance': round(user['balance'] or 0, 2),
            'profit_loss': round(user['profit_loss'] or 0, 2),
            'brokerage_charges': round(user['brokerage_charges'] or 0, 2),
            'tax_charges': round(user['tax_charges'] or 0, 2),
            'total_trading_value': round(result['trading_value'] or 0, 2),
            'total_profit_loss': round(result['total_pl'] or 0, 2)
        }
        user_data.append(user_info)

    cur.close()
    return render_template('admin.html', user_data=user_data)


if __name__ == '__main__':
    with app.app_context():
        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT 1")
            cur.close()
            print("✅ Connected to MySQL database.")
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
    app.run(debug=True)

