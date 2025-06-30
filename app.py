from flask import Flask, render_template, redirect, url_for, flash, request, send_from_directory
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from concurrent_log_handler import ConcurrentRotatingFileHandler
from dotenv import load_dotenv
import logging
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
import string
import secrets
import os
from datetime import date, datetime, timedelta
import re

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'pecific-ocean'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:OraclE999#%^@localhost/gym_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Setup logging
handler = ConcurrentRotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# Initialize Flask-login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# To generate random password
def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

def is_admin():
    if not current_user.is_authenticated or current_user.role != 'admin':
        app.logger.warning(f"Unauthorized access attempt to admin route by {current_user.get_id() if current_user.is_authenticated else 'anonymous'}")
        flash('Unauthorized Access.', 'danger')
        return redirect(url_for('login'))
    return None

def is_member():
    if not current_user.is_authenticated or current_user.role != 'member':
        flash('Unauthorized Access.', 'danger')
        app.logger.warning(f"Unauthorized access attempt to member route by {current_user.get_id() if current_user.is_authenticated else 'anonymous'}")
        return redirect(url_for('login'))
    return None

# Database Model
class Admin(db.Model, UserMixin):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(50), unique = True, nullable = False)
    password = db.Column(db.String(128), nullable = False)
    role = db.Column(db.String(20), default='admin')

    def set_password(self, password):
        self.password = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def get_id(self):
        return f"admin_{self.id}"
    
class Member(db.Model, UserMixin):
    __tablename__ = 'members'
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100), nullable = False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    phone = db.Column(db.String(15))
    join_date = db.Column(db.Date, nullable=False)
    fee_package = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='member')
    status = db.Column(db.String(20), default='new', nullable=False)

    bills = db.relationship('Bill', backref='member', lazy=True)
    notifications = db.relationship('Notification', backref='member', lazy=True)
    

    def set_password(self, password):
        self.password = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def get_id(self):
        return f"member_{self.id}"
    

    
class Bill(db.Model):
    __tablename__ = 'bills'
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('members.id'), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    issue_date = db.Column(db.Date, nullable=False)
    due_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), default='pending')

class Receipt(db.Model):
    __tablename__ = 'receipts'
    id = db.Column(db.Integer, primary_key=True)
    bill_id = db.Column(db.Integer, db.ForeignKey('bills.id'), nullable=False)
    member_id = db.Column(db.Integer, db.ForeignKey('members.id'), nullable=False)
    receipt_url = db.Column(db.String(255), nullable=False)
    generated_date = db.Column(db.Date, nullable=False)


class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('members.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    sent_date = db.Column(db.Date, nullable=False)


class GymSchedule(db.Model):
    __tablename__ = 'gym_schedules'
    id = db.Column(db.Integer, primary_key=True)
    schedule_date = db.Column(db.Date, nullable=False, unique=True)
    status = db.Column(db.String(10), nullable=False, default='open')  # 'open' or 'closed'

# Flask-Login user Loader
@login_manager.user_loader
def load_user(user_id):
    if user_id.startswith('admin_'):
        return db.session.get(Admin, int(user_id.split('_')[1]))
    elif user_id.startswith('member_'):
        return db.session.get(Member, int(user_id.split('_')[1]))
    return None


@app.route('/')
def index():
    app.logger.info('Accessed index page.')
    return render_template('index.html')

@app.route('/about')
def about():
    app.logger.info('Access about pagee.')
    return render_template('about.html')

@app.route('/contact')
def contact():
    app.logger.info('Access contact pagee.')
    return render_template('contact.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_input = request.form.get('username')
        password = request.form.get('password')

        try:
            if not username_input or not password:
                flash('All fields are required.', 'danger')
                return render_template('login.html')
            
            if '@' in username_input:
                username = username_input.split('@')[0]
            else:
                username = username_input

            # Check Admin
            admin = Admin.query.filter_by(username=username).first()
            if admin and admin.check_password(password):
                login_user(admin)
                flash(f"Login successful! Welcome {username}.", 'success')
                return redirect(url_for('admin_dashboard'))
            
            # Check Member
            member = Member.query.filter_by(username=username).first()
            if member and member.check_password(password):
                login_user(member)
                flash(f"Login successful! Welcome {member.name}", "success")
                return redirect(url_for('member_dashboard'))
            
            flash('Invalid username or password', 'danger')
            return render_template('login.html')
        except Exception as e:
            app.logger.error(f"An error occured during login username: {username}, error: {str(e)}")
            flash("An error occured. Please try again later.", 'danger')
            return render_template('login.html')
        
    return render_template('login.html')


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    is_admin_result = is_admin()
    if is_admin_result is not None:
        return is_admin_result
    
    app.logger.info(f"Admin: {current_user.username} access dashboard.")

    active_members_count = Member.query.filter((Member.status == 'new') | (Member.status == 'old')).count()
    pending_bills_count = Bill.query.filter_by(status='pending').count()
    total_revenue = db.session.query(db.func.sum(Bill.amount)).filter(Bill.status == 'paid').scalar() or 0.00
    expired_bills_count = Bill.query.filter(Bill.status == 'pending', Bill.due_date < date.today()).count()

    return render_template('admin_dashboard.html', active_members_count=active_members_count, pending_bills_count=pending_bills_count, total_revenue=total_revenue, expired_bills_count=expired_bills_count, current_date=date.today(), title='Admin Dashboard')

@app.route('/admin/add-member', methods=['GET', 'POST'])
@login_required
def add_member():
    is_admin_result = is_admin()
    if is_admin_result is not None:
        return is_admin_result
    
    if request.method == 'POST':
        name = request.form.get('name').strip()
        email = request.form.get('email').strip()
        phone = request.form.get('phone').strip()
        fee_package = request.form.get('fee_package').strip()
        member_password = generate_random_password().strip()
        
        try:
            if not all([name, email, phone, fee_package]):
                flash('All fields are required.', 'danger')
                return render_template('add_member.html', current_date=date.today())
            
            if name and not re.match(r"^[A-Za-z\s]+$", name):
                flash('Name should be letters or spaces', 'danger')
                return render_template('add_member.html', current_date=date.today())
            
            if email and not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
                flash('Invalid email format', 'danger')
                return render_template('add_member.html', current_date=date.today())
            
            if phone and not re.match(r"^[6-9]\d{9}$", phone):
                flash('Enter a valid 10-digit Indian phone number', 'danger')
                return render_template('add_member.html', current_date=date.today())
            
            if Member.query.filter_by(email=email).first():
                flash('Email already register.', 'danger')
                return render_template('add_memeber.html', current_date=date.today())
            
            new_member = Member(
                name=name,
                username=email.split('@')[0],
                email=email,
                phone=phone,
                join_date=date.today(),
                fee_package=fee_package
            )
            new_member.set_password(member_password)
            db.session.add(new_member)
            db.session.commit()
            app.logger.info(f"Member: {new_member.username} added successfully with temporary password: {member_password} by {current_user.username}")
            flash(f"{new_member.username} added successully! Temporary password: {member_password} \nPlease note it and share with the member manually.", "success")
            return redirect(url_for('admin_dashboard'))
        
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"An error occured during add member: {email}, via: {current_user.username}, erorr: {str(e)}")
            flash('An error ocuured. Please try again later.', 'danger')
            return render_template('add_member.html', current_date=date.today(), title='Add Member')
        
    return render_template('add_member.html', current_date=date.today(), title='Add Member')


@app.route('/update-delete-members', methods=['GET', 'POST'])
@login_required
def update_delete_members():
    is_admin_result = is_admin()
    if is_admin_result is not None:
        return is_admin_result
    
    members = Member.query.all()

    if request.method == 'POST':
        member_id = request.form.get('member_id')
        action = request.form.get('action')

        # member = Member.query.get(member_id)
        member = db.session.get(Member, member_id)
        if not member:
            flash('Members not found.', 'danger')
            return redirect(url_for('update_delete_members', current_date=date.today()))
        
        if action == 'update':
            return redirect(url_for('update_member', member_id=member_id))
        elif action == 'delete':
            db.session.delete(member)
            db.session.commit()
            flash('Member deleted successfully!', 'success')
            return redirect(url_for('update_delete_members', current_date=date.today()))
        
    return render_template('update_delete_members.html', members=members, current_date=date.today())

@app.route('/update-member/<int:member_id>', methods=['GET', 'POST'])
@login_required
def update_member(member_id):
    is_admin_result = is_admin()
    if is_admin_result is not None:
        return is_admin_result
    
    try:
        member = Member.query.get_or_404(member_id)
    except Exception as e:
        app.logger.error(f"Error to fethcing member: {member_id}, error: {str(e)}" )
        flash('An error occured. Please try again later.', 'danger')
        return redirect(url_for('update_delete_members'))
    
    if request.method == 'POST':
        try:
            name=request.form.get('name')
            email=request.form.get('email')
            phone=request.form.get('phone')
            fee_package=request.form.get('fee_package')

            if Member.query.filter(Member.email == email, Member.id != member_id).first():
                flash('Email already register by another member', 'danger')
                return redirect(url_for('update_member', member_id=member_id))
            
            member.name = name
            member.email = email
            member.username = email.split('@')[0]
            member.phone = phone
            member.fee_package = fee_package
            db.session.commit()
            app.logger.info(f"Updated: {member.username} data")
            flash('Member Updated Successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating member: {str(e)}")
            flash('An erro occured. Please try again later.', 'danger')

        return redirect(url_for('update_delete_members'))
    
    return render_template('update_member.html', member=member, current_date=date.today())


@app.route('/create-bills', methods=['GET', 'POST'])
@login_required
def create_bills():
    is_admin_result = is_admin()
    if is_admin_result is not None:
        return is_admin_result
    
    today = date.today()
    eligible_members = []
    try:
        threshold_date_new = date.today() - timedelta(days=3)
        # Fetch member eligible for first bill (join date + 3 days complete)
        new_members = Member.query.filter(
            Member.status == 'new',
            Member.join_date <= threshold_date_new
        ).all()

        # Fetch old member eligible for monthly bill (last bill paid + 30 days)
        threshold_date_old = date.today() - timedelta(days=30)
        old_members = Member.query.filter(
            Member.status == 'old'
        ).join(Bill).filter(
            Bill.member_id == Member.id,
            Bill.status == 'paid',
            Bill.issue_date <= threshold_date_old
        ).all()
        
        eligible_members = new_members + old_members
        
    except Exception as e:
        app.logger.error(f"Error fetching eligible members: {str(e)}")
        return render_template(url_for('create_bills'))

    if request.method == 'POST':
        try:
            print(f"Hey eligible member: {eligible_members}")
            member_id = request.form.get('member_id')
            # member = Member.query.get(member_id)
            member = db.session.get(Member, member_id)
            if not member:
                flash('Member not found', 'danger')
                return redirect(url_for('create_bills'))
            
            fee_amounts = {'Basic':500.00, 'Premium':1000.00, 'Pro':1500.00}
            amount = fee_amounts.get(member.fee_package, 0.00)
            if member.status == 'new':
                issue_date = member.join_date + timedelta(days=3)
            else:  # old members
                last_paid_bill = Bill.query.filter_by(member_id=member.id, status='paid').order_by(Bill.issue_date.desc()).first()
                issue_date = last_paid_bill.issue_date + timedelta(days=30) if last_paid_bill else date.today()

            # Check if bill already exists for this month
            existing_bill_this_month = Bill.query.filter(
                Bill.member_id == member_id,
                Bill.issue_date >= date(today.year, today.month, 1),  # Start of current month
                Bill.issue_date <= today
            ).first()
            if existing_bill_this_month:
                flash('Bill already created this month!', 'danger')
                return redirect(url_for('create_bills'))

            due_date = issue_date + timedelta(days=7)
            status = 'pending'

            
            new_bill = Bill(
                member_id = member_id,
                amount=amount,
                issue_date=issue_date,
                due_date=due_date,
                status=status
            )
            db.session.add(new_bill)
            db.session.flush()

            # Generate Receipt PDF
            pdf_folder = 'static/receipts'
            if not os.path.exists(pdf_folder):
                os.makedirs(pdf_folder)
            
            

            # Setup PDF path
            receipt_filename = f"bill_{new_bill.id}_{member.username}.pdf"
            pdf_path = os.path.join(pdf_folder, receipt_filename)
            pdf = SimpleDocTemplate(pdf_path, pagesize=letter, author="GYMMANAGER")
            bill_type = 'First' if member.status == 'new' else 'Monthly'
            elements = []

            # Define Paragraph Style
            center_style = ParagraphStyle(
                name='CenterStyle',
                alignment=1,  # Center alignment
                fontSize=20,
                fontName='Times-Roman',
                colors = colors.darkgray
            )
            detail_style = ParagraphStyle(
                name='DetailStyle',
                alignment=0,  # Left alignment
                fontSize=14,
                fontName='Times-Roman',
            )
            footer_style = ParagraphStyle(
                name='FooterStyle',
                alignment=1,  # Center alignment
                fontSize=12,
                fontName='Times-Roman'
            )

            # Header
            elements.append(Paragraph(f"GYMMANAGER", center_style))
            elements.append(Spacer(1, 12))
            elements.append(HRFlowable(width="100%", thickness=1, color=colors.black, spaceAfter=12, spaceBefore=12))
            elements.append(Spacer(1, 40))
            

            member_data = [
                ['Member ID:', f'GM{member.id}'],
                ['Member Name:', member.name],
                ['Member Email:', member.email],
                ['Phone Number:', member.phone],
                ['Join Date:', str(member.join_date)],
                ['Fee Package:', member.fee_package],
            ]

            member_table = Table(member_data, colWidths=[1.8*inch, 3.5*inch])
            member_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, -1), 'Times-Roman'),
                ('FONTSIZE', (0, 0), (-1, -1), 16),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('ALIGN', (1, 0), (1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 10)
            ]))

            
            elements.append(member_table)
            elements.append(Spacer(1, 100))

            # Table (Increased font and size)
            data = [
                ['Bill Type', 'Issue Date', 'Due Date', 'Amount'],
                [bill_type, str(issue_date), str(due_date), f"{amount}"]
            ]
            table = Table(data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch], rowHeights=0.5*inch)
            table.setStyle(TableStyle([
                ('FONTSIZE', (0, 0), (-1, -1), 14),  # Increased font size
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#3B57D1")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#f9f9f9")),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Times-Bold'),
                ('FONTNAME', (0, 1), (-1, 1), 'Times-Roman'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
            ]))
            elements.append(table)
            elements.append(Spacer(1, 80))

            # Footer
            elements.append(Spacer(1, 80))
            elements.append(HRFlowable(width="100%", thickness=1, color=colors.black, spaceAfter=12, spaceBefore=12))
            elements.append(Paragraph(f"Thank you for staying fit with us!", footer_style))
            elements.append(Spacer(1, 14))
            elements.append(Paragraph(f"Generated on: {date.today()}", footer_style))

            pdf.build(elements)

            new_receipt = Receipt(
                bill_id=new_bill.id,
                member_id=member_id,
                receipt_url=receipt_filename,
                generated_date=date.today()
            )
            db.session.add(new_receipt)

            notification_message = f"New bill generated for you. Amount: {amount}, Due Date: {due_date}"
            new_notification = Notification(member_id=member_id, message=notification_message, sent_date=date.today())
            db.session.add(new_notification)

            db.session.commit()

            if member.status == 'new':
                member.status = 'old'
                db.session.commit()

            app.logger.info(f"Bill create successfully for: {member.username}")
            flash('Bill created successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating bill for: {member.username}, error: {str(e)}")
            flash('An error occured to creat bill or bill receipt. Please try again later.', 'danger')

        return redirect(url_for('create_bills'))

    return render_template('create_bills.html', members=eligible_members, current_date=date.today())

@app.route('/receipts/<filename>')
@login_required
def serve_receipt(filename):
    return send_from_directory('static/receipts', filename)

# New route for admin to view bills
@app.route('/admin/bills')
@login_required
def admin_bills():
    is_admin_result = is_admin()
    if is_admin_result is not None:
        return is_admin_result
    
    bills = Bill.query.join(Member).order_by(Bill.id.desc()).all()
    return render_template('admin_bills.html', bills=bills, current_date=date.today())


@app.route('/admin/assign-package', methods=['GET', 'POST'])
@login_required
def assign_package():
    is_admin_result = is_admin()
    if is_admin_result is not None:
        flash('Unauthorize Access.', 'danger')
        return is_admin_result
    
    members = Member.query.all()
    if request.method == 'POST':
        member_id = request.form.get('member_id')
        package = request.form.get('package')
        if member_id and package in ['Basic', 'Premium', 'Pro']:
            member = Member.query.get(member_id)
            if member:
                member.fee_package = package
                db.session.commit()
                flash('Fee package assigned successfully!', 'success')
            else:
                flash('Member not found.', 'danger')
        else:
            flash('Invalid package selection.', 'danger')
        return redirect(url_for('assign_package'))
    
    return render_template('assign_package.html', members=members, current_date = date.today())

# Route for admin to view notifications
@app.route('/admin/notifications')
@login_required
def admin_notifications():
    if current_user.role != 'admin':
        flash('Access denied! Admins only.', 'danger')
        return redirect(url_for('index'))
    notifications = Notification.query.join(Member).order_by(Notification.sent_date.desc()).all()
    return render_template('admin_notifications.html', notifications=notifications, current_date=date.today())


@app.route('/admin/manage-schedule', methods=['GET', 'POST'])
@login_required
def manage_schedule():
    is_admin_result = is_admin()
    if is_admin_result is not None:
        return is_admin_result
    
    schedules = GymSchedule.query.all()
    today = date.today()
    if request.method == 'POST':
        schedule_date = request.form.get('schedule_date')
        status = request.form.get('status')
        if schedule_date and status in ['open', 'closed']:
            try:
                schedule_date = datetime.strptime(schedule_date, '%Y-%m-%d').date()
                if schedule_date < today:
                    flash('Only today or future dates are allowed.', 'danger')
                    return redirect(url_for('manage_schedule'))
                existing_schedule = GymSchedule.query.filter_by(schedule_date=schedule_date).first()
                if existing_schedule:
                    existing_schedule.status = status
                else:
                    new_schedule = GymSchedule(schedule_date=schedule_date, status=status)
                    db.session.add(new_schedule)
                # Send notification to all members
                members = Member.query.all()
                for member in members:
                    notification_message = f"Gym schedule updated for {schedule_date}: Status is {status}."
                    new_notification = Notification(member_id=member.id, message=notification_message, sent_date=date.today())
                    db.session.add(new_notification)
                db.session.commit()
                flash('Schedule updated and notifications sent!', 'success')
            except ValueError:
                flash('Invalid date format. Use YYYY-MM-DD.', 'danger')
        else:
            flash('Date and status are required.', 'danger')
        return redirect(url_for('manage_schedule'))
    return render_template('manage_schedule.html', schedules=schedules, today=date.today().strftime('%Y-%m-%d'), current_date=date.today())

@app.route('/admin/view-schedule')
@login_required
def view_schedule():
    is_admin_result = is_admin()
    if is_admin_result is not None:
        return is_admin_result
    
    schedules = GymSchedule.query.order_by(GymSchedule.schedule_date.desc()).all()
    return render_template('view_schedule.html', schedules=schedules, current_date=date.today())

@app.route('/member/dashboard')
@login_required
def member_dashboard():
    is_member_result = is_member()
    if is_member_result is not None:
        return is_member_result
    
    
    app.logger.info(f"Member: {current_user.username} access dashboard.")
    return render_template('member_dashboard.html', title='Member Dashboard', current_date=date.today())

@app.route('/member/bill-notifications')
@login_required
def member_bill_notifications():
    is_member_result = is_member()
    if is_member_result is not None:
        return is_member_result
    
    # Fetch bill notifications for the current member
    notifications = Notification.query.filter_by(member_id=current_user.id).order_by(Notification.sent_date.desc()).all()
    app.logger.info(f"Member: {current_user.username} accessed bill notifications.")
    return render_template('member_bill_notifications.html', notifications=notifications, current_date=date.today(), title='Bill Notifications')


@app.route('/member/view-bill-receipts')
@login_required
def member_view_bill_receipts():
    is_member_result = is_member()
    if is_member_result is not None:
        return is_member_result
    
    app.logger.info(f"Member: {current_user.username} accessed view bill receipts.")
    try:
        # Fetch bills and their receipts for the current member
        bills = Bill.query.filter_by(member_id=current_user.id).order_by(Bill.due_date.desc()).all()

        receipts = Receipt.query.filter_by(member_id=current_user.id).all()
        return render_template('member_view_bill_receipts.html', title='View Bill Receipts', bills=bills, receipts=receipts, current_date=date.today())
    
    except Exception as e:
        app.logger.error(f"Error fetching bills/receipts for {current_user.username}: {str(e)}")
        flash('An error occurred while loading bills. Please try again later.', 'danger')
        return redirect(url_for('member_dashboard'))
    
@app.route('/member/view-schedule')
@login_required
def member_view_schedule():
    is_member_result = is_member()
    if is_member_result is not None:
        return is_member_result
    
    app.logger.info(f"Member: {current_user.username} accessed view schedule.")
    try:
        # Fetch gym schedules
        schedules = GymSchedule.query.order_by(GymSchedule.schedule_date.desc()).all()
        return render_template('member_view_schedule.html', title='View Gym Schedule', schedules=schedules, current_date=date.today())
    except Exception as e:
        app.logger.error(f"Error fetching schedule for {current_user.username}: {str(e)}")
        flash('An error occurred while loading schedule. Please try again later.', 'danger')
        return redirect(url_for('member_dashboard'))
    
@app.route('/member/change-password', methods=['GET', 'POST'])
@login_required
def member_change_password():
    is_member_result = is_member()
    if is_member_result is not None:
        return is_member_result
    
    app.logger.info(f"Member: {current_user.username} accessed change password.")
    if request.method == 'POST':
        try:
            temp_password = request.form.get('temp_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            if not all([temp_password, new_password, confirm_password]):
                flash('All fields are required.', 'danger')
                return redirect(url_for('change_password'))

            # Fetch current member
            member = Member.query.filter_by(id=current_user.id).first()
            if not member:
                flash('Member not found.', 'danger')
                return redirect(url_for('member_change_password'))

            # Check if status is 'new' and temp_password matches
            if member.status != 'new':
                flash('Password can only be changed for new members with temporary password.', 'danger')
                return redirect(url_for('member_change_password'))
            if not member.check_password(temp_password):
                flash('Invalid temporary password. Please try again.', 'danger')
                return redirect(url_for('member_change_password'))

            # Validate new password
            if not new_password or new_password != confirm_password:
                flash('New passwords do not match or are empty. Please try again.', 'danger')
                return redirect(url_for('member_change_password'))

            # Update password and status
            member.set_password(new_password)
            db.session.commit()
            app.logger.info(f"Member: {current_user.username} successfully change their their password.")
            flash('Password changed successfully! Your account is now active.', 'success')
            return redirect(url_for('member_dashboard'))
        except Exception as e:
            app.logger.error(f"Error changing password for {current_user.username}: {str(e)}")
            db.session.rollback()
            flash('An error occurred while changing password. Please try again later.', 'danger')
            return redirect(url_for('member_change_password'))

    return render_template('member_change_password.html', title='Change Password', current_date=date.today())




@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))


# Initialize Database 
with app.app_context():
    db.create_all()
    # create default admin if not exists
    if not Admin.query.filter_by(username='admin').first():
        admin = Admin(username='admin', email='admin@example.com')
        admin_password = generate_random_password()
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()
        app.logger.info(f"Default admin created with password: {admin_password}")

    # Create default user if not exists
    if not Member.query.filter_by(username='member').first():
        member = Member(name='Default Member', email='member@example.com', username='member', fee_package='Basic')
        member_password = generate_random_password()
        member.set_password(member_password)
        member.join_date = date.today()
        db.session.add(member)
        db.session.commit()
        app.logger.info(f"Default member created with password: {member_password}")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug = True)