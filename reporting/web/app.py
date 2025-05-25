# shikra/modules/reporting/web/app.py
# Purpose: Flask-based web interface for the Shikra malware analysis platform

import logging
import os
import json
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import hashlib
import mimetypes
import threading
import time

# Flask and web dependencies
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, SelectField, TextAreaField, BooleanField, IntegerField
from wtforms.validators import DataRequired, Length, Email
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import NotFound, BadRequest, InternalServerError

# Optional dependencies for enhanced functionality
try:
    from flask_socketio import SocketIO, emit, join_room, leave_room
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False
    SocketIO = None

try:
    import sqlite3
    DATABASE_AVAILABLE = True
except ImportError:
    DATABASE_AVAILABLE = False

# Shikra components integration
from ..report_generator import ReportGenerator
from ..visualizer import DataVisualizer

# Configure logging for this module
logger = logging.getLogger(__name__)

# Simple User model for demonstration (in production, use proper database)
class User(UserMixin):
    def __init__(self, user_id, username, email, password_hash, role='analyst'):
        self.id = user_id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role = role
        self.is_active = True
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role == 'admin'

# Simple in-memory user store (replace with database in production)
USERS = {
    'admin': User('admin', 'admin', 'admin@shikra.local', 
                  generate_password_hash('admin123'), 'admin'),
    'analyst': User('analyst', 'analyst', 'analyst@shikra.local',
                    generate_password_hash('analyst123'), 'analyst')
}

# Form classes
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    password = StringField('Password', validators=[DataRequired()])

class SampleSubmissionForm(FlaskForm):
    sample_file = FileField('Malware Sample', validators=[
        FileRequired(),
        FileAllowed(['exe', 'dll', 'bin', 'zip', 'rar', '7z', 'pdf', 'doc', 'docx', 'xls', 'xlsx'], 
                   'Executable files, archives, and documents only!')
    ])
    vm_profile = SelectField('VM Profile', choices=[
        ('windows_10_x64', 'Windows 10 x64'),
        ('windows_7_x64', 'Windows 7 x64'),
        ('ubuntu_20_x64', 'Ubuntu 20.04 x64')
    ], default='windows_10_x64')
    analysis_timeout = IntegerField('Analysis Timeout (minutes)', default=10, validators=[DataRequired()])
    network_simulation = BooleanField('Enable Network Simulation', default=True)
    detailed_logging = BooleanField('Enable Detailed Logging', default=False)
    description = TextAreaField('Sample Description', validators=[Length(max=500)])

class SearchForm(FlaskForm):
    query = StringField('Search Query', validators=[DataRequired()])
    search_type = SelectField('Search Type', choices=[
        ('all', 'All Fields'),
        ('filename', 'Filename'),
        ('hash', 'File Hash'),
        ('ioc', 'IOCs'),
        ('signature', 'Signatures')
    ], default='all')

class ShikraWebApp:
    """
    Flask-based web application providing user interface for Shikra malware analysis.
    """
    
    def __init__(self, data_directory: Optional[Path] = None, 
                 config_file: Optional[Path] = None):
        """
        Initialize the Shikra web application with configuration.
        """
        self.app = Flask(__name__, 
                        template_folder='templates',
                        static_folder='static')
        self.data_directory = data_directory or Path("./data")
        self.config_file = config_file
        
        # Analysis tracking
        self.active_analyses = {}  # analysis_id -> status info
        self.analysis_queue = []   # pending analyses
        self.completed_analyses = {}  # analysis_id -> results
        
        # Initialize components
        self.report_generator = ReportGenerator()
        self.visualizer = DataVisualizer()
        
        self._setup_flask_config()
        self._setup_authentication()
        self._setup_routes()
        self._setup_error_handlers()
        self._setup_websockets()
        self._load_existing_analyses()
        
        logger.info("ShikraWebApp initialized")
    
    def _setup_flask_config(self):
        """Configure Flask application settings and security parameters."""
        # Basic Flask configuration
        self.app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'shikra-dev-key-change-in-production')
        self.app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
        self.app.config['UPLOAD_FOLDER'] = self.data_directory / 'uploads'
        self.app.config['RESULTS_FOLDER'] = self.data_directory / 'results'
        self.app.config['REPORTS_FOLDER'] = self.data_directory / 'reports'
        
        # Create necessary directories
        for folder in ['UPLOAD_FOLDER', 'RESULTS_FOLDER', 'REPORTS_FOLDER']:
            Path(self.app.config[folder]).mkdir(parents=True, exist_ok=True)
        
        # Security settings
        self.app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
        self.app.config['SESSION_COOKIE_HTTPONLY'] = True
        self.app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
        
        # CSRF Protection
        self.csrf = CSRFProtect(self.app)
        
        # Custom Jinja2 filters
        self.app.jinja_env.filters['datetime'] = self._format_datetime
        self.app.jinja_env.filters['filesize'] = self._format_filesize
        self.app.jinja_env.filters['truncate_hash'] = lambda x: f"{x[:8]}...{x[-8:]}" if len(x) > 16 else x
    
    def _setup_authentication(self):
        """Set up Flask-Login for user authentication."""
        self.login_manager = LoginManager()
        self.login_manager.init_app(self.app)
        self.login_manager.login_view = 'login'
        self.login_manager.login_message = 'Please log in to access Shikra.'
        
        @self.login_manager.user_loader
        def load_user(user_id):
            return USERS.get(user_id)
    
    def _setup_routes(self):
        """Define all Flask routes and URL endpoints."""
        
        # Authentication routes
        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            if current_user.is_authenticated:
                return redirect(url_for('dashboard'))
            
            form = LoginForm()
            if form.validate_on_submit():
                user = USERS.get(form.username.data)
                if user and user.check_password(form.password.data):
                    login_user(user, remember=True)
                    next_page = request.args.get('next')
                    flash(f'Welcome back, {user.username}!', 'success')
                    return redirect(next_page) if next_page else redirect(url_for('dashboard'))
                else:
                    flash('Invalid username or password.', 'danger')
            
            return render_template('auth/login.html', form=form)
        
        @self.app.route('/logout')
        @login_required
        def logout():
            logout_user()
            flash('You have been logged out.', 'info')
            return redirect(url_for('login'))
        
        # Main application routes
        @self.app.route('/')
        @self.app.route('/dashboard')
        @login_required
        def dashboard():
            return self.dashboard_view()
        
        @self.app.route('/analyses')
        @login_required
        def analysis_list():
            return self.analysis_list_view()
        
        @self.app.route('/analysis/<analysis_id>')
        @login_required
        def analysis_detail(analysis_id):
            return self.analysis_detail_view(analysis_id)
        
        @self.app.route('/submit', methods=['GET', 'POST'])
        @login_required
        def sample_submission():
            return self.sample_submission_view()
        
        @self.app.route('/search')
        @login_required
        def search():
            return self.search_interface()
        
        # API routes
        @self.app.route('/api/analyses')
        @login_required
        def api_analyses():
            return self.api_analysis_list()
        
        @self.app.route('/api/analysis/<analysis_id>')
        @login_required
        def api_analysis(analysis_id):
            return self.api_analysis_detail(analysis_id)
        
        @self.app.route('/api/submit', methods=['POST'])
        @login_required
        def api_submit():
            return self.api_sample_submission()
        
        @self.app.route('/api/status/<analysis_id>')
        @login_required
        def api_status(analysis_id):
            return self.api_analysis_status(analysis_id)
        
        @self.app.route('/api/search/ioc')
        @login_required
        def api_ioc_search():
            return self.api_ioc_search()
        
        # Export routes
        @self.app.route('/export/<analysis_id>/<export_format>')
        @login_required
        def export_analysis(analysis_id, export_format):
            return self.export_analysis_data(analysis_id, export_format)
        
        # Administrative routes
        @self.app.route('/admin')
        @login_required
        def admin():
            if not current_user.is_admin():
                flash('Administrative access required.', 'danger')
                return redirect(url_for('dashboard'))
            return self.administrative_interface()
        
        # File serving routes
        @self.app.route('/static/reports/<path:filename>')
        @login_required
        def serve_report(filename):
            return send_file(self.app.config['REPORTS_FOLDER'] / filename)
        
        @self.app.route('/static/visualizations/<path:filename>')
        @login_required
        def serve_visualization(filename):
            viz_path = self.data_directory / 'visualizations' / filename
            if viz_path.exists():
                return send_file(viz_path)
            else:
                return NotFound()
    
    def _setup_error_handlers(self):
        """Configure error handling for common HTTP errors."""
        
        @self.app.errorhandler(404)
        def not_found_error(error):
            return render_template('errors/404.html'), 404
        
        @self.app.errorhandler(500)
        def internal_error(error):
            logger.error(f"Internal server error: {error}")
            return render_template('errors/500.html'), 500
        
        @self.app.errorhandler(413)
        def too_large(error):
            flash('File too large. Maximum size is 100MB.', 'danger')
            return redirect(url_for('sample_submission'))
    
    def _setup_websockets(self):
        """Set up WebSocket support for real-time updates."""
        if SOCKETIO_AVAILABLE:
            self.socketio = SocketIO(self.app, cors_allowed_origins="*")
            
            @self.socketio.on('join_analysis')
            def on_join_analysis(data):
                analysis_id = data['analysis_id']
                join_room(analysis_id)
                emit('status', {'message': f'Joined analysis {analysis_id}'})
            
            @self.socketio.on('leave_analysis')
            def on_leave_analysis(data):
                analysis_id = data['analysis_id']
                leave_room(analysis_id)
        else:
            self.socketio = None
            logger.warning("SocketIO not available. Real-time updates disabled.")
    
    def _load_existing_analyses(self):
        """Load existing analysis results from the data directory."""
        try:
            results_folder = Path(self.app.config['RESULTS_FOLDER'])
            if results_folder.exists():
                for result_dir in results_folder.iterdir():
                    if result_dir.is_dir():
                        analysis_json = result_dir / 'analysis_results.json'
                        if analysis_json.exists():
                            with open(analysis_json, 'r') as f:
                                self.completed_analyses[result_dir.name] = json.load(f)
            
            logger.info(f"Loaded {len(self.completed_analyses)} existing analyses")
        except Exception as e:
            logger.error(f"Error loading existing analyses: {e}")
    
    def _format_datetime(self, dt):
        """Jinja2 filter for datetime formatting."""
        if isinstance(dt, str):
            try:
                dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
            except:
                return dt
        elif isinstance(dt, (int, float)):
            dt = datetime.fromtimestamp(dt)
        
        if isinstance(dt, datetime):
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        return str(dt)
    
    def _format_filesize(self, size_bytes):
        """Jinja2 filter for file size formatting."""
        if not isinstance(size_bytes, (int, float)):
            return str(size_bytes)
        
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"
    
    def dashboard_view(self):
        """Render the main dashboard page."""
        try:
            # Gather dashboard statistics
            total_analyses = len(self.completed_analyses) + len(self.active_analyses)
            active_count = len(self.active_analyses)
            queued_count = len(self.analysis_queue)
            
            # Recent analyses (last 10)
            recent_analyses = []
            for analysis_id, data in list(self.completed_analyses.items())[-10:]:
                recent_analyses.append({
                    'id': analysis_id,
                    'filename': data.get('sample_info', {}).get('filename', 'Unknown'),
                    'timestamp': data.get('metadata', {}).get('generated_at', ''),
                    'score': self._get_overall_score(data),
                    'classification': self._get_classification(data)
                })
            
            # System statistics
            threat_distribution = Counter()
            for data in self.completed_analyses.values():
                classification = self._get_classification(data)
                threat_distribution[classification] += 1
            
            # Active analyses status
            active_analyses_info = []
            for analysis_id, status in self.active_analyses.items():
                active_analyses_info.append({
                    'id': analysis_id,
                    'filename': status.get('filename', 'Unknown'),
                    'progress': status.get('progress', 0),
                    'current_phase': status.get('current_phase', 'Unknown'),
                    'started': status.get('started', '')
                })
            
            dashboard_data = {
                'stats': {
                    'total_analyses': total_analyses,
                    'active_analyses': active_count,
                    'queued_analyses': queued_count,
                    'completed_today': self._count_analyses_today()
                },
                'recent_analyses': recent_analyses,
                'threat_distribution': dict(threat_distribution),
                'active_analyses': active_analyses_info,
                'system_health': self._get_system_health()
            }
            
            return render_template('dashboard.html', **dashboard_data)
            
        except Exception as e:
            logger.error(f"Error in dashboard view: {e}")
            flash('Error loading dashboard data.', 'danger')
            return render_template('dashboard.html', 
                                 stats={}, recent_analyses=[], 
                                 threat_distribution={}, active_analyses=[])
    
    def analysis_list_view(self):
        """Display a paginated list of all analysis results."""
        try:
            # Get pagination parameters
            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 20, type=int)
            sort_by = request.args.get('sort', 'timestamp')
            order = request.args.get('order', 'desc')
            
            # Get filter parameters
            classification_filter = request.args.get('classification', '')
            score_min = request.args.get('score_min', type=int)
            score_max = request.args.get('score_max', type=int)
            
            # Prepare analysis list
            analyses = []
            for analysis_id, data in self.completed_analyses.items():
                analysis_item = {
                    'id': analysis_id,
                    'filename': data.get('sample_info', {}).get('filename', 'Unknown'),
                    'timestamp': data.get('metadata', {}).get('generated_at', ''),
                    'score': self._get_overall_score(data),
                    'classification': self._get_classification(data),
                    'size': data.get('sample_info', {}).get('size_bytes', 0),
                    'hash': data.get('sample_info', {}).get('sha256', '')[:16] + '...'
                }
                
                # Apply filters
                if classification_filter and analysis_item['classification'] != classification_filter:
                    continue
                    
                if score_min is not None and analysis_item['score'] < score_min:
                    continue
                    
                if score_max is not None and analysis_item['score'] > score_max:
                    continue
                
                analyses.append(analysis_item)
            
            # Sort analyses
            reverse = (order == 'desc')
            if sort_by == 'timestamp':
                analyses.sort(key=lambda x: x['timestamp'], reverse=reverse)
            elif sort_by == 'score':
                analyses.sort(key=lambda x: x['score'], reverse=reverse)
            elif sort_by == 'filename':
                analyses.sort(key=lambda x: x['filename'].lower(), reverse=reverse)
            
            # Pagination
            total = len(analyses)
            start = (page - 1) * per_page
            end = start + per_page
            analyses_page = analyses[start:end]
            
            pagination = {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page,
                'has_prev': page > 1,
                'has_next': end < total
            }
            
            return render_template('analyses/list.html', 
                                 analyses=analyses_page,
                                 pagination=pagination,
                                 filters={
                                     'classification': classification_filter,
                                     'score_min': score_min,
                                     'score_max': score_max,
                                     'sort': sort_by,
                                     'order': order
                                 })
            
        except Exception as e:
            logger.error(f"Error in analysis list view: {e}")
            flash('Error loading analysis list.', 'danger')
            return render_template('analyses/list.html', analyses=[], pagination={})
    
    def analysis_detail_view(self, analysis_id: str):
        """Display detailed view of a specific analysis result."""
        try:
            if analysis_id not in self.completed_analyses:
                if analysis_id in self.active_analyses:
                    # Show progress page for active analysis
                    return render_template('analyses/progress.html', 
                                         analysis_id=analysis_id,
                                         status=self.active_analyses[analysis_id])
                else:
                    flash(f'Analysis {analysis_id} not found.', 'danger')
                    return redirect(url_for('analysis_list'))
            
            analysis_data = self.completed_analyses[analysis_id]
            
            # Process analysis data for display
            display_data = {
                'analysis_id': analysis_id,
                'sample_info': analysis_data.get('sample_info', {}),
                'metadata': analysis_data.get('metadata', {}),
                'executive_summary': analysis_data.get('executive_summary', {}),
                'threat_assessment': analysis_data.get('threat_assessment', {}),
                'behavioral_analysis': analysis_data.get('behavioral_analysis', {}),
                'network_analysis': analysis_data.get('network_analysis', {}),
                'memory_analysis': analysis_data.get('memory_analysis', {}),
                'iocs': analysis_data.get('iocs', {}),
                'mitre_attack': analysis_data.get('mitre_attack', []),
                'timeline': analysis_data.get('timeline', [])[:50],  # Limit for display
                'visualizations': self._get_analysis_visualizations(analysis_id)
            }
            
            return render_template('analyses/detail.html', **display_data)
            
        except Exception as e:
            logger.error(f"Error in analysis detail view for {analysis_id}: {e}")
            flash('Error loading analysis details.', 'danger')
            return redirect(url_for('analysis_list'))
    
    def sample_submission_view(self):
        """Provide interface for submitting new malware samples."""
        form = SampleSubmissionForm()
        
        if form.validate_on_submit():
            try:
                # Handle file upload
                uploaded_file = form.sample_file.data
                filename = secure_filename(uploaded_file.filename)
                
                # Generate unique analysis ID
                analysis_id = str(uuid.uuid4())
                
                # Create analysis directory
                analysis_dir = Path(self.app.config['UPLOAD_FOLDER']) / analysis_id
                analysis_dir.mkdir(parents=True, exist_ok=True)
                
                # Save uploaded file
                file_path = analysis_dir / filename
                uploaded_file.save(file_path)
                
                # Calculate file hash
                file_hash = self._calculate_file_hash(file_path)
                
                # Create analysis configuration
                analysis_config = {
                    'analysis_id': analysis_id,
                    'filename': filename,
                    'file_path': str(file_path),
                    'file_hash': file_hash,
                    'vm_profile': form.vm_profile.data,
                    'analysis_timeout': form.analysis_timeout.data,
                    'network_simulation': form.network_simulation.data,
                    'detailed_logging': form.detailed_logging.data,
                    'description': form.description.data,
                    'submitted_by': current_user.username,
                    'submitted_at': datetime.utcnow().isoformat()
                }
                
                # Add to analysis queue
                self.analysis_queue.append(analysis_config)
                
                # Start analysis in background
                self._start_background_analysis(analysis_config)
                
                flash(f'Sample submitted successfully! Analysis ID: {analysis_id}', 'success')
                return redirect(url_for('analysis_detail', analysis_id=analysis_id))
                
            except Exception as e:
                logger.error(f"Error in sample submission: {e}")
                flash('Error submitting sample. Please try again.', 'danger')
        
        return render_template('submit.html', form=form)
    
    def search_interface(self):
        """Provide advanced search functionality."""
        form = SearchForm()
        results = []
        search_performed = False
        
        if form.validate_on_submit() or request.args.get('q'):
            search_performed = True
            query = form.query.data or request.args.get('q', '')
            search_type = form.search_type.data or request.args.get('type', 'all')
            
            try:
                results = self._perform_search(query, search_type)
            except Exception as e:
                logger.error(f"Search error: {e}")
                flash('Search error occurred.', 'danger')
        
        return render_template('search.html', 
                             form=form, 
                             results=results,
                             search_performed=search_performed)
    
    def api_analysis_list(self):
        """RESTful API endpoint returning list of all analyses."""
        try:
            page = request.args.get('page', 1, type=int)
            per_page = min(request.args.get('per_page', 20, type=int), 100)
            
            analyses = []
            for analysis_id, data in self.completed_analyses.items():
                analyses.append({
                    'id': analysis_id,
                    'filename': data.get('sample_info', {}).get('filename'),
                    'timestamp': data.get('metadata', {}).get('generated_at'),
                    'score': self._get_overall_score(data),
                    'classification': self._get_classification(data),
                    'url': url_for('api_analysis', analysis_id=analysis_id, _external=True)
                })
            
            # Pagination
            total = len(analyses)
            start = (page - 1) * per_page
            end = start + per_page
            
            return jsonify({
                'analyses': analyses[start:end],
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'pages': (total + per_page - 1) // per_page
                }
            })
            
        except Exception as e:
            logger.error(f"API analysis list error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    def api_analysis_detail(self, analysis_id: str):
        """RESTful API endpoint returning detailed analysis data."""
        try:
            if analysis_id not in self.completed_analyses:
                return jsonify({'error': 'Analysis not found'}), 404
            
            return jsonify(self.completed_analyses[analysis_id])
            
        except Exception as e:
            logger.error(f"API analysis detail error for {analysis_id}: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    def api_sample_submission(self):
        """RESTful API endpoint for programmatic sample submission."""
        try:
            if 'file' not in request.files:
                return jsonify({'error': 'No file provided'}), 400
            
            uploaded_file = request.files['file']
            if uploaded_file.filename == '':
                return jsonify({'error': 'No file selected'}), 400
            
            # Validate file type
            allowed_extensions = {'exe', 'dll', 'bin', 'zip', 'rar', '7z', 'pdf', 'doc', 'docx'}
            file_ext = uploaded_file.filename.rsplit('.', 1)[1].lower() if '.' in uploaded_file.filename else ''
            
            if file_ext not in allowed_extensions:
                return jsonify({'error': 'File type not allowed'}), 400
            
            # Process submission similar to web interface
            analysis_id = str(uuid.uuid4())
            filename = secure_filename(uploaded_file.filename)
            
            analysis_dir = Path(self.app.config['UPLOAD_FOLDER']) / analysis_id
            analysis_dir.mkdir(parents=True, exist_ok=True)
            
            file_path = analysis_dir / filename
            uploaded_file.save(file_path)
            
            analysis_config = {
                'analysis_id': analysis_id,
                'filename': filename,
                'file_path': str(file_path),
                'file_hash': self._calculate_file_hash(file_path),
                'vm_profile': request.form.get('vm_profile', 'windows_10_x64'),
                'analysis_timeout': int(request.form.get('timeout', 10)),
                'network_simulation': request.form.get('network_simulation', 'true').lower() == 'true',
                'submitted_by': getattr(current_user, 'username', 'api_user'),
                'submitted_at': datetime.utcnow().isoformat()
            }
            
            self.analysis_queue.append(analysis_config)
            self._start_background_analysis(analysis_config)
            
            return jsonify({
                'analysis_id': analysis_id,
                'status': 'queued',
                'message': 'Sample submitted successfully',
                'status_url': url_for('api_status', analysis_id=analysis_id, _external=True)
            }), 201
            
        except Exception as e:
            logger.error(f"API sample submission error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    def api_analysis_status(self, analysis_id: str):
        """RESTful API endpoint for checking analysis progress."""
        try:
            if analysis_id in self.completed_analyses:
                return jsonify({
                    'analysis_id': analysis_id,
                    'status': 'completed',
                    'progress': 100,
                    'result_url': url_for('api_analysis', analysis_id=analysis_id, _external=True)
                })
            elif analysis_id in self.active_analyses:
                status = self.active_analyses[analysis_id]
                return jsonify({
                    'analysis_id': analysis_id,
                    'status': 'running',
                    'progress': status.get('progress', 0),
                    'current_phase': status.get('current_phase', 'Unknown'),
                    'estimated_completion': status.get('estimated_completion')
                })
            elif any(item['analysis_id'] == analysis_id for item in self.analysis_queue):
                queue_position = next(i for i, item in enumerate(self.analysis_queue) 
                                    if item['analysis_id'] == analysis_id)
                return jsonify({
                    'analysis_id': analysis_id,
                    'status': 'queued',
                    'queue_position': queue_position + 1,
                    'estimated_start': self._estimate_queue_time(queue_position)
                })
            else:
                return jsonify({'error': 'Analysis not found'}), 404
                
        except Exception as e:
            logger.error(f"API status error for {analysis_id}: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    def api_ioc_search(self):
        """RESTful API endpoint for searching IOCs."""
        try:
            query = request.args.get('q', '')
            ioc_type = request.args.get('type', 'all')
            limit = min(request.args.get('limit', 100, type=int), 1000)
            
            if not query:
                return jsonify({'error': 'Query parameter required'}), 400
            
            results = []
            
            for analysis_id, data in self.completed_analyses.items():
                iocs = data.get('iocs', {})
                
                for category, ioc_list in iocs.items():
                    if ioc_type != 'all' and category != ioc_type:
                        continue
                    
                    if isinstance(ioc_list, list):
                        for ioc in ioc_list:
                            indicator = ioc.get('indicator', '') if isinstance(ioc, dict) else str(ioc)
                            
                            if query.lower() in indicator.lower():
                                results.append({
                                    'indicator': indicator,
                                    'type': category,
                                    'analysis_id': analysis_id,
                                    'context': ioc.get('context', '') if isinstance(ioc, dict) else '',
                                    'analysis_url': url_for('analysis_detail', analysis_id=analysis_id, _external=True)
                                })
                            
                            if len(results) >= limit:
                                break
                    
                    if len(results) >= limit:
                        break
                
                if len(results) >= limit:
                    break
            
            return jsonify({
                'query': query,
                'type': ioc_type,
                'total_results': len(results),
                'results': results
            })
            
        except Exception as e:
            logger.error(f"IOC search error: {e}")
            return jsonify({'error': 'Internal server error'}), 500
    
    def administrative_interface(self):
        """Administrative interface for system management."""
        try:
            # System statistics
            system_stats = {
                'total_analyses': len(self.completed_analyses),
                'active_analyses': len(self.active_analyses),
                'queued_analyses': len(self.analysis_queue),
                'disk_usage': self._get_disk_usage(),
                'memory_usage': self._get_memory_usage(),
                'uptime': self._get_uptime()
            }
            
            # Recent activities
            recent_activities = []
            for analysis_id, data in list(self.completed_analyses.items())[-20:]:
                recent_activities.append({
                    'type': 'analysis_completed',
                    'analysis_id': analysis_id,
                    'filename': data.get('sample_info', {}).get('filename', 'Unknown'),
                    'timestamp': data.get('metadata', {}).get('generated_at', ''),
                    'user': data.get('metadata', {}).get('submitted_by', 'Unknown')
                })
            
            # Active users
            active_users = self._get_active_users()
            
            # System health
            system_health = self._get_system_health()
            
            return render_template('admin/dashboard.html',
                                 system_stats=system_stats,
                                 recent_activities=recent_activities,
                                 active_users=active_users,
                                 system_health=system_health,
                                 analysis_queue=self.analysis_queue[:10])  # Show first 10 in queue
            
        except Exception as e:
            logger.error(f"Admin interface error: {e}")
            flash('Error loading administrative interface.', 'danger')
            return render_template('admin/dashboard.html', 
                                 system_stats={}, recent_activities=[], 
                                 active_users=[], system_health={})
    
    def export_analysis_data(self, analysis_id: str, export_format: str):
        """Export analysis data in various formats."""
        try:
            if analysis_id not in self.completed_analyses:
                return jsonify({'error': 'Analysis not found'}), 404
            
            analysis_data = self.completed_analyses[analysis_id]
            
            if export_format == 'json':
                # Create temporary file
                export_path = self.data_directory / 'exports' / f"{analysis_id}.json"
                export_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(export_path, 'w') as f:
                    json.dump(analysis_data, f, indent=2, default=str)
                
                return send_file(export_path, as_attachment=True, 
                               download_name=f"analysis_{analysis_id}.json")
            
            elif export_format == 'pdf':
                # Generate PDF report
                report_path = self.data_directory / 'exports' / f"{analysis_id}.pdf"
                report_path.parent.mkdir(parents=True, exist_ok=True)
                
                self.report_generator.generate_pdf_report(analysis_data, report_path)
                
                if report_path.exists():
                    return send_file(report_path, as_attachment=True,
                                   download_name=f"analysis_{analysis_id}.pdf")
                else:
                    flash('Error generating PDF report.', 'danger')
                    return redirect(url_for('analysis_detail', analysis_id=analysis_id))
            
            elif export_format == 'csv':
                # Export IOCs as CSV
                csv_path = self.data_directory / 'exports' / f"{analysis_id}_iocs.csv"
                csv_path.parent.mkdir(parents=True, exist_ok=True)
                
                self._export_iocs_csv(analysis_data, csv_path)
                
                return send_file(csv_path, as_attachment=True,
                               download_name=f"iocs_{analysis_id}.csv")
            
            else:
                return jsonify({'error': 'Unsupported export format'}), 400
                
        except Exception as e:
            logger.error(f"Export error for {analysis_id}: {e}")
            return jsonify({'error': 'Export failed'}), 500
    
    def websocket_status_updates(self):
        """WebSocket endpoint for real-time analysis status updates."""
        if not self.socketio:
            return jsonify({'error': 'WebSocket not available'}), 503
        
        @self.socketio.on('connect')
        def handle_connect():
            logger.info(f"WebSocket client connected: {request.sid}")
            emit('connected', {'message': 'Connected to Shikra WebSocket'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            logger.info(f"WebSocket client disconnected: {request.sid}")
    
    def run_application(self, host: str = '127.0.0.1', port: int = 5000, debug: bool = False):
        """Start the Flask web application server."""
        logger.info(f"Starting Shikra web application on {host}:{port}")
        
        if self.socketio:
            self.socketio.run(self.app, host=host, port=port, debug=debug)
        else:
            self.app.run(host=host, port=port, debug=debug)
    
    # Helper methods
    def _get_overall_score(self, analysis_data):
        """Extract overall threat score from analysis data."""
        threat_assessment = analysis_data.get('threat_assessment', {})
        return threat_assessment.get('overall_score', 0)
    
    def _get_classification(self, analysis_data):
        """Extract classification from analysis data."""
        executive_summary = analysis_data.get('executive_summary', {})
        return executive_summary.get('threat_level', 'Unknown')
    
    def _count_analyses_today(self):
        """Count analyses completed today."""
        today = datetime.now().date()
        count = 0
        
        for data in self.completed_analyses.values():
            timestamp_str = data.get('metadata', {}).get('generated_at', '')
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                if timestamp.date() == today:
                    count += 1
            except:
                continue
        
        return count
    
    def _get_system_health(self):
        """Get system health indicators."""
        return {
            'status': 'healthy',
            'cpu_usage': 'Normal',
            'memory_usage': 'Normal',
            'disk_space': 'Normal',
            'analysis_engine': 'Running'
        }
    
    def _calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of file."""
        import hashlib
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()
    
    def _get_analysis_visualizations(self, analysis_id):
        """Get available visualizations for an analysis."""
        viz_dir = self.data_directory / 'visualizations' / analysis_id
        visualizations = []
        
        if viz_dir.exists():
            for viz_file in viz_dir.glob('*.png'):
                visualizations.append({
                    'name': viz_file.stem,
                    'path': f'/static/visualizations/{analysis_id}/{viz_file.name}',
                    'type': 'image'
                })
            
            for viz_file in viz_dir.glob('*.html'):
                visualizations.append({
                    'name': viz_file.stem,
                    'path': f'/static/visualizations/{analysis_id}/{viz_file.name}',
                    'type': 'interactive'
                })
        
        return visualizations
    
    def _perform_search(self, query, search_type):
        """Perform search across analysis results."""
        results = []
        query_lower = query.lower()
        
        for analysis_id, data in self.completed_analyses.items():
            match_found = False
            match_details = []
            
            if search_type in ['all', 'filename']:
                filename = data.get('sample_info', {}).get('filename', '')
                if query_lower in filename.lower():
                    match_found = True
                    match_details.append(f"Filename: {filename}")
            
            if search_type in ['all', 'hash']:
                hashes = ['md5', 'sha1', 'sha256']
                for hash_type in hashes:
                    hash_value = data.get('sample_info', {}).get(hash_type, '')
                    if query_lower in hash_value.lower():
                        match_found = True
                        match_details.append(f"{hash_type.upper()}: {hash_value}")
            
            if search_type in ['all', 'ioc']:
                iocs = data.get('iocs', {})
                for category, ioc_list in iocs.items():
                    if isinstance(ioc_list, list):
                        for ioc in ioc_list:
                            indicator = ioc.get('indicator', '') if isinstance(ioc, dict) else str(ioc)
                            if query_lower in indicator.lower():
                                match_found = True
                                match_details.append(f"IOC ({category}): {indicator}")
            
            if search_type in ['all', 'signature']:
                for module_name in ['behavioral_analysis', 'network_analysis', 'memory_analysis']:
                    module_data = data.get(module_name, {})
                    signatures = module_data.get('signatures', [])
                    for sig in signatures:
                        description = sig.get('description', '')
                        if query_lower in description.lower():
                            match_found = True
                            match_details.append(f"Signature: {description}")
            
            if match_found:
                results.append({
                    'analysis_id': analysis_id,
                    'filename': data.get('sample_info', {}).get('filename', 'Unknown'),
                    'timestamp': data.get('metadata', {}).get('generated_at', ''),
                    'score': self._get_overall_score(data),
                    'classification': self._get_classification(data),
                    'match_details': match_details[:5]  # Limit matches shown
                })
        
        return results
    
    def _start_background_analysis(self, analysis_config):
        """Start analysis in background thread."""
        def run_analysis():
            try:
                analysis_id = analysis_config['analysis_id']
                
                # Update status to running
                self.active_analyses[analysis_id] = {
                    'filename': analysis_config['filename'],
                    'progress': 0,
                    'current_phase': 'Initializing',
                    'started': datetime.utcnow().isoformat()
                }
                
                # Remove from queue
                self.analysis_queue = [item for item in self.analysis_queue 
                                     if item['analysis_id'] != analysis_id]
                
                # Simulate analysis progress (replace with actual analysis integration)
                phases = [
                    ('Setting up VM', 10),
                    ('Starting malware execution', 20),
                    ('Behavioral analysis', 40),
                    ('Network analysis', 60),
                    ('Memory analysis', 80),
                    ('Generating report', 90),
                    ('Finalizing', 100)
                ]
                
                for phase_name, progress in phases:
                    self.active_analyses[analysis_id].update({
                        'current_phase': phase_name,
                        'progress': progress
                    })
                    
                    # Emit WebSocket update if available
                    if self.socketio:
                        self.socketio.emit('analysis_progress', {
                            'analysis_id': analysis_id,
                            'progress': progress,
                            'phase': phase_name
                        }, room=analysis_id)
                    
                    time.sleep(2)  # Simulate work
                
                # Create mock analysis results
                mock_results = self._create_mock_analysis_results(analysis_config)
                
                # Move to completed
                self.completed_analyses[analysis_id] = mock_results
                del self.active_analyses[analysis_id]
                
                # Emit completion notification
                if self.socketio:
                    self.socketio.emit('analysis_complete', {
                        'analysis_id': analysis_id,
                        'message': 'Analysis completed successfully'
                    }, room=analysis_id)
                
                logger.info(f"Analysis {analysis_id} completed successfully")
                
            except Exception as e:
                logger.error(f"Background analysis error for {analysis_id}: {e}")
                # Handle error state
                if analysis_id in self.active_analyses:
                    self.active_analyses[analysis_id].update({
                        'current_phase': 'Error',
                        'progress': 0,
                        'error': str(e)
                    })
        
        # Start analysis thread
        analysis_thread = threading.Thread(target=run_analysis, daemon=True)
        analysis_thread.start()
    
    def _create_mock_analysis_results(self, analysis_config):
        """Create mock analysis results for demonstration."""
        return {
            'sample_info': {
                'filename': analysis_config['filename'],
                'file_path': analysis_config['file_path'],
                'sha256': analysis_config['file_hash'],
                'size_bytes': Path(analysis_config['file_path']).stat().st_size,
                'analysis_start_time': analysis_config['submitted_at']
            },
            'metadata': {
                'analysis_id': analysis_config['analysis_id'],
                'generated_at': datetime.utcnow().isoformat() + 'Z',
                'shikra_version': '1.0.0',
                'submitted_by': analysis_config['submitted_by']
            },
            'executive_summary': {
                'threat_level': 'MEDIUM',
                'overall_score': 65,
                'risk_description': 'Moderate threat detected with suspicious behavioral patterns.',
                'key_capabilities': ['File System Modification', 'Network Communication'],
                'recommended_actions': ['Monitor affected systems', 'Update security signatures']
            },
            'threat_assessment': {
                'overall_score': 65,
                'module_scores': {
                    'behavioral': 70,
                    'network': 45,
                    'memory': 55
                }
            },
            'behavioral_analysis': {
                'score': 70,
                'classification': 'Suspicious',
                'signatures': [
                    {
                        'type': 'file_modification',
                        'severity': 'medium',
                        'description': 'Multiple file operations detected'
                    }
                ]
            },
            'network_analysis': {
                'score': 45,
                'classification': 'Low Risk',
                'signatures': [
                    {
                        'type': 'dns_query',
                        'severity': 'low',
                        'description': 'Standard DNS queries observed'
                    }
                ]
            },
            'memory_analysis': {
                'score': 55,
                'classification': 'Suspicious',
                'signatures': [
                    {
                        'type': 'process_injection',
                        'severity': 'medium',
                        'description': 'Potential process injection detected'
                    }
                ]
            },
            'iocs': {
                'file_hashes': [{'indicator': analysis_config['file_hash'], 'type': 'sha256'}],
                'file_paths': [{'indicator': analysis_config['filename'], 'context': 'sample'}],
                'network_indicators': [],
                'registry_keys': []
            },
            'mitre_attack': [
                {
                    'technique_id': 'T1055',
                    'technique_name': 'Process Injection',
                    'tactic': 'Defense Evasion',
                    'confidence': 'medium'
                }
            ],
            'timeline': [
                {
                    'timestamp': datetime.utcnow().isoformat(),
                    'event_type': 'File Creation',
                    'description': 'Sample file created',
                    'severity': 'info'
                }
            ]
        }
    
    def _estimate_queue_time(self, queue_position):
        """Estimate time until analysis starts based on queue position."""
        avg_analysis_time = 600  # 10 minutes average
        estimated_seconds = queue_position * avg_analysis_time
        estimated_time = datetime.utcnow() + timedelta(seconds=estimated_seconds)
        return estimated_time.isoformat()
    
    def _export_iocs_csv(self, analysis_data, csv_path):
        """Export IOCs to CSV format."""
        import csv
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Type', 'Indicator', 'Context', 'Source'])
            
            iocs = analysis_data.get('iocs', {})
            for category, ioc_list in iocs.items():
                if isinstance(ioc_list, list):
                    for ioc in ioc_list:
                        if isinstance(ioc, dict):
                            writer.writerow([
                                category,
                                ioc.get('indicator', ''),
                                ioc.get('context', ''),
                                ioc.get('source', '')
                            ])
                        else:
                            writer.writerow([category, str(ioc), '', ''])
    
    def _get_disk_usage(self):
        """Get disk usage statistics."""
        import shutil
        try:
            total, used, free = shutil.disk_usage(self.data_directory)
            return {
                'total': total,
                'used': used,
                'free': free,
                'percent': (used / total) * 100
            }
        except:
            return {'percent': 0}
    
    def _get_memory_usage(self):
        """Get memory usage statistics."""
        try:
            import psutil
            memory = psutil.virtual_memory()
            return {
                'total': memory.total,
                'available': memory.available,
                'percent': memory.percent
            }
        except:
            return {'percent': 0}
    
    def _get_uptime(self):
        """Get system uptime."""
        try:
            import psutil
            boot_time = psutil.boot_time()
            uptime_seconds = time.time() - boot_time
            return str(timedelta(seconds=int(uptime_seconds)))
        except:
            return 'Unknown'
    
    def _get_active_users(self):
        """Get list of active users."""
        # In a real implementation, this would track user sessions
        return [
            {'username': 'admin', 'last_seen': '2 minutes ago'},
            {'username': 'analyst', 'last_seen': '15 minutes ago'}
        ]

# Flask application factory
def create_shikra_app(config_path: Optional[Path] = None) -> Flask:
    """
    Flask application factory for creating Shikra web interface.
    """
    try:
        # Initialize the web app
        web_app = ShikraWebApp(config_file=config_path)
        
        # Add custom template functions
        @web_app.app.template_global()
        def get_threat_color(threat_level):
            colors = {
                'CRITICAL': 'danger',
                'HIGH': 'warning',
                'MEDIUM': 'info',
                'LOW': 'success',
                'MINIMAL': 'secondary'
            }
            return colors.get(threat_level, 'secondary')
        
        @web_app.app.template_global()
        def get_score_color(score):
            if score >= 80:
                return 'danger'
            elif score >= 60:
                return 'warning'
            elif score >= 40:
                return 'info'
            else:
                return 'success'
        
        logger.info("Shikra Flask application created successfully")
        return web_app.app
        
    except Exception as e:
        logger.error(f"Error creating Shikra Flask application: {e}")
        raise

# Application entry point
if __name__ == '__main__':
    # Development server startup
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        app = create_shikra_app()
        logger.info("Starting Shikra web application in development mode")
        app.run(debug=True, host='0.0.0.0', port=5000)
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise