"""Main desktop application window for SecureX Threat Advisor"""

import sys
import os
import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

# PyQt6
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QPushButton, QLabel, QTableWidget, QTableWidgetItem, QComboBox,
    QSpinBox, QStatusBar, QProgressBar, QMessageBox, QDialog, QLineEdit,
    QFormLayout, QListWidget, QListWidgetItem, QHeaderView, QScrollArea,
    QFrame, QGridLayout
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QSize
from PyQt6.QtGui import QIcon, QFont, QColor, QBrush
from PyQt6.QtWidgets import QStyle
from PyQt6.QtCharts import QChart, QChartView, QLineSeries
from PyQt6.QtCore import QPointF

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.utils import Config, Logger, load_rules
from src.database.db_manager import DatabaseManager
from src.monitors.system_monitor import SystemMonitor
from src.monitors.network_monitor import NetworkMonitor
from src.detection.rule_engine import RuleEngine
from src.risk_assessment.risk_scorer import RiskScorer
from src.advisory.advisor import SecurityAdvisor
from src.ml_models.ml_integration import MLIntegration
from src.notifications.notification_manager import NotificationManager
from src.desktop.theme import Palette, STYLESHEET, severity_badge_style


class ScanWorker(QThread):
    """Background worker for threat scanning"""
    scan_complete = pyqtSignal(list)
    status_update = pyqtSignal(str)

    def __init__(self, config, rules_data):
        super().__init__()
        self.config = config
        self.rules_data = rules_data
        self.running = True

    def run(self):
        try:
            self.status_update.emit("Initializing monitors...")
            system_monitor = SystemMonitor(self.config)
            network_monitor = NetworkMonitor(self.config)
            rule_engine = RuleEngine(self.rules_data)
            risk_scorer = RiskScorer(self.config)
            advisor = SecurityAdvisor(self.rules_data['advisory_templates'], self.config)
            ml_integration = MLIntegration()

            self.status_update.emit("Collecting system events...")
            system_results = system_monitor.scan_system()
            network_results = network_monitor.scan_network()

            all_events = []
            all_events.extend(system_results.get('suspicious_processes', []))
            all_events.extend(system_results.get('high_resource_usage', []))
            all_events.extend(system_results.get('new_processes', []))
            all_events.extend(network_results.get('suspicious_ports', []))
            all_events.extend(network_results.get('excessive_connections', []))
            all_events.extend(network_results.get('unusual_destinations', []))

            threats = []
            self.status_update.emit(f"Analyzing {len(all_events)} events...")

            for event in all_events:
                threat = rule_engine.check_event(event)
                if threat:
                    threat_with_risk = risk_scorer.calculate_risk(threat)
                    ml_risk = ml_integration.calculate_ml_risk_score(threat)
                    threat_enriched = ml_integration.enrich_threat_with_ml_score(threat_with_risk, ml_risk)
                    advisory = advisor.generate_advisory(threat_enriched)
                    threat_enriched['advisory'] = advisory
                    threats.append(threat_enriched)

            self.status_update.emit(f"Scan complete: {len(threats)} threats detected")
            self.scan_complete.emit(threats)

        except Exception as e:
            self.status_update.emit(f"Scan error: {str(e)}")


class MainWindow(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureX Threat Advisor - Desktop")
        self.setGeometry(100, 100, 1400, 900)
        self.setMinimumSize(1100, 700)
        self.setWindowIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))

        # Initialize backend
        self.config = Config('config/config.yaml')
        self.logger = Logger.setup_logging(self.config)
        self.rules_data = load_rules(self.config.get('detection.rule_based.rules_file', 'config/rules.json'))
        self.db = DatabaseManager(self.config.get('database.path', 'data/db/threats.db'))
        self.ml_integration = MLIntegration()

        # Notification manager
        self.notification_manager = None
        notification_config = self.config.config.get('notifications', {})
        if notification_config.get('enabled', False):
            try:
                self.notification_manager = NotificationManager(notification_config)
            except Exception as e:
                self.logger.error(f"Failed to initialize notifications: {e}")

        # Scan worker
        self.scan_worker = None

        # UI Setup
        self.init_ui()

        # Timers
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_data)
        self.refresh_timer.start(5000)  # Refresh every 5 seconds

        self.logger.info("Desktop application started")

    def init_ui(self):
        """Initialize user interface"""
        self.setStyleSheet(STYLESHEET)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(16, 16, 16, 8)
        main_layout.setSpacing(12)

        style = self.style()

        # Top control bar
        control_layout = QHBoxLayout()
        control_layout.setSpacing(8)

        title_label = QLabel("SecureX Threat Advisor")
        title_font = QFont()
        title_font.setPointSize(13)
        title_font.setBold(True)
        title_label.setFont(title_font)

        self.scan_button = QPushButton(" Scan Now")
        self.scan_button.setObjectName("primaryButton")
        self.scan_button.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_BrowserReload))
        self.scan_button.setMinimumHeight(36)
        self.scan_button.clicked.connect(self.start_scan)

        self.train_ml_button = QPushButton(" Train ML Model")
        self.train_ml_button.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView))
        self.train_ml_button.setMinimumHeight(36)
        self.train_ml_button.clicked.connect(self.train_ml_model)

        self.clear_button = QPushButton(" Clear Old")
        self.clear_button.setObjectName("dangerButton")
        self.clear_button.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_TrashIcon))
        self.clear_button.setMinimumHeight(36)
        self.clear_button.clicked.connect(self.clear_old_threats)

        control_layout.addWidget(title_label)
        control_layout.addStretch()
        control_layout.addWidget(self.scan_button)
        control_layout.addWidget(self.train_ml_button)
        control_layout.addWidget(self.clear_button)

        main_layout.addLayout(control_layout)

        # Tabs
        tabs = QTabWidget()
        tabs.setDocumentMode(True)

        tabs.addTab(self.create_dashboard_tab(), "Dashboard")
        tabs.addTab(self.create_threats_tab(), "Threats")
        tabs.addTab(self.create_stats_tab(), "Statistics")
        tabs.addTab(self.create_ml_tab(), "ML Model")
        tabs.addTab(self.create_notifications_tab(), "Notifications")
        tabs.addTab(self.create_settings_tab(), "Settings")

        main_layout.addWidget(tabs)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setMaximumHeight(14)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)

        central_widget.setLayout(main_layout)

    @staticmethod
    def _section_header(text):
        """Create a consistently styled section header label."""
        label = QLabel(text)
        label.setProperty("role", "sectionHeader")
        return label

    def create_dashboard_tab(self):
        """Create dashboard tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # Threat summary
        layout.addWidget(self._section_header("Threat Summary"))
        summary_layout = QHBoxLayout()
        summary_layout.setSpacing(12)

        self.total_threats_label = self.create_stat_box("Total Threats", "0", QColor(Palette.ACCENT))
        self.critical_label = self.create_stat_box("Critical", "0", QColor(Palette.CRITICAL))
        self.high_label = self.create_stat_box("High", "0", QColor(Palette.HIGH))
        self.medium_label = self.create_stat_box("Medium", "0", QColor(Palette.MEDIUM))
        self.low_label = self.create_stat_box("Low", "0", QColor(Palette.LOW))

        summary_layout.addWidget(self.total_threats_label)
        summary_layout.addWidget(self.critical_label)
        summary_layout.addWidget(self.high_label)
        summary_layout.addWidget(self.medium_label)
        summary_layout.addWidget(self.low_label)

        layout.addLayout(summary_layout)

        # System metrics
        layout.addWidget(self._section_header("System Metrics"))
        metrics_layout = QHBoxLayout()
        metrics_layout.setSpacing(12)

        self.cpu_label = self.create_stat_box("CPU", "0%", QColor(Palette.LOW))
        self.memory_label = self.create_stat_box("Memory", "0%", QColor(Palette.ACCENT))
        self.disk_label = self.create_stat_box("Disk", "0%", QColor(Palette.MEDIUM))

        metrics_layout.addWidget(self.cpu_label)
        metrics_layout.addWidget(self.memory_label)
        metrics_layout.addWidget(self.disk_label)
        metrics_layout.addStretch()

        layout.addLayout(metrics_layout)

        # Recent threats table
        layout.addWidget(self._section_header("Recent Threats"))
        self.recent_threats_table = QTableWidget()
        self.recent_threats_table.setColumnCount(6)
        self.recent_threats_table.setHorizontalHeaderLabels([
            "Name", "Severity", "Risk Score", "Category", "Time", "Status"
        ])
        self.recent_threats_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.recent_threats_table.verticalHeader().setVisible(False)
        self.recent_threats_table.setAlternatingRowColors(True)
        self.recent_threats_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.recent_threats_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.recent_threats_table.verticalHeader().setDefaultSectionSize(30)
        layout.addWidget(self.recent_threats_table)

        widget.setLayout(layout)
        return widget

    def create_threats_tab(self):
        """Create threats list tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Filter bar
        filter_layout = QHBoxLayout()
        filter_layout.setSpacing(8)
        filter_layout.addWidget(QLabel("Severity:"))

        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "Critical", "High", "Medium", "Low"])
        self.severity_filter.currentTextChanged.connect(self.refresh_threats_table)
        filter_layout.addWidget(self.severity_filter)

        filter_layout.addWidget(QLabel("Window (hours):"))
        self.hours_spin = QSpinBox()
        self.hours_spin.setValue(24)
        self.hours_spin.setMaximum(168)
        self.hours_spin.valueChanged.connect(self.refresh_threats_table)
        filter_layout.addWidget(self.hours_spin)

        filter_layout.addStretch()
        caption = QLabel("Double-click a row for full advisory details")
        caption.setProperty("role", "caption")
        filter_layout.addWidget(caption)

        layout.addLayout(filter_layout)

        # Threats table
        self.threats_table = QTableWidget()
        self.threats_table.setColumnCount(7)
        self.threats_table.setHorizontalHeaderLabels([
            "ID", "Threat Name", "Severity", "Risk Score", "Category", "Time", "Advisory"
        ])
        self.threats_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.threats_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.threats_table.verticalHeader().setVisible(False)
        self.threats_table.setAlternatingRowColors(True)
        self.threats_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.threats_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.threats_table.verticalHeader().setDefaultSectionSize(30)
        self.threats_table.doubleClicked.connect(self.show_threat_details)

        layout.addWidget(self.threats_table)

        widget.setLayout(layout)
        return widget

    def create_stats_tab(self):
        """Create statistics tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # Stats grid
        layout.addWidget(self._section_header("Key Metrics"))
        stats_layout = QGridLayout()
        stats_layout.setSpacing(12)

        stats_grid = [
            ("Total Threats (24h)", "0"),
            ("Avg Risk Score", "0.00"),
            ("Highest Risk", "0.00"),
            ("Threats/Hour", "0"),
            ("Critical Incidents", "0"),
            ("Detection Rate", "0%"),
        ]

        self.stat_labels = {}
        for idx, (label, value) in enumerate(stats_grid):
            row = idx // 3
            col = idx % 3
            stat_widget = self.create_stat_box(label, value, QColor(Palette.ACCENT))
            stats_layout.addWidget(stat_widget, row, col)
            self.stat_labels[label] = stat_widget

        layout.addLayout(stats_layout)

        # Timeline
        layout.addWidget(self._section_header("Threat Timeline (24h)"))
        self.timeline_chart = QChartView()
        self.timeline_chart.setStyleSheet(
            f"background-color: {Palette.BG_SURFACE_ALT}; border: 1px solid {Palette.BORDER}; border-radius: 8px;"
        )
        layout.addWidget(self.timeline_chart)

        widget.setLayout(layout)
        return widget

    def create_ml_tab(self):
        """Create ML model tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # Model status
        layout.addWidget(self._section_header("Model Status"))
        status_layout = QHBoxLayout()
        status_layout.setSpacing(12)

        self.ml_trained_label = self.create_stat_box("Status", "Not Trained", QColor(Palette.MEDIUM))
        self.ml_samples_label = self.create_stat_box("Samples", "0", QColor(Palette.LOW))
        self.ml_accuracy_label = self.create_stat_box("Last Accuracy", "N/A", QColor(Palette.ACCENT))

        status_layout.addWidget(self.ml_trained_label)
        status_layout.addWidget(self.ml_samples_label)
        status_layout.addWidget(self.ml_accuracy_label)
        status_layout.addStretch()

        layout.addLayout(status_layout)

        # Model info
        info_group = QFrame()
        info_group.setObjectName("formGroup")
        info_layout = QFormLayout()
        info_layout.setContentsMargins(16, 14, 16, 14)
        info_layout.setSpacing(10)

        self.model_path_label = QLabel("Not loaded")
        self.model_features_label = QLabel("0")
        self.model_version_label = QLabel("1.2.0")

        info_layout.addRow("Model Path:", self.model_path_label)
        info_layout.addRow("Features Extracted:", self.model_features_label)
        info_layout.addRow("Model Version:", self.model_version_label)

        info_group.setLayout(info_layout)
        layout.addWidget(self._section_header("Model Information"))
        layout.addWidget(info_group)

        # Training info
        layout.addWidget(self._section_header("Recent Training"))
        self.training_info_list = QListWidget()
        layout.addWidget(self.training_info_list)

        # Controls
        control_layout = QHBoxLayout()
        control_layout.setSpacing(8)
        control_layout.addStretch()

        style = self.style()
        reload_button = QPushButton(" Reload Model")
        reload_button.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_BrowserReload))
        reload_button.clicked.connect(self.reload_ml_model)
        control_layout.addWidget(reload_button)

        retrain_button = QPushButton(" Retrain Model")
        retrain_button.setObjectName("primaryButton")
        retrain_button.setIcon(style.standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView))
        retrain_button.clicked.connect(self.train_ml_model)
        control_layout.addWidget(retrain_button)

        layout.addLayout(control_layout)
        layout.addStretch()

        widget.setLayout(layout)
        return widget

    def create_notifications_tab(self):
        """Create notifications tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # Notification status
        layout.addWidget(self._section_header("Notification Status"))
        status_layout = QHBoxLayout()
        status_layout.setSpacing(12)

        self.notif_enabled_label = self.create_stat_box("Status", "Disabled", QColor(Palette.TEXT_MUTED))
        self.notif_recipients_label = self.create_stat_box("Recipients", "0", QColor(Palette.ACCENT))

        status_layout.addWidget(self.notif_enabled_label)
        status_layout.addWidget(self.notif_recipients_label)
        status_layout.addStretch()

        layout.addLayout(status_layout)

        # Recipients list
        layout.addWidget(self._section_header("Email Recipients"))
        self.recipients_list = QListWidget()
        layout.addWidget(self.recipients_list)

        # Add recipient
        add_layout = QHBoxLayout()
        add_layout.setSpacing(8)
        self.recipient_input = QLineEdit()
        self.recipient_input.setPlaceholderText("Enter email address...")
        add_button = QPushButton(" Add")
        add_button.setObjectName("primaryButton")
        add_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogApplyButton))
        add_button.clicked.connect(self.add_recipient)
        add_layout.addWidget(self.recipient_input)
        add_layout.addWidget(add_button)
        layout.addLayout(add_layout)

        # Test notification
        layout.addWidget(self._section_header("Test"))
        test_layout = QHBoxLayout()
        test_button = QPushButton(" Send Test Notification")
        test_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxInformation))
        test_button.clicked.connect(self.send_test_notification)
        test_layout.addWidget(test_button)
        test_layout.addStretch()
        layout.addLayout(test_layout)

        layout.addStretch()

        widget.setLayout(layout)
        return widget

    def create_settings_tab(self):
        """Create settings tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # Application settings
        layout.addWidget(self._section_header("Application Settings"))

        settings_group = QFrame()
        settings_group.setObjectName("formGroup")
        settings_layout = QFormLayout()
        settings_layout.setContentsMargins(16, 14, 16, 14)
        settings_layout.setSpacing(10)

        auto_refresh_combo = QComboBox()
        auto_refresh_combo.addItems(["5 seconds", "10 seconds", "30 seconds", "1 minute"])
        settings_layout.addRow("Refresh Interval:", auto_refresh_combo)

        theme_combo = QComboBox()
        theme_combo.addItems(["Dark", "Light"])
        settings_layout.addRow("Theme:", theme_combo)

        alert_sound_combo = QComboBox()
        alert_sound_combo.addItems(["On", "Off"])
        settings_layout.addRow("Alert Sounds:", alert_sound_combo)

        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)

        # Database
        layout.addWidget(self._section_header("Database"))
        db_group = QFrame()
        db_group.setObjectName("formGroup")
        db_layout = QHBoxLayout()
        db_layout.setContentsMargins(16, 12, 16, 12)
        db_path_label = QLabel(self.config.get('database.path', 'data/db/threats.db'))
        db_path_label.setProperty("role", "caption")
        vacuum_button = QPushButton(" Optimize")
        vacuum_button.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_DriveHDIcon))
        vacuum_button.clicked.connect(self.optimize_database)
        db_layout.addWidget(db_path_label)
        db_layout.addStretch()
        db_layout.addWidget(vacuum_button)
        db_group.setLayout(db_layout)
        layout.addWidget(db_group)

        # About
        layout.addWidget(self._section_header("About"))
        about_group = QFrame()
        about_group.setObjectName("formGroup")
        about_layout = QFormLayout()
        about_layout.setContentsMargins(16, 14, 16, 14)
        about_layout.setSpacing(10)
        about_layout.addRow("Application:", QLabel("SecureX Threat Advisor"))
        about_layout.addRow("Version:", QLabel("v1.2.0"))
        about_layout.addRow("Status:", QLabel("Production Ready"))
        about_group.setLayout(about_layout)
        layout.addWidget(about_group)

        layout.addStretch()

        widget.setLayout(layout)
        return widget

    def create_stat_box(self, title, value, color):
        """Create a styled stat card with a colored accent bar, title and value."""
        box = QFrame()
        box.setObjectName("statCard")
        box.setMinimumHeight(84)
        box.setStyleSheet(box.styleSheet() + f"""
            QFrame#statCard {{
                border-top: 3px solid {color.name()};
            }}
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        title_label = QLabel(title.upper())
        title_label.setProperty("role", "statTitle")

        value_label = QLabel(value)
        value_label.setProperty("role", "statValue")
        value_label.setStyleSheet(f"color: {color.name()};")

        layout.addWidget(title_label)
        layout.addWidget(value_label)
        layout.addStretch()
        box.setLayout(layout)

        # Store reference for updates
        box.title_label = title_label
        box.value_label = value_label

        return box

    def start_scan(self):
        """Start a threat scan"""
        if self.scan_worker and self.scan_worker.isRunning():
            QMessageBox.warning(self, "Scan In Progress", "A scan is already running")
            return

        self.status_label.setText("Scanning...")
        self.progress_bar.setVisible(True)
        self.scan_button.setEnabled(False)

        self.scan_worker = ScanWorker(self.config.config, self.rules_data)
        self.scan_worker.scan_complete.connect(self.on_scan_complete)
        self.scan_worker.status_update.connect(self.status_label.setText)
        self.scan_worker.start()

    def on_scan_complete(self, threats):
        """Handle scan completion"""
        self.status_label.setText(f"Ready - {len(threats)} threats detected")
        self.progress_bar.setVisible(False)
        self.scan_button.setEnabled(True)

        if threats:
            critical_count = sum(1 for t in threats if t.get('severity', '').lower() == 'critical')
            high_count = sum(1 for t in threats if t.get('severity', '').lower() == 'high')
            QMessageBox.information(
                self,
                "Scan Complete",
                f"Found {len(threats)} threats\n\n" +
                f"Critical: {critical_count}\n" +
                f"High: {high_count}"
            )

        self.refresh_data()

    def refresh_data(self):
        """Refresh dashboard data"""
        try:
            stats = self.db.get_threat_statistics()

            # Update summary
            # Note: DatabaseManager stores severity lowercase ('low'/'medium'/'high'),
            # matching what RuleEngine/config/rules.json produce.
            total = stats.get('total_threats', 0)
            by_severity = stats.get('by_severity', {})

            self.total_threats_label.value_label.setText(str(total))
            self.critical_label.value_label.setText(str(by_severity.get('critical', 0)))
            self.high_label.value_label.setText(str(by_severity.get('high', 0)))
            self.medium_label.value_label.setText(str(by_severity.get('medium', 0)))
            self.low_label.value_label.setText(str(by_severity.get('low', 0)))

            # Update system metrics
            try:
                import os
                import psutil
                disk_path = os.path.abspath(os.sep)  # 'C:\\' on Windows, '/' on Unix
                self.cpu_label.value_label.setText(f"{psutil.cpu_percent()}%")
                self.memory_label.value_label.setText(f"{psutil.virtual_memory().percent}%")
                self.disk_label.value_label.setText(f"{psutil.disk_usage(disk_path).percent}%")
            except Exception as e:
                self.logger.debug(f"Failed to read system metrics: {e}")

            # Update recent threats
            self.refresh_recent_threats_table()

        except Exception as e:
            self.logger.error(f"Error refreshing data: {e}")

    def refresh_recent_threats_table(self):
        """Refresh recent threats table"""
        try:
            threats = self.db.get_recent_threats(limit=10, hours=24)
            self.recent_threats_table.setRowCount(len(threats))

            for row, threat in enumerate(threats):
                self.recent_threats_table.setItem(row, 0, QTableWidgetItem(threat.get('threat_name', '')))

                severity = str(threat.get('severity', ''))
                severity_item = QTableWidgetItem(severity.title())
                severity_item.setForeground(QBrush(Palette.severity_color(severity)))
                self.recent_threats_table.setItem(row, 1, severity_item)

                risk_score = threat.get('risk_score', 0)
                self.recent_threats_table.setItem(row, 2, QTableWidgetItem(f"{risk_score:.2f}"))
                self.recent_threats_table.setItem(row, 3, QTableWidgetItem(threat.get('category', '')))
                self.recent_threats_table.setItem(row, 4, QTableWidgetItem(str(threat.get('detected_at', ''))[:16]))
                self.recent_threats_table.setItem(row, 5, QTableWidgetItem("New"))

        except Exception as e:
            self.logger.error(f"Error refreshing threats table: {e}")

    def refresh_threats_table(self):
        """Refresh threats list table"""
        try:
            hours = self.hours_spin.value()
            threats = self.db.get_recent_threats(limit=100, hours=hours)

            severity_filter = self.severity_filter.currentText()
            if severity_filter != "All":
                threats = [t for t in threats if t.get('severity', '').lower() == severity_filter.lower()]

            self.threats_table.setRowCount(len(threats))

            for row, threat in enumerate(threats):
                self.threats_table.setItem(row, 0, QTableWidgetItem(str(threat.get('id', ''))))
                self.threats_table.setItem(row, 1, QTableWidgetItem(threat.get('threat_name', '')))

                severity = str(threat.get('severity', ''))
                severity_item = QTableWidgetItem(severity.title())
                severity_item.setForeground(QBrush(Palette.severity_color(severity)))
                self.threats_table.setItem(row, 2, severity_item)

                risk_score = threat.get('risk_score', 0)
                self.threats_table.setItem(row, 3, QTableWidgetItem(f"{risk_score:.2f}"))
                self.threats_table.setItem(row, 4, QTableWidgetItem(threat.get('category', '')))
                self.threats_table.setItem(row, 5, QTableWidgetItem(str(threat.get('detected_at', ''))[:16]))

                advisory_text = threat.get('advisory', {}).get('summary', '')[:50]
                self.threats_table.setItem(row, 6, QTableWidgetItem(advisory_text))

        except Exception as e:
            self.logger.error(f"Error refreshing threats: {e}")

    def show_threat_details(self, index):
        """Show threat details"""
        try:
            threat_id = int(self.threats_table.item(index.row(), 0).text())
            threat = self.db.get_threat_by_id(threat_id)

            if threat:
                details = f"""
Threat: {threat.get('threat_name', 'Unknown')}
Severity: {threat.get('severity', 'Unknown')}
Risk Score: {threat.get('risk_score', 0):.2f}
Category: {threat.get('category', 'Unknown')}
Time: {threat.get('detected_at', 'Unknown')}

Description: {threat.get('description', 'No description')}

Advisory: {threat.get('advisory', {}).get('summary', 'No advisory')}
"""
                QMessageBox.information(self, "Threat Details", details)
        except Exception as e:
            self.logger.error(f"Error showing threat details: {e}")

    def train_ml_model(self):
        """Train ML model"""
        try:
            self.status_label.setText("Training ML model...")
            self.progress_bar.setVisible(True)
            self.train_ml_button.setEnabled(False)

            # Get historical threats
            threats = self.db.get_recent_threats(limit=500, hours=720)

            if len(threats) < 50:
                QMessageBox.warning(
                    self,
                    "Insufficient Data",
                    f"Need 50+ threats for training, found {len(threats)}"
                )
                self.status_label.setText("Ready")
                self.progress_bar.setVisible(False)
                self.train_ml_button.setEnabled(True)
                return

            self.ml_integration.train_model(threats)

            stats = self.ml_integration.get_model_stats()
            self.ml_trained_label.value_label.setText("Trained")
            self.ml_samples_label.value_label.setText(str(len(threats)))

            QMessageBox.information(
                self,
                "Training Complete",
                f"ML model trained on {len(threats)} samples"
            )

            self.status_label.setText("Ready")
            self.progress_bar.setVisible(False)
            self.train_ml_button.setEnabled(True)

        except Exception as e:
            self.logger.error(f"ML training error: {e}")
            QMessageBox.critical(self, "Training Error", str(e))
            self.status_label.setText("Ready")
            self.progress_bar.setVisible(False)
            self.train_ml_button.setEnabled(True)

    def reload_ml_model(self):
        """Reload ML model"""
        try:
            stats = self.ml_integration.get_model_stats()
            self.ml_trained_label.value_label.setText("Ready" if stats['trained'] else "Not Trained")
            QMessageBox.information(self, "ML Model", f"Status: {stats['status']}")
        except Exception as e:
            self.logger.error(f"Error reloading model: {e}")

    def add_recipient(self):
        """Add notification recipient"""
        email = self.recipient_input.text().strip()
        if email:
            self.recipients_list.addItem(email)
            self.recipient_input.clear()

    def send_test_notification(self):
        """Send test notification"""
        if not self.notification_manager:
            QMessageBox.warning(self, "Not Configured", "Notifications not enabled")
            return

        try:
            test_threat = {
                'threat_name': 'Test Threat',
                'risk_level': 'Critical',
                'risk_score': 0.95,
                'category': 'Test',
                'description': 'This is a test notification',
                'severity': 'Critical',
                'timestamp': datetime.now().isoformat()
            }

            self.notification_manager.notify_threat(test_threat)
            QMessageBox.information(self, "Success", "Test notification sent")

        except Exception as e:
            self.logger.error(f"Error sending test: {e}")
            QMessageBox.critical(self, "Error", str(e))

    def clear_old_threats(self):
        """Clear threats older than 30 days"""
        reply = QMessageBox.question(
            self,
            "Clear Old Data",
            "Delete threats older than 30 days?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.db.cleanup_old_logs(days=30)
                QMessageBox.information(self, "Success", "Old threats cleared")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def closeEvent(self, event):
        """Clean up the refresh timer and any running scan thread before closing."""
        self.refresh_timer.stop()

        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.requestInterruption()
            self.scan_worker.wait(3000)  # Wait up to 3 seconds for graceful shutdown

        event.accept()

    def optimize_database(self):
        """Optimize database"""
        try:
            self.db.vacuum()
            QMessageBox.information(self, "Success", "Database optimized")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


def main():
    app_instance = app = None
    try:
        from PyQt6.QtWidgets import QApplication
        app = QApplication(sys.argv)
        app.setStyle("Fusion")
        app.setFont(QFont("Segoe UI", 9))

        window = MainWindow()
        window.show()

        sys.exit(app.exec())
    except ImportError:
        print("Error: PyQt6 not installed")
        print("Install with: pip install PyQt6 PyQt6-Charts")
        sys.exit(1)


if __name__ == '__main__':
    main()
