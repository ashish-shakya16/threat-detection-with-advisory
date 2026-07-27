"""
Main Entry Point for Cybersecurity Threat Advisor

This is the orchestrator that brings all modules together:
- Initializes configuration and logging
- Sets up monitoring, detection, risk assessment, and advisory modules
- Runs the main monitoring loop
- Handles database logging
- Provides CLI interface

This is where the magic happens - all components work together!
"""

import sys
import time
import logging
import argparse
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src.utils import Config, Logger, load_rules, ensure_directory
from src.logging_config import setup_logging
from src.database import DatabaseManager
from src.monitors import SystemMonitor, NetworkMonitor
from src.detection import RuleEngine
from src.risk_assessment import RiskScorer
from src.advisory import SecurityAdvisor


class ThreatAdvisor:
    """
    Main application class that orchestrates all components.
    
    Explanation:
    This class is the "brain" of the system:
    1. Initializes all modules with configuration
    2. Runs periodic scans (monitoring)
    3. Detects threats using rules
    4. Calculates risk scores
    5. Generates advisories
    6. Logs everything to database
    7. Displays alerts
    
    Architecture pattern: Pipeline/Chain
    Events flow through: Monitor → Detect → Risk → Advisory → Database
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """
        Initialize Threat Advisor system.
        
        Args:
            config_path: Path to configuration file
        """
        # Load configuration
        self.config = Config(config_path)

        # Setup logging
        self.logger = setup_logging(
            log_file=self.config.get('logging.log_file', 'data/logs/app.log'),
            level=self.config.get('logging.level', 'INFO')
        )
        self.logger.info("=" * 70)
        self.logger.info("Cybersecurity Threat Advisor Starting...")
        self.logger.info("=" * 70)
        
        # Load detection rules
        rules_data = load_rules(self.config.get('detection.rule_based.rules_file', 'config/rules.json'))
        
        # Initialize database
        db_path = self.config.get('database.path', 'data/db/threats.db')
        self.db = DatabaseManager(db_path)
        
        # Initialize monitors
        self.logger.info("Initializing monitoring modules...")
        self.system_monitor = SystemMonitor(self.config.config)
        self.network_monitor = NetworkMonitor(self.config.config)
        
        # Initialize detection engine
        self.logger.info("Initializing detection engine...")
        self.rule_engine = RuleEngine(rules_data)
        
        # Initialize risk assessment
        self.logger.info("Initializing risk assessment...")
        self.risk_scorer = RiskScorer(self.config.config)
        
        # Initialize advisory system
        self.logger.info("Initializing advisory system...")
        advisory_templates = rules_data.get('advisory_templates', {})
        self.advisor = SecurityAdvisor(advisory_templates, self.config.config)
        
        # Running state
        self.running = False
        self.scan_count = 0
        
        self.logger.info("[OK] All modules initialized successfully")
        self.logger.info("")
    
    def scan_once(self) -> dict:
        """
        Perform a single complete scan cycle.
        
        This is the core workflow:
        1. Monitor system and network
        2. Collect all events
        3. Detect threats using rules
        4. Calculate risk scores
        5. Generate advisories
        6. Log to database
        7. Return results
        
        Returns:
            Dictionary with scan results
        """
        self.scan_count += 1
        self.logger.info(f"--- Scan #{self.scan_count} ---")
        
        all_events = []
        all_threats = []
        
        # 1. System Monitoring
        if self.config.get('monitoring.system.enabled', True):
            self.logger.debug("Running system scan...")
            system_results = self.system_monitor.scan_system()
            
            # Collect events
            all_events.extend(system_results.get('suspicious_processes', []))
            all_events.extend(system_results.get('high_resource_usage', []))
        
        # 2. Network Monitoring
        if self.config.get('monitoring.network.enabled', True):
            self.logger.debug("Running network scan...")
            network_results = self.network_monitor.scan_network()
            
            # Collect events
            all_events.extend(network_results.get('suspicious_ports', []))
            all_events.extend(network_results.get('excessive_connections', []))
        
        self.logger.info(f"Collected {len(all_events)} events")
        
        # 3. Threat Detection
        if all_events:
            self.logger.debug("Running threat detection...")
            threats = self.rule_engine.check_events(all_events)
            self.logger.info(f"Detected {len(threats)} threats")
            
            # 4. Risk Assessment
            for threat in threats:
                threat = self.risk_scorer.calculate_risk(threat)
                all_threats.append(threat)
            
            # 5. Generate Advisories and Log
            for threat in all_threats:
                # Generate advisory
                advisory = self.advisor.generate_advisory(threat)
                
                # Log threat to database
                threat_id = self.db.log_threat(threat)
                
                # Log advisory to database
                self.db.log_advisory(threat_id, advisory)
                
                # Display alert
                self._display_alert(threat, advisory)
        
        # Log events to database
        for event in all_events:
            self.db.log_event(event)
        
        results = {
            'scan_number': self.scan_count,
            'events_collected': len(all_events),
            'threats_detected': len(all_threats),
            'threats': all_threats
        }
        
        self.logger.info(f"Scan complete: {len(all_threats)} threats detected\n")
        
        return results
    
    def _display_alert(self, threat: dict, advisory: dict):
        """
        Display threat alert and advisory.
        
        Args:
            threat: Threat dictionary
            advisory: Advisory dictionary
        """
        if not self.config.get('alerts.console.enabled', True):
            return
        
        # Only show high/medium risk in console (to avoid spam)
        risk_level = threat.get('risk_level', 'Unknown')
        if risk_level in ['High', 'Critical', 'Medium']:
            print("\n" + self.advisor.format_for_display(advisory))
    
    def run_continuous(self, interval: int = None):
        """
        Run continuous monitoring loop.
        
        Args:
            interval: Scan interval in seconds (from config if not specified)
        """
        if interval is None:
            interval = self.config.get('monitoring.system_check_interval', 5)
        
        self.logger.info(f"Starting continuous monitoring (interval: {interval}s)")
        self.logger.info("Press Ctrl+C to stop\n")
        
        self.running = True
        
        try:
            while self.running:
                self.scan_once()
                time.sleep(interval)
        
        except KeyboardInterrupt:
            self.logger.info("\n\nStopping monitoring...")
            self.running = False
    
    def list_recent_threats(self, hours: int = 24, limit: int = 50):
        """
        List recent threats from database.
        
        Args:
            hours: Time window in hours
            limit: Maximum threats to display
        """
        threats = self.db.get_recent_threats(limit=limit, hours=hours)
        
        print(f"\n{'=' * 70}")
        print(f"Recent Threats (last {hours} hours)")
        print(f"{'=' * 70}\n")
        
        if not threats:
            print("No threats detected in this time period.")
            return
        
        for i, threat in enumerate(threats, 1):
            print(f"{i}. [{threat['risk_level']}] {threat['threat_name']}")
            print(f"   Time: {threat['timestamp']}")
            print(f"   Category: {threat['category']}")
            print(f"   Risk Score: {threat['risk_score']:.2f}")
            print()
    
    def show_statistics(self, hours: int = 24):
        """
        Display threat statistics.
        
        Args:
            hours: Time window in hours
        """
        stats = self.db.get_threat_statistics(hours=hours)
        
        print(f"\n{'=' * 70}")
        print(f"Threat Statistics (last {hours} hours)")
        print(f"{'=' * 70}\n")
        
        print(f"Total Threats: {stats['total_threats']}")
        print(f"Active Critical Threats: {stats['active_critical']}\n")
        
        print("By Severity:")
        for severity, count in stats['by_severity'].items():
            print(f"  - {severity.capitalize()}: {count}")
        
        print("\nBy Category:")
        for category, count in stats['by_category'].items():
            print(f"  - {category}: {count}")
        
        print()


def main():
    """
    Main entry point with CLI argument parsing.
    """
    parser = argparse.ArgumentParser(
        description="Cybersecurity Threat Advisor - Intelligent threat detection and advisory system"
    )
    
    parser.add_argument(
        '--init',
        action='store_true',
        help='Initialize system (create directories and database)'
    )
    
    parser.add_argument(
        '--scan',
        action='store_true',
        help='Run a single scan and exit'
    )
    
    parser.add_argument(
        '--monitor',
        action='store_true',
        help='Run continuous monitoring (default mode)'
    )
    
    parser.add_argument(
        '--interval',
        type=int,
        default=5,
        help='Scan interval in seconds (default: 5)'
    )
    
    parser.add_argument(
        '--list-threats',
        action='store_true',
        help='List recent threats from database'
    )
    
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show threat statistics'
    )
    
    parser.add_argument(
        '--hours',
        type=int,
        default=24,
        help='Time window in hours for queries (default: 24)'
    )
    
    args = parser.parse_args()
    
    # Initialize directories
    if args.init:
        print("Initializing system...")
        ensure_directory('data/db')
        ensure_directory('data/logs')
        ensure_directory('config')
        print("✓ Directories created")
        print("✓ System initialized")
        return
    
    # Create advisor instance
    advisor = ThreatAdvisor()
    
    # Handle commands
    if args.list_threats:
        advisor.list_recent_threats(hours=args.hours)
    
    elif args.stats:
        advisor.show_statistics(hours=args.hours)
    
    elif args.scan:
        advisor.scan_once()
    
    else:
        # Default: continuous monitoring
        advisor.run_continuous(interval=args.interval)


if __name__ == "__main__":
    main()
