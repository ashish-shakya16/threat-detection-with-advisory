"""
Risk Assessment Module

This module calculates risk scores and classifies threats:
- Combines multiple factors (severity, confidence, impact)
- Calculates numerical risk score (0-1)
- Classifies into Low, Medium, High, Critical risk levels
- Adjusts for asset criticality, network exposure and context
- Provides reasoning for the risk score

Risk scoring is crucial for prioritization and response.
"""

import logging
from typing import Dict, Any, Optional

from src.risk_assessment.asset_context import CRITICALITY_MULTIPLIERS, EXPOSURE_MULTIPLIERS


class RiskScorer:
    """
    Calculates risk scores and classifies threat severity.
    
    Explanation:
    Risk score combines multiple factors:
    - Severity: How dangerous is the threat type?
    - Confidence: How sure are we this is a real threat?
    - Impact: What damage could this cause?
    - Prevalence: How common is this attack?
    
    Formula:
    risk_score = (severity_weight * severity_score +
                  confidence_weight * confidence_score +
                  impact_weight * impact_score +
                  prevalence_weight * prevalence_score)
    
    Why weighted scoring?
    - Not all factors are equally important
    - Allows tuning based on organization priorities
    - More flexible than simple averages
    
    Output:
    - Numerical score: 0.0 (no risk) to 1.0 (critical)
    - Risk level: Low, Medium, High
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize risk scorer with configuration.
        
        Args:
            config: Configuration dictionary with weights and thresholds
        """
        self.config = config
        self.logger = logging.getLogger('CyberAdvisor.RiskScorer')
        
        # Get weights from config
        risk_config = config.get('risk_assessment', {})
        weights = risk_config.get('weights', {})
        
        self.severity_weight = weights.get('severity', 0.4)
        self.confidence_weight = weights.get('confidence', 0.3)
        self.impact_weight = weights.get('impact', 0.2)
        self.prevalence_weight = weights.get('prevalence', 0.1)
        
        # Get thresholds
        thresholds = risk_config.get('thresholds', {})
        self.low_threshold = thresholds.get('low', 0.3)
        self.medium_threshold = thresholds.get('medium', 0.6)
        self.high_threshold = thresholds.get('high', 0.85)
        
        # Impact factors
        self.impact_factors = risk_config.get('impact_factors', {})
        
        self.logger.info("Risk Scorer initialized")
    
    def calculate_risk(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate risk score and level for a threat.
        
        Args:
            threat: Threat dictionary from detection engine
        
        Returns:
            Updated threat dictionary with risk_score and risk_level
        """
        # Get individual scores
        severity_score = self._severity_to_score(threat.get('severity', 'medium'))
        confidence_score = float(threat.get('confidence', 0.5))
        impact_score = self._impact_to_score(threat.get('impact', 'unknown'))
        prevalence_score = self._estimate_prevalence(threat)
        
        # Calculate weighted risk score
        risk_score = (
            self.severity_weight * severity_score +
            self.confidence_weight * confidence_score +
            self.impact_weight * impact_score +
            self.prevalence_weight * prevalence_score
        )
        
        # Ensure score is between 0 and 1
        risk_score = max(0.0, min(1.0, risk_score))
        
        # Classify risk level
        risk_level = self._classify_risk_level(risk_score)
        
        # Add to threat
        threat['risk_score'] = round(risk_score, 3)
        threat['risk_level'] = risk_level
        threat['risk_components'] = {
            'severity_score': round(severity_score, 3),
            'confidence_score': round(confidence_score, 3),
            'impact_score': round(impact_score, 3),
            'prevalence_score': round(prevalence_score, 3)
        }
        
        self.logger.info(
            f"Risk calculated for {threat.get('threat_name')}: "
            f"Score={risk_score:.3f}, Level={risk_level}"
        )
        
        return threat
    
    def _severity_to_score(self, severity: str) -> float:
        """
        Convert severity level to numerical score.
        
        Args:
            severity: Severity string (low, medium, high, critical)
        
        Returns:
            Numerical score 0-1
        """
        severity_map = {
            'low': 0.25,
            'medium': 0.5,
            'high': 0.85,
            'critical': 1.0
        }
        return severity_map.get(severity.lower(), 0.5)
    
    def _impact_to_score(self, impact: str) -> float:
        """
        Convert impact type to numerical score.
        
        Args:
            impact: Impact type (data_access, system_control, etc.)
        
        Returns:
            Numerical score 0-1
        """
        # Get impact factor from config, default to 3
        impact_value = self.impact_factors.get(impact, 3)
        
        # Normalize to 0-1 scale (assuming max impact value is 5)
        return min(impact_value / 5.0, 1.0)
    
    def _estimate_prevalence(self, threat: Dict[str, Any]) -> float:
        """
        Estimate how common/prevalent this threat type is.
        
        Explanation:
        Common threats are more likely to be real (higher prevalence score).
        Rare threats might be false positives or advanced attacks.
        
        Args:
            threat: Threat dictionary
        
        Returns:
            Prevalence score 0-1
        """
        category = threat.get('category', '').lower()
        
        # Prevalence estimates based on category
        prevalence_map = {
            'malware': 0.8,
            'brute force': 0.9,
            'network attack': 0.7,
            'resource abuse': 0.6,
            'file tampering': 0.5,
            'network scan': 0.7,
            'privilege escalation': 0.6,
            'script attack': 0.7,
            'data theft': 0.5,
            'code injection': 0.4
        }
        
        return prevalence_map.get(category, 0.5)
    
    def _classify_risk_level(self, risk_score: float) -> str:
        """
        Classify numerical risk score into level.
        
        Args:
            risk_score: Numerical risk score 0-1
        
        Returns:
            Risk level string (Low, Medium, High)
        """
        if risk_score < self.low_threshold:
            return 'Low'
        elif risk_score < self.medium_threshold:
            return 'Medium'
        elif risk_score < self.high_threshold:
            return 'High'
        else:
            return 'Critical'
    
    def get_risk_explanation(self, threat: Dict[str, Any]) -> str:
        """
        Generate human-readable explanation of risk score.
        
        Args:
            threat: Threat with calculated risk
        
        Returns:
            Explanation string
        """
        components = threat.get('risk_components', {})
        risk_score = threat.get('risk_score', 0)
        risk_level = threat.get('risk_level', 'Unknown')
        
        explanation = f"Risk Level: {risk_level} (Score: {risk_score:.2f})\n\n"
        explanation += "Risk Calculation:\n"
        explanation += f"- Severity: {components.get('severity_score', 0):.2f} "
        explanation += f"(weight: {self.severity_weight})\n"
        explanation += f"- Confidence: {components.get('confidence_score', 0):.2f} "
        explanation += f"(weight: {self.confidence_weight})\n"
        explanation += f"- Impact: {components.get('impact_score', 0):.2f} "
        explanation += f"(weight: {self.impact_weight})\n"
        explanation += f"- Prevalence: {components.get('prevalence_score', 0):.2f} "
        explanation += f"(weight: {self.prevalence_weight})\n"
        
        return explanation
    
    def adjust_risk_by_context(self, threat: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Adjust risk score based on contextual factors.
        
        Explanation:
        Context can increase or decrease risk:
        - Repeated offender process: increase risk
        - Known safe process: decrease risk
        - Time of day: off-hours activity more suspicious
        - User role: admin account compromise worse
        
        Args:
            threat: Threat with initial risk
            context: Contextual information
        
        Returns:
            Threat with adjusted risk
        """
        risk_score = threat.get('risk_score', 0.5)
        adjustments = []
        
        # Check for repeat offender
        if context.get('repeat_offender'):
            risk_score *= 1.2
            adjustments.append("Increased: Repeat offender")
        
        # Check time of day
        if context.get('off_hours'):
            risk_score *= 1.1
            adjustments.append("Increased: Off-hours activity")
        
        # Check user privileges
        if context.get('privileged_user'):
            risk_score *= 1.15
            adjustments.append("Increased: Privileged user account")

        # Asset criticality and network exposure (see asset_context.py)
        criticality = context.get('asset_criticality')
        if criticality in CRITICALITY_MULTIPLIERS and CRITICALITY_MULTIPLIERS[criticality] != 1.0:
            risk_score *= CRITICALITY_MULTIPLIERS[criticality]
            direction = 'Increased' if CRITICALITY_MULTIPLIERS[criticality] > 1 else 'Decreased'
            adjustments.append(f"{direction}: {criticality} asset criticality")
        exposure = context.get('exposure')
        if exposure in EXPOSURE_MULTIPLIERS and EXPOSURE_MULTIPLIERS[exposure] != 1.0:
            risk_score *= EXPOSURE_MULTIPLIERS[exposure]
            adjustments.append(f"Increased: {exposure} network exposure")

        # Ensure score stays within bounds
        risk_score = max(0.0, min(1.0, risk_score))
        
        # Update threat
        threat['risk_score'] = round(risk_score, 3)
        threat['risk_level'] = self._classify_risk_level(risk_score)
        threat['risk_adjustments'] = adjustments
        
        return threat


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    test_config = {
        'risk_assessment': {
            'weights': {
                'severity': 0.4,
                'confidence': 0.3,
                'impact': 0.2,
                'prevalence': 0.1
            },
            'thresholds': {
                'low': 0.3,
                'medium': 0.6,
                'high': 0.85
            },
            'impact_factors': {
                'data_access': 3,
                'system_control': 5,
                'network_access': 4,
                'privilege_escalation': 5
            }
        }
    }
    
    scorer = RiskScorer(test_config)
    
    # Test threat
    test_threat = {
        'threat_name': 'Suspicious Process',
        'category': 'Malware',
        'severity': 'high',
        'confidence': 0.9,
        'impact': 'system_control'
    }
    
    result = scorer.calculate_risk(test_threat)
    print(f"Threat: {result['threat_name']}")
    print(f"Risk Score: {result['risk_score']}")
    print(f"Risk Level: {result['risk_level']}")
    print("\n" + scorer.get_risk_explanation(result))
