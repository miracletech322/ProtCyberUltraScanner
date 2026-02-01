# ============================================================================
# ADVANCED ML FALSE POSITIVE REDUCTION ENGINE
# ============================================================================
# Class: AdvancedFalsePositiveDetector
# Purpose: AI-powered false positive filtering with ensemble ML models,
#          adaptive learning, and explainable AI (XAI) capabilities
# ============================================================================

import os
import re
import json
import pickle
import hashlib
from datetime import datetime
from typing import Optional, List, Dict, Tuple, Union, Any
from dataclasses import dataclass, field
from enum import Enum
import numpy as np
import pandas as pd
from collections import defaultdict, Counter

# Optional ML imports with fallback handling
try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier, IsolationForest
    from sklearn.svm import SVC
    from xgboost import XGBClassifier
    from sklearn.preprocessing import StandardScaler, RobustScaler, LabelEncoder, OneHotEncoder
    from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV, StratifiedKFold
    from sklearn.metrics import (classification_report, accuracy_score, precision_recall_fscore_support, 
                                confusion_matrix, roc_auc_score, precision_recall_curve)
    from sklearn.feature_selection import SelectKBest, f_classif, RFE
    from sklearn.pipeline import Pipeline
    from sklearn.calibration import CalibratedClassifierCV
    from imblearn.over_sampling import SMOTE
    from imblearn.ensemble import BalancedRandomForestClassifier
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: ML libraries not available. Using rule-based fallback only.")

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

# Local imports
from logger import logger
from scan_result import ScanResult

class DetectionMethod(Enum):
    """Enum for detection methods used."""
    ENSEMBLE_ML = "ensemble_machine_learning"
    DEEP_LEARNING = "deep_learning"
    RULE_BASED = "rule_based"
    HYBRID = "hybrid"
    ANOMALY_DETECTION = "anomaly_detection"

class ModelType(Enum):
    """Enum for model types."""
    RANDOM_FOREST = "random_forest"
    XGBOOST = "xgboost"
    GRADIENT_BOOSTING = "gradient_boosting"
    SVM = "svm"
    VOTING_ENSEMBLE = "voting_ensemble"
    ISOLATION_FOREST = "isolation_forest"

@dataclass
class ModelMetadata:
    """Metadata for trained models."""
    model_id: str
    model_type: ModelType
    training_date: datetime
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    roc_auc: float
    feature_importance: Dict[str, float]
    training_samples: int
    class_distribution: Dict[str, int]
    hyperparameters: Dict[str, Any]
    version: str = "1.0.0"

@dataclass
class PredictionExplanation:
    """Detailed explanation for predictions."""
    prediction: str
    confidence: float
    contributing_factors: List[Tuple[str, float, str]]  # (feature_name, importance, reason)
    shap_values: Optional[List[float]] = None
    decision_path: Optional[List[str]] = None
    similar_cases: List[Dict] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

class AdvancedFalsePositiveDetector:
    """
    Advanced AI-powered false positive reduction engine with ensemble learning,
    adaptive capabilities, and explainable AI features.
    
    Features:
    1. Ensemble of multiple ML models for robust predictions
    2. Adaptive learning from manual corrections
    3. Explainable AI with SHAP values and feature importance
    4. Automated feature engineering
    5. Model versioning and A/B testing
    6. Real-time feedback loop
    7. Anomaly detection for novel attack patterns
    8. Confidence calibration
    9. Multi-dimensional scoring
    """
    
    def __init__(self, 
                 model_storage_path: str = "models/fp_detection/",
                 use_ensemble: bool = True,
                 enable_adaptive_learning: bool = True,
                 enable_xai: bool = True,
                 min_training_samples: int = 100,
                 confidence_threshold: float = 0.7):
        
        self.model_storage_path = model_storage_path
        self.use_ensemble = use_ensemble
        self.enable_adaptive_learning = enable_adaptive_learning
        self.enable_xai = enable_xai
        self.min_training_samples = min_training_samples
        self.confidence_threshold = confidence_threshold
        
        # Initialize components
        self.models: Dict[str, Any] = {}
        self.ensemble_weights: Dict[str, float] = {}
        self.scaler = None
        self.encoders: Dict[str, Any] = {}
        self.feature_selector = None
        
        # Feature engineering
        self.feature_pipeline = []
        self.feature_importance_history = []
        
        # Adaptive learning
        self.feedback_buffer = []
        self.adaptive_learning_rate = 0.1
        self.concept_drift_detector = ConceptDriftDetector()
        
        # Metadata
        self.model_metadata: Dict[str, ModelMetadata] = {}
        self.training_history = []
        self.prediction_stats = defaultdict(lambda: defaultdict(int))
        
        # Advanced features
        self.anomaly_detector = None
        self.confidence_calibrator = None
        self.feature_correlations = {}
        
        # Initialize
        self._setup_model_storage()
        self._initialize_models()
        if not hasattr(self, 'rule_engine'):
            self._initialize_rule_engine()
        
    def _setup_model_storage(self):
        """Setup model storage directory structure."""
        os.makedirs(self.model_storage_path, exist_ok=True)
        os.makedirs(f"{self.model_storage_path}/versions", exist_ok=True)
        os.makedirs(f"{self.model_storage_path}/feedback", exist_ok=True)
        os.makedirs(f"{self.model_storage_path}/explanations", exist_ok=True)
        
    def _initialize_models(self):
        """Initialize ML models with advanced configurations."""
        if not ML_AVAILABLE:
            logger.warning("ML libraries not available. Using rule-based engine only.")
            self._initialize_rule_engine()
            return
            
        try:
            # Base models
            self.models = {
                'rf': BalancedRandomForestClassifier(
                    n_estimators=200,
                    max_depth=15,
                    min_samples_split=5,
                    min_samples_leaf=2,
                    class_weight='balanced_subsample',
                    random_state=42,
                    n_jobs=-1
                ),
                'xgb': XGBClassifier(
                    n_estimators=150,
                    max_depth=8,
                    learning_rate=0.05,
                    subsample=0.8,
                    colsample_bytree=0.8,
                    use_label_encoder=False,
                    eval_metric='logloss',
                    random_state=42
                ),
                'gb': GradientBoostingClassifier(
                    n_estimators=150,
                    learning_rate=0.05,
                    max_depth=7,
                    min_samples_split=5,
                    min_samples_leaf=2,
                    random_state=42
                )
            }
            
            # Ensemble voting classifier
            if self.use_ensemble:
                estimators = [
                    ('rf', self.models['rf']),
                    ('xgb', self.models['xgb']),
                    ('gb', self.models['gb'])
                ]
                self.models['ensemble'] = VotingClassifier(
                    estimators=estimators,
                    voting='soft',
                    weights=[0.4, 0.3, 0.3]
                )
            
            # Anomaly detector for novel patterns
            self.anomaly_detector = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            )
            
            # Initialize scaler and encoders
            self.scaler = RobustScaler()  # More robust to outliers
            self.encoders = {
                'label': LabelEncoder(),
                'onehot': OneHotEncoder(sparse_output=False, handle_unknown='ignore')
            }
            
            # Feature selector
            self.feature_selector = SelectKBest(score_func=f_classif, k=15)
            
            logger.info("Advanced ML models initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")
            self._initialize_rule_engine()
    
    def _initialize_rule_engine(self):
        """Initialize advanced rule-based engine."""
        self.rule_engine = {
            'rules': [],
            'weights': {},
            'thresholds': {},
            'patterns': self._load_fp_patterns()
        }
        
        # Load rule configurations
        self._load_rule_configurations()

    def _load_rule_configurations(self):
        """Load rule configurations (placeholder)."""
        return
        
    def _load_fp_patterns(self) -> Dict:
        """Load false positive patterns from knowledge base."""
        return {
            'generic_errors': [
                r'error\s*:\s*\d+',
                r'exception',
                r'warning',
                r'stack trace',
                r'undefined',
                r'null pointer'
            ],
            'application_framework': [
                r'asp\.net',
                r'java\.',
                r'php',
                r'ruby on rails',
                r'django',
                r'flask'
            ],
            'security_controls': [
                r'waf',
                r'firewall',
                r'rate limit',
                r'captcha',
                r'honeypot'
            ],
            'benign_patterns': [
                r'page not found',
                r'access denied',
                r'invalid input',
                r'please login',
                r'session expired'
            ]
        }
    
    def extract_advanced_features(self, scan_result: ScanResult) -> Dict[str, float]:
        """
        Extract advanced features for ML model including engineered features.
        
        Features include:
        - Statistical features
        - Temporal patterns
        - Structural features
        - Semantic features
        - Contextual features
        """
        features = {}
        
        # Basic features
        features.update(self._extract_basic_features(scan_result))
        
        # Statistical features
        features.update(self._extract_statistical_features(scan_result))
        
        # Temporal features
        features.update(self._extract_temporal_features(scan_result))
        
        # Structural features
        features.update(self._extract_structural_features(scan_result))
        
        # Semantic features
        features.update(self._extract_semantic_features(scan_result))
        
        # Contextual features
        features.update(self._extract_contextual_features(scan_result))
        
        # Engineered features
        features.update(self._engineer_features(features))
        
        return features
    
    def _extract_basic_features(self, result: ScanResult) -> Dict[str, float]:
        """Extract basic features."""
        return {
            'response_code': float(result.response_code or 0),
            'response_time_ms': float(result.response_time * 1000 if result.response_time else 0),
            'payload_length': float(len(result.payload_used) if result.payload_used else 0),
            'response_size_bytes': float(result.response_size or 0),
            'confidence_score': float(result.confidence or 0.0),
            'has_error_message': 1.0 if result.error_message else 0.0,
            'has_evidence': 1.0 if result.evidence and len(result.evidence) > 10 else 0.0,
            'parameter_count': float(len(result.parameters_tested) if result.parameters_tested else 0),
        }
    
    def _extract_statistical_features(self, result: ScanResult) -> Dict[str, float]:
        """Extract statistical features."""
        evidence = result.evidence or ""
        
        return {
            'evidence_length': float(len(evidence)),
            'evidence_word_count': float(len(evidence.split())),
            'evidence_char_diversity': float(len(set(evidence)) / max(len(evidence), 1)),
            'numeric_ratio': float(sum(c.isdigit() for c in evidence) / max(len(evidence), 1)),
            'special_char_ratio': float(sum(not c.isalnum() for c in evidence) / max(len(evidence), 1)),
            'uppercase_ratio': float(sum(c.isupper() for c in evidence) / max(len(evidence), 1)),
        }
    
    def _extract_temporal_features(self, result: ScanResult) -> Dict[str, float]:
        """Extract temporal features."""
        current_hour = datetime.now().hour
        
        return {
            'scan_hour_sin': np.sin(2 * np.pi * current_hour / 24),
            'scan_hour_cos': np.cos(2 * np.pi * current_hour / 24),
            'is_business_hours': 1.0 if 9 <= current_hour <= 17 else 0.0,
            'is_night_hours': 1.0 if 0 <= current_hour <= 5 else 0.0,
        }
    
    def _extract_structural_features(self, result: ScanResult) -> Dict[str, float]:
        """Extract structural features."""
        url = result.url_tested or ""
        
        return {
            'url_depth': float(url.count('/') - 2),
            'url_length': float(len(url)),
            'query_param_count': float(url.count('?') + url.count('&')),
            'has_subdomain': 1.0 if len(url.split('//')[-1].split('.')[:-2]) > 0 else 0.0,
            'path_complexity': float(len(url.split('/'))),
            'file_extension_present': 1.0 if '.' in url.split('/')[-1] else 0.0,
        }
    
    def _extract_semantic_features(self, result: ScanResult) -> Dict[str, float]:
        """Extract semantic features."""
        evidence = (result.evidence or "").lower()
        
        semantic_scores = {
            'contains_sql_keywords': 0.0,
            'contains_xss_patterns': 0.0,
            'contains_command_injection': 0.0,
            'contains_path_traversal': 0.0,
            'contains_ssrf_patterns': 0.0,
        }
        
        # SQL Injection patterns
        sql_patterns = ['select', 'union', 'insert', 'update', 'delete', 'drop', 'table', 'from']
        if any(pattern in evidence for pattern in sql_patterns):
            semantic_scores['contains_sql_keywords'] = 1.0
        
        # XSS patterns
        xss_patterns = ['<script>', 'javascript:', 'onerror=', 'alert(']
        if any(pattern in evidence for pattern in xss_patterns):
            semantic_scores['contains_xss_patterns'] = 1.0
        
        return semantic_scores
    
    def _extract_contextual_features(self, result: ScanResult) -> Dict[str, float]:
        """Extract contextual features."""
        severity_map = {
            'Critical': 1.0, 'High': 0.8, 'Medium': 0.5, 
            'Low': 0.3, 'Informational': 0.1
        }
        
        return {
            'severity_score': severity_map.get(result.severity, 0.0),
            'vulnerability_type_score': self._encode_vuln_type(result.vulnerability_type),
            'target_risk_score': self._calculate_target_risk(result),
            'previous_fp_rate': self._get_historical_fp_rate(result),
        }

    def _calculate_target_risk(self, result: ScanResult) -> float:
        """Calculate a basic target risk score (placeholder)."""
        url = (result.url_tested or result.url or "").lower()
        score = 0.0
        if url.startswith("https://"):
            score += 0.5
        if "admin" in url or "login" in url:
            score += 0.5
        return min(score, 1.0)

    def _get_historical_fp_rate(self, result: ScanResult) -> float:
        """Return historical false positive rate (placeholder)."""
        return 0.0

    def _encode_vuln_type(self, vuln_type: str) -> float:
        """Encode vulnerability type into a numeric score."""
        if not vuln_type:
            return 0.0
        vuln = vuln_type.lower()
        if 'sql' in vuln:
            return 1.0
        if 'xss' in vuln:
            return 0.8
        if 'csrf' in vuln:
            return 0.6
        if 'auth' in vuln or 'session' in vuln:
            return 0.7
        if 'info' in vuln:
            return 0.2
        return 0.5
    
    def _engineer_features(self, base_features: Dict[str, float]) -> Dict[str, float]:
        """Create engineered features from base features."""
        engineered = {}
        
        # Interaction features
        if 'response_time_ms' in base_features and 'response_size_bytes' in base_features:
            engineered['response_efficiency'] = (
                base_features['response_size_bytes'] / max(base_features['response_time_ms'], 0.1)
            )
        
        # Ratio features
        if 'evidence_length' in base_features and 'response_size_bytes' in base_features:
            engineered['evidence_coverage'] = (
                base_features['evidence_length'] / max(base_features['response_size_bytes'], 1)
            )
        
        # Polynomial features
        for feature_name in ['confidence_score', 'severity_score']:
            if feature_name in base_features:
                engineered[f'{feature_name}_squared'] = base_features[feature_name] ** 2
                engineered[f'{feature_name}_cubed'] = base_features[feature_name] ** 3
        
        return engineered
    
    def predict_with_explanation(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Make prediction with detailed explanation.
        
        Returns:
            Dict containing prediction, confidence, and XAI explanation
        """
        # Extract features
        features = self.extract_advanced_features(scan_result)
        feature_vector = self._prepare_feature_vector(features)
        
        if not self._is_model_ready():
            # Fallback to advanced rule-based detection
            return self._advanced_rule_based_prediction(scan_result, features)
        
        try:
            # Get predictions from all models
            predictions = {}
            confidences = {}
            
            for model_name, model in self.models.items():
                if hasattr(model, 'predict_proba'):
                    proba = model.predict_proba(feature_vector.reshape(1, -1))[0]
                    prediction = model.predict(feature_vector.reshape(1, -1))[0]
                    
                    predictions[model_name] = prediction
                    confidences[model_name] = float(max(proba))
            
            # Ensemble prediction
            if self.use_ensemble and 'ensemble' in self.models:
                final_prediction = predictions.get('ensemble', False)
                final_confidence = confidences.get('ensemble', 0.5)
            else:
                # Weighted voting
                final_prediction = self._weighted_voting(predictions, confidences)
                final_confidence = np.mean(list(confidences.values()))
            
            # Check for anomalies
            is_anomaly = self._detect_anomaly(feature_vector)
            
            # Generate explanation
            explanation = self._generate_explanation(
                scan_result, 
                features, 
                final_prediction, 
                final_confidence,
                model_predictions=predictions,
                is_anomaly=is_anomaly
            )
            
            # Calibrate confidence
            calibrated_confidence = self._calibrate_confidence(
                final_confidence, 
                features, 
                is_anomaly
            )
            
            result = {
                'is_false_positive': bool(final_prediction == 'false_positive' or final_prediction == 1),
                'confidence': float(calibrated_confidence),
                'prediction_method': DetectionMethod.ENSEMBLE_ML.value if ML_AVAILABLE else DetectionMethod.RULE_BASED.value,
                'explanation': explanation,
                'features_used': list(features.keys()),
                'model_predictions': predictions,
                'is_anomaly': is_anomaly,
                'recommendation': self._generate_recommendation(
                    final_prediction, 
                    calibrated_confidence, 
                    is_anomaly
                ),
                'metadata': {
                    'model_version': self._get_current_model_version(),
                    'prediction_timestamp': datetime.now().isoformat(),
                    'feature_hash': self._hash_features(features),
                }
            }
            
            # Update statistics
            self._update_prediction_stats(result)
            
            # Store for adaptive learning
            if self.enable_adaptive_learning:
                self.feedback_buffer.append({
                    'scan_result': scan_result,
                    'prediction': result,
                    'timestamp': datetime.now()
                })
            
            return result
            
        except Exception as e:
            logger.error(f"Advanced prediction failed: {e}")
            return self._advanced_rule_based_prediction(scan_result, features)
    
    def _advanced_rule_based_prediction(self, scan_result: ScanResult, 
                                       features: Dict[str, float]) -> Dict[str, Any]:
        """Advanced rule-based prediction with scoring system."""
        rules_triggered = []
        rule_scores = []
        
        # Rule categories with weights
        rule_categories = {
            'confidence_rules': self._apply_confidence_rules(scan_result),
            'pattern_rules': self._apply_pattern_rules(scan_result),
            'structural_rules': self._apply_structural_rules(scan_result),
            'contextual_rules': self._apply_contextual_rules(scan_result),
            'statistical_rules': self._apply_statistical_rules(features),
        }
        
        for category, (rules, scores) in rule_categories.items():
            rules_triggered.extend(rules)
            rule_scores.extend(scores)
        
        # Calculate weighted score
        if rule_scores:
            # Apply weights based on rule reliability
            weights = self._get_rule_weights(rules_triggered)
            weighted_scores = [score * weight for score, weight in zip(rule_scores, weights)]
            final_score = np.mean(weighted_scores)
        else:
            final_score = 0.5
        
        # Determine prediction
        is_false_positive = final_score > 0.6
        
        # Generate explanation
        explanation = self._generate_rule_explanation(rules_triggered, rule_scores, final_score)
        
        return {
            'is_false_positive': is_false_positive,
            'confidence': float(final_score),
            'prediction_method': DetectionMethod.RULE_BASED.value,
            'explanation': explanation,
            'rules_triggered': rules_triggered,
            'rule_scores': rule_scores,
            'final_score': float(final_score),
            'metadata': {
                'rule_engine_version': '2.0.0',
                'prediction_timestamp': datetime.now().isoformat(),
            }
        }

    def _generate_rule_explanation(self, rules_triggered: List[str],
                                   rule_scores: List[float],
                                   final_score: float) -> PredictionExplanation:
        """Generate a basic rule-based explanation."""
        explanation = PredictionExplanation(
            prediction="false_positive" if final_score >= self.confidence_threshold else "likely_true_positive",
            confidence=float(final_score),
            contributing_factors=[],
            recommendations=[]
        )
        for rule in rules_triggered:
            explanation.contributing_factors.append((f"Rule: {rule}", 0.2, "Rule-based signal"))
        return explanation
    
    def _apply_confidence_rules(self, scan_result: ScanResult) -> Tuple[List[str], List[float]]:
        """Apply confidence-based rules."""
        rules = []
        scores = []
        
        confidence = scan_result.confidence or 0.0
        
        if confidence < 0.2:
            rules.append('very_low_confidence')
            scores.append(0.9)
        elif confidence < 0.4:
            rules.append('low_confidence')
            scores.append(0.7)
        elif confidence > 0.8:
            rules.append('high_confidence')
            scores.append(0.3)  # Lower FP probability
        
        return rules, scores
    
    def _apply_pattern_rules(self, scan_result: ScanResult) -> Tuple[List[str], List[float]]:
        """Apply pattern-based rules."""
        rules = []
        scores = []
        
        evidence = (scan_result.evidence or "").lower()
        
        # Check for generic error patterns
        for pattern_name, patterns in self.rule_engine['patterns'].items():
            for pattern in patterns:
                if re.search(pattern, evidence, re.IGNORECASE):
                    rules.append(f'pattern_{pattern_name}')
                    scores.append(0.6 if pattern_name == 'benign_patterns' else 0.8)
                    break
        
        return rules, scores
    
    def _apply_structural_rules(self, scan_result: ScanResult) -> Tuple[List[str], List[float]]:
        """Apply structural rules."""
        rules = []
        scores = []
        
        # Response time analysis
        if scan_result.response_time and scan_result.response_time < 0.005:
            rules.append('suspiciously_fast_response')
            scores.append(0.7)
        
        # Response size analysis
        if scan_result.response_size and scan_result.response_size < 50:
            rules.append('very_small_response')
            scores.append(0.6)
        
        # Status code analysis
        if scan_result.response_code in [403, 404, 500, 503]:
            rules.append(f'status_code_{scan_result.response_code}')
            scores.append(0.5)
        
        return rules, scores

    def _apply_contextual_rules(self, scan_result: ScanResult) -> Tuple[List[str], List[float]]:
        """Apply contextual rules (placeholder)."""
        rules = []
        scores = []
        
        url = (scan_result.url_tested or scan_result.url or "").lower()
        if "login" in url or "auth" in url:
            rules.append("auth_context")
            scores.append(0.4)
        
        return rules, scores

    def _apply_statistical_rules(self, features: Dict[str, float]) -> Tuple[List[str], List[float]]:
        """Apply statistical rules based on feature thresholds (placeholder)."""
        rules = []
        scores = []
        
        if features.get('confidence_score', 0.0) < 0.3:
            rules.append("low_confidence_feature")
            scores.append(0.6)
        
        return rules, scores
    
    def _generate_explanation(self, scan_result: ScanResult, features: Dict[str, float],
                            prediction: str, confidence: float, **kwargs) -> PredictionExplanation:
        """Generate detailed explanation for prediction."""
        explanation = PredictionExplanation(
            prediction=prediction,
            confidence=confidence,
            contributing_factors=[],
            recommendations=[]
        )
        
        # Add feature contributions
        if self.enable_xai and SHAP_AVAILABLE and self.models:
            try:
                # Generate SHAP values
                shap_values = self._calculate_shap_values(features)
                explanation.shap_values = shap_values
                
                # Get top contributing features
                top_features = self._get_top_contributing_features(features, shap_values)
                explanation.contributing_factors.extend(top_features)
                
            except Exception as e:
                logger.warning(f"SHAP explanation failed: {e}")
        
        # Add rule-based factors if available
        if 'rules_triggered' in kwargs.get('model_predictions', {}):
            rules = kwargs['model_predictions']['rules_triggered']
            for rule in rules:
                explanation.contributing_factors.append(
                    (f"Rule: {rule}", 0.3, "Rule-based heuristic")
                )
        
        # Add anomaly detection results
        if kwargs.get('is_anomaly', False):
            explanation.contributing_factors.append(
                ("Novel pattern detected", 0.4, "Anomaly detection flagged unusual characteristics")
            )
            explanation.recommendations.append(
                "Manual review recommended due to novel attack pattern"
            )
        
        # Add contextual recommendations
        if confidence < self.confidence_threshold:
            explanation.recommendations.append(
                f"Low confidence prediction ({confidence:.1%}). Consider manual verification."
            )
        
        # Find similar historical cases
        similar_cases = self._find_similar_cases(scan_result, features)
        explanation.similar_cases = similar_cases[:3]  # Top 3 similar cases
        
        return explanation
    
    def train_advanced_model(self, training_data: List[Dict], 
                           validation_data: Optional[List[Dict]] = None,
                           perform_hyperparameter_tuning: bool = True) -> ModelMetadata:
        """
        Train advanced ML model with comprehensive pipeline.
        
        Steps:
        1. Data preparation and augmentation
        2. Feature engineering and selection
        3. Hyperparameter tuning
        4. Model training with cross-validation
        5. Model evaluation and calibration
        6. Metadata generation
        """
        if not ML_AVAILABLE:
            raise RuntimeError("ML libraries not available for training")
        
        if len(training_data) < self.min_training_samples:
            raise ValueError(
                f"Insufficient training data: {len(training_data)} samples. "
                f"Minimum required: {self.min_training_samples}"
            )
        
        try:
            # Prepare data
            X, y, feature_names = self._prepare_training_data(training_data)
            
            # Handle class imbalance
            X_resampled, y_resampled = self._handle_imbalance(X, y)
            
            # Feature selection
            X_selected, selected_features = self._select_features(X_resampled, y_resampled)
            
            # Hyperparameter tuning
            if perform_hyperparameter_tuning:
                self._perform_hyperparameter_tuning(X_selected, y_resampled)
            
            # Train models
            model_performances = {}
            for model_name, model in self.models.items():
                if model_name != 'ensemble':  # Ensemble trained separately
                    performance = self._train_single_model(
                        model, model_name, X_selected, y_resampled, selected_features
                    )
                    model_performances[model_name] = performance
            
            # Train ensemble
            if self.use_ensemble:
                ensemble_performance = self._train_ensemble(
                    X_selected, y_resampled, selected_features
                )
                model_performances['ensemble'] = ensemble_performance
            
            # Train anomaly detector
            self._train_anomaly_detector(X_selected)
            
            # Generate model metadata
            model_id = self._generate_model_id()
            metadata = self._create_model_metadata(
                model_id, model_performances, X_selected, y_resampled, selected_features
            )
            
            # Save model
            self._save_model_version(metadata)
            
            # Update current model
            self.model_metadata[model_id] = metadata
            
            logger.info(f"Advanced model trained successfully. Model ID: {model_id}")
            return metadata
            
        except Exception as e:
            logger.error(f"Advanced model training failed: {e}")
            raise
    
    def adaptive_learn_from_feedback(self, feedback_data: List[Dict]):
        """
        Adaptive learning from manual corrections and feedback.
        
        Implements:
        - Online learning
        - Concept drift adaptation
        - Feedback-weighted learning
        - Incremental model updates
        """
        if not self.enable_adaptive_learning or not feedback_data:
            return
        
        try:
            # Process feedback buffer
            all_feedback = self.feedback_buffer + feedback_data
            
            if len(all_feedback) < 10:  # Minimum batch size for learning
                return
            
            # Extract features and labels from feedback
            X_feedback = []
            y_feedback = []
            feedback_weights = []
            
            for feedback in all_feedback:
                scan_result = feedback['scan_result']
                correction = feedback.get('correction')  # Manual correction
                
                if correction:
                    features = self.extract_advanced_features(scan_result)
                    X_feedback.append(list(features.values()))
                    y_feedback.append(correction)
                    
                    # Weight based on confidence and source
                    weight = self._calculate_feedback_weight(feedback)
                    feedback_weights.append(weight)
            
            if len(X_feedback) > 0:
                # Update models with feedback
                X_array = np.array(X_feedback)
                y_array = np.array(y_feedback)
                weights_array = np.array(feedback_weights)
                
                for model_name, model in self.models.items():
                    if hasattr(model, 'partial_fit'):
                        model.partial_fit(
                            X_array, y_array, 
                            classes=np.unique(y_array),
                            sample_weight=weights_array
                        )
                
                # Update ensemble weights based on feedback performance
                self._update_ensemble_weights(X_array, y_array, weights_array)
                
                # Detect concept drift
                drift_detected = self.concept_drift_detector.detect_drift(X_array, y_array)
                if drift_detected:
                    logger.warning("Concept drift detected. Consider retraining model.")
                
                # Clear feedback buffer
                self.feedback_buffer.clear()
                
                logger.info(f"Adaptive learning completed with {len(X_feedback)} samples")
        
        except Exception as e:
            logger.error(f"Adaptive learning failed: {e}")
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics."""
        metrics = {
            'model_health': self._check_model_health(),
            'prediction_statistics': dict(self.prediction_stats),
            'feature_importance': self._get_current_feature_importance(),
            'training_history': self.training_history[-10:],  # Last 10 training sessions
            'feedback_statistics': {
                'total_feedback': len(self.feedback_buffer),
                'feedback_quality': self._calculate_feedback_quality(),
            },
            'model_versions': list(self.model_metadata.keys()),
            'current_model': self._get_current_model_version(),
        }
        
        if self.models:
            for model_name, model in self.models.items():
                if hasattr(model, 'score'):
                    metrics[f'{model_name}_info'] = {
                        'type': type(model).__name__,
                        'n_features': getattr(model, 'n_features_in_', 'unknown'),
                        'classes': getattr(model, 'classes_', []).tolist() if hasattr(model, 'classes_') else [],
                    }
        
        return metrics
    
    def save_state(self, path: Optional[str] = None):
        """Save complete detector state."""
        save_path = path or f"{self.model_storage_path}/detector_state.pkl"
        
        state = {
            'models': self.models,
            'ensemble_weights': self.ensemble_weights,
            'scaler': self.scaler,
            'encoders': self.encoders,
            'feature_selector': self.feature_selector,
            'model_metadata': self.model_metadata,
            'training_history': self.training_history,
            'prediction_stats': dict(self.prediction_stats),
            'rule_engine': self.rule_engine,
            'config': {
                'use_ensemble': self.use_ensemble,
                'enable_adaptive_learning': self.enable_adaptive_learning,
                'enable_xai': self.enable_xai,
                'min_training_samples': self.min_training_samples,
                'confidence_threshold': self.confidence_threshold,
            }
        }
        
        try:
            with open(save_path, 'wb') as f:
                pickle.dump(state, f)
            logger.info(f"Detector state saved to {save_path}")
        except Exception as e:
            logger.error(f"Failed to save detector state: {e}")
    
    def load_state(self, path: str):
        """Load detector state from file."""
        try:
            with open(path, 'rb') as f:
                state = pickle.load(f)
            
            self.models = state.get('models', {})
            self.ensemble_weights = state.get('ensemble_weights', {})
            self.scaler = state.get('scaler')
            self.encoders = state.get('encoders', {})
            self.feature_selector = state.get('feature_selector')
            self.model_metadata = state.get('model_metadata', {})
            self.training_history = state.get('training_history', [])
            self.prediction_stats = defaultdict(lambda: defaultdict(int), 
                                              state.get('prediction_stats', {}))
            self.rule_engine = state.get('rule_engine', {})
            
            logger.info(f"Detector state loaded from {path}")
            
        except Exception as e:
            logger.error(f"Failed to load detector state: {e}")
            self._initialize_models()
    
    # Helper methods (partial implementations for brevity)
    def _prepare_feature_vector(self, features: Dict[str, float]) -> np.ndarray:
        """Prepare feature vector for model prediction."""
        # Sort features to ensure consistent order
        feature_names = sorted(features.keys())
        feature_vector = np.array([features[name] for name in feature_names])
        
        # Apply scaling if available and fitted
        if self.scaler:
            try:
                feature_vector = self.scaler.transform(feature_vector.reshape(1, -1)).flatten()
            except Exception:
                # If scaler isn't fitted yet, skip scaling for now
                pass
        
        return feature_vector
    
    def _is_model_ready(self) -> bool:
        """Check if ML model is ready for predictions."""
        return ML_AVAILABLE and self.models and any(
            hasattr(model, 'predict') for model in self.models.values()
        )
    
    def _weighted_voting(self, predictions: Dict[str, Any], confidences: Dict[str, float]) -> Any:
        """Perform weighted voting across models."""
        # Implement weighted voting logic
        vote_counts = defaultdict(float)
        
        for model_name, prediction in predictions.items():
            weight = confidences.get(model_name, 0.5)
            vote_counts[prediction] += weight
        
        # Return prediction with highest weighted vote
        return max(vote_counts.items(), key=lambda x: x[1])[0] if vote_counts else False
    
    def _detect_anomaly(self, feature_vector: np.ndarray) -> bool:
        """Detect if features represent an anomaly."""
        if self.anomaly_detector and hasattr(self.anomaly_detector, 'predict'):
            try:
                prediction = self.anomaly_detector.predict(feature_vector.reshape(1, -1))
                return prediction[0] == -1  # -1 indicates anomaly in IsolationForest
            except:
                pass
        return False
    
    def _calibrate_confidence(self, confidence: float, features: Dict[str, float], 
                            is_anomaly: bool) -> float:
        """Calibrate confidence score based on additional factors."""
        calibrated = confidence
        
        # Adjust for anomalies
        if is_anomaly:
            calibrated *= 0.7  # Reduce confidence for anomalies
        
        # Adjust based on feature quality
        feature_quality = self._assess_feature_quality(features)
        calibrated *= feature_quality
        
        # Ensure within bounds
        return max(0.0, min(1.0, calibrated))
    
    def _generate_recommendation(self, prediction: Any, confidence: float, 
                               is_anomaly: bool) -> str:
        """Generate recommendation based on prediction."""
        if is_anomaly:
            return "Manual review required: Novel attack pattern detected"
        
        if confidence < 0.3:
            return "High likelihood of false positive. Consider suppressing or manual review."
        elif confidence < 0.6:
            return "Moderate confidence. Recommend additional verification."
        else:
            if prediction in ['false_positive', 1]:
                return "Confident false positive. Can be safely suppressed."
            else:
                return "Likely true positive. Investigate further."
    
    def _calculate_shap_values(self, features: Dict[str, float]) -> List[float]:
        """Calculate SHAP values for feature importance."""
        # This is a simplified implementation
        # In production, would use actual SHAP library
        return [0.0] * len(features)
    
    def _get_top_contributing_features(self, features: Dict[str, float], 
                                      shap_values: List[float]) -> List[Tuple[str, float, str]]:
        """Get top contributing features for explanation."""
        if not shap_values or len(shap_values) != len(features):
            return []
        
        # Pair features with their SHAP values
        feature_contributions = list(zip(features.keys(), shap_values))
        
        # Sort by absolute contribution
        feature_contributions.sort(key=lambda x: abs(x[1]), reverse=True)
        
        # Return top 5 with explanations
        top_features = []
        for feature_name, contribution in feature_contributions[:5]:
            if contribution > 0:
                reason = "Supports false positive classification"
            else:
                reason = "Supports true positive classification"
            
            top_features.append((feature_name, abs(contribution), reason))
        
        return top_features
    
    def _find_similar_cases(self, scan_result: ScanResult, 
                           features: Dict[str, float]) -> List[Dict]:
        """Find historically similar cases."""
        # Simplified implementation
        return []
    
    def _update_prediction_stats(self, prediction_result: Dict[str, Any]):
        """Update prediction statistics."""
        key = 'fp' if prediction_result['is_false_positive'] else 'tp'
        confidence_level = 'high' if prediction_result['confidence'] > 0.7 else 'low'
        
        self.prediction_stats[key]['total'] += 1
        self.prediction_stats[key][confidence_level] += 1
        self.prediction_stats[key]['recent'] = datetime.now().isoformat()
    
    def _check_model_health(self) -> Dict[str, Any]:
        """Check health of ML models."""
        health = {
            'ml_available': ML_AVAILABLE,
            'models_initialized': len(self.models) > 0,
            'scaler_available': self.scaler is not None,
            'training_data_sufficiency': len(self.training_history) > 0,
            'last_training': self.training_history[-1]['timestamp'] if self.training_history else None,
            'prediction_volume': sum(stats['total'] for stats in self.prediction_stats.values()),
        }
        
        if self.models:
            health['active_models'] = list(self.models.keys())
            health['ensemble_active'] = self.use_ensemble and 'ensemble' in self.models
        
        return health
    
    def _get_current_model_version(self) -> str:
        """Get current model version."""
        if self.model_metadata:
            latest = max(self.model_metadata.values(), key=lambda m: m.training_date)
            return latest.version
        return "1.0.0"
    
    def _hash_features(self, features: Dict[str, float]) -> str:
        """Create hash of features for tracking."""
        feature_str = json.dumps(sorted(features.items()), sort_keys=True)
        return hashlib.md5(feature_str.encode()).hexdigest()[:8]

class ConceptDriftDetector:
    """Detect concept drift in data distribution."""
    
    def __init__(self, window_size: int = 100, drift_threshold: float = 0.05):
        self.window_size = window_size
        self.drift_threshold = drift_threshold
        self.data_buffer = []
        self.drift_scores = []
    
    def detect_drift(self, X: np.ndarray, y: np.ndarray) -> bool:
        """Detect concept drift in new data."""
        if len(self.data_buffer) < self.window_size:
            self.data_buffer.append((X, y))
            return False
        
        # Calculate drift score (simplified)
        drift_score = self._calculate_drift_score(X, y)
        self.drift_scores.append(drift_score)
        
        # Check if drift exceeds threshold
        if len(self.drift_scores) > 10:
            recent_drift = np.mean(self.drift_scores[-5:])
            if recent_drift > self.drift_threshold:
                return True
        
        return False
    
    def _calculate_drift_score(self, X_new: np.ndarray, y_new: np.ndarray) -> float:
        """Calculate drift score between new and historical data."""
        # Simplified implementation
        # In production, would use statistical tests like KS-test or PSI
        if not self.data_buffer:
            return 0.0
        
        # Compare with last window
        last_X, last_y = self.data_buffer[-1]
        
        if len(last_X) == 0 or len(X_new) == 0:
            return 0.0
        
        # Simple mean difference as proxy for drift
        if last_X.shape[1] == X_new.shape[1]:
            mean_diff = np.mean(np.abs(np.mean(last_X, axis=0) - np.mean(X_new, axis=0)))
            return float(mean_diff)
        
        return 0.0

# Export the main class
__all__ = ['AdvancedFalsePositiveDetector', 'DetectionMethod', 'ModelType', 
           'ModelMetadata', 'PredictionExplanation']