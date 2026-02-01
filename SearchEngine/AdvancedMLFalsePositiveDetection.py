# ============================================================================
# ADVANCED ML-POWERED FALSE POSITIVE REDUCTION ENGINE
# ============================================================================
"""
ADVANCED FALSE POSITIVE DETECTOR WITH ENSEMBLE LEARNING & EXPLAINABLE AI

This class implements a sophisticated machine learning pipeline for reducing
false positives in vulnerability scanning results. It combines:
- Ensemble learning with multiple model architectures
- Advanced feature engineering for security context
- SHAP-based explainable AI for transparent predictions
- Automated model versioning and performance tracking
- Active learning with human feedback integration
- Cross-validation with stratified sampling for imbalanced data
"""

import os
import re
import json
import pickle
import hashlib
from logger import logger
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any, Union
import numpy as np
import pandas as pd
from dataclasses import dataclass, field, asdict

# Optional imports for ML capabilities
try:
    from sklearn.ensemble import (
        RandomForestClassifier, 
        GradientBoostingClassifier,
        VotingClassifier,
        StackingClassifier
    )
    from sklearn.preprocessing import (
        StandardScaler, 
        LabelEncoder, 
        OneHotEncoder,
        KBinsDiscretizer
    )
    from sklearn.model_selection import (
        train_test_split, 
        StratifiedKFold,
        GridSearchCV,
        cross_val_score
    )
    from sklearn.metrics import (
        classification_report, 
        accuracy_score, 
        precision_recall_fscore_support,
        roc_auc_score,
        confusion_matrix
    )
    from imblearn.over_sampling import SMOTE
    from imblearn.under_sampling import RandomUnderSampler
    from imblearn.pipeline import Pipeline as ImbPipeline
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logger.warning("Advanced ML libraries not available. Falling back to basic implementation.")

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    logger.warning("SHAP not available. Explainable AI features disabled.")

# ============================================================================
# DATA STRUCTURES
# ============================================================================

class DetectionMethod(Enum):
    """Enum for different detection methodologies."""
    ML_ENSEMBLE = "ml_ensemble"
    RULE_BASED = "rule_based"
    HYBRID = "hybrid"
    ACTIVE_LEARNING = "active_learning"


class ModelType(Enum):
    """Enum for different ML model types."""
    RANDOM_FOREST = "random_forest"
    GRADIENT_BOOSTING = "gradient_boosting"
    VOTING_CLASSIFIER = "voting_classifier"
    STACKING_CLASSIFIER = "stacking_classifier"
    NEURAL_NETWORK = "neural_network"


@dataclass
class FeatureImportance:
    """Data structure for feature importance tracking."""
    feature_name: str
    importance_score: float
    shap_value: Optional[float] = None
    correlation_with_target: Optional[float] = None
    stability_score: Optional[float] = None


@dataclass
class ModelMetadata:
    """Metadata for model versioning and tracking."""
    version: str
    created_at: datetime
    training_data_size: int
    performance_metrics: Dict[str, float]
    feature_set_version: str
    hyperparameters: Dict[str, Any]
    cross_val_scores: List[float]
    data_balance_info: Dict[str, int]


@dataclass
class PredictionExplanation:
    """Structured explanation for model predictions."""
    prediction: str
    confidence: float
    top_features: List[Tuple[str, float, str]]  # (feature, value, impact)
    shap_force_plot_data: Optional[Dict] = None
    rule_triggers: List[str] = field(default_factory=list)
    model_confidence_intervals: Optional[Tuple[float, float]] = None


# ============================================================================
# MAIN CLASS
# ============================================================================

class AdvancedFalsePositiveDetector:
    """
    Advanced AI-powered false positive detection engine with ensemble learning,
    explainable AI, and continuous learning capabilities.
    
    Features:
    - Multiple ML model architectures with ensemble voting
    - SHAP-based explainable AI for transparent decision-making
    - Automated hyperparameter tuning with cross-validation
    - Feature importance analysis and drift detection
    - Active learning with human feedback integration
    - Model versioning and performance tracking
    - Real-time prediction with confidence intervals
    - Automated data balancing for imbalanced datasets
    """
    
    def __init__(self, 
                 model_config: Optional[Dict] = None,
                 enable_shap: bool = True,
                 enable_active_learning: bool = True,
                 model_storage_path: str = "models/fp_detector/"):
        """
        Initialize the advanced false positive detector.
        
        Args:
            model_config: Configuration dictionary for model parameters
            enable_shap: Enable SHAP explainable AI features
            enable_active_learning: Enable active learning with feedback loop
            model_storage_path: Path for storing model artifacts
        """
        self.model_config = model_config or self._get_default_config()
        self.enable_shap = enable_shap and SHAP_AVAILABLE
        self.enable_active_learning = enable_active_learning
        self.model_storage_path = model_storage_path
        
        # Model components
        self.models: Dict[str, Any] = {}
        self.ensemble_model: Optional[Any] = None
        self.scaler = StandardScaler() if ML_AVAILABLE else None
        self.encoders: Dict[str, Any] = {}
        self.feature_processor = None
        
        # Feature engineering
        self.feature_weights = self._initialize_feature_weights()
        self.feature_importance_history: List[FeatureImportance] = []
        
        # Training data and metadata
        self.training_data: List[Dict] = []
        self.validation_data: List[Dict] = []
        self.human_feedback_data: List[Dict] = []
        self.model_metadata: Optional[ModelMetadata] = None
        
        # Performance tracking
        self.performance_history: List[Dict] = []
        self.confusion_matrices: List[np.ndarray] = []
        
        # SHAP explainer
        self.shap_explainer = None
        
        # Initialize models
        self._initialize_models()
        
        # Create storage directory
        os.makedirs(model_storage_path, exist_ok=True)
        
        logger.info(f"Advanced False Positive Detector initialized. SHAP: {self.enable_shap}, "
                   f"Active Learning: {self.enable_active_learning}")
    
    def _get_default_config(self) -> Dict:
        """Get default model configuration."""
        return {
            'ensemble_method': 'voting',
            'models': [
                {'type': 'random_forest', 'weight': 0.4},
                {'type': 'gradient_boosting', 'weight': 0.4},
                {'type': 'neural_network', 'weight': 0.2}
            ],
            'hyperparameter_tuning': True,
            'cross_validation_folds': 5,
            'data_balancing': 'smote',
            'feature_selection_threshold': 0.01,
            'confidence_threshold': 0.7,
            'retrain_interval': 100,  # Retrain after 100 new samples
            'active_learning_batch_size': 10
        }
    
    def _initialize_feature_weights(self) -> Dict[str, float]:
        """Initialize advanced feature weights with security context."""
        return {
            # Response characteristics
            'response_code': 0.08,
            'response_time': 0.12,
            'response_size': 0.06,
            'response_entropy': 0.05,
            
            # Payload characteristics
            'payload_length': 0.07,
            'payload_complexity': 0.08,
            'payload_entropy': 0.06,
            
            # Vulnerability context
            'vulnerability_type': 0.09,
            'parameter_type': 0.06,
            'parameter_location': 0.05,
            
            # Evidence quality
            'evidence_length': 0.04,
            'evidence_specificity': 0.08,
            'has_error_message': 0.07,
            'error_message_specificity': 0.05,
            
            # Confidence metrics
            'scanner_confidence': 0.15,
            'severity_score': 0.10,
            'historical_accuracy': 0.07,
            
            # Contextual features
            'url_complexity': 0.04,
            'parameter_count': 0.03,
            'session_dependent': 0.05,
            'authentication_required': 0.06
        }
    
    def _initialize_models(self):
        """Initialize ensemble of ML models."""
        if not ML_AVAILABLE:
            logger.warning("ML libraries not available. Using rule-based only.")
            self.models = {}
            return
        
        try:
            from sklearn.neural_network import MLPClassifier
            
            # Initialize individual models
            base_models = []
            
            # Random Forest with balanced class weights
            rf_model = RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                class_weight='balanced_subsample',
                random_state=42,
                n_jobs=-1
            )
            base_models.append(('random_forest', rf_model))
            
            # Gradient Boosting
            gb_model = GradientBoostingClassifier(
                n_estimators=150,
                learning_rate=0.1,
                max_depth=7,
                subsample=0.8,
                random_state=42
            )
            base_models.append(('gradient_boosting', gb_model))
            
            # Neural Network
            nn_model = MLPClassifier(
                hidden_layer_sizes=(100, 50),
                activation='relu',
                solver='adam',
                alpha=0.0001,
                batch_size='auto',
                learning_rate='adaptive',
                max_iter=500,
                random_state=42
            )
            base_models.append(('neural_network', nn_model))
            
            # Create ensemble model
            if self.model_config['ensemble_method'] == 'voting':
                self.ensemble_model = VotingClassifier(
                    estimators=base_models,
                    voting='soft',
                    weights=[m['weight'] for m in self.model_config['models']]
                )
            elif self.model_config['ensemble_method'] == 'stacking':
                self.ensemble_model = StackingClassifier(
                    estimators=base_models,
                    final_estimator=RandomForestClassifier(n_estimators=100),
                    cv=5,
                    n_jobs=-1
                )
            
            # Store individual models for explainability
            self.models = dict(base_models)
            
            logger.info(f"Initialized ensemble with {len(base_models)} models")
            
        except Exception as e:
            logger.error(f"Failed to initialize models: {e}")
            self.models = {}
    
    def _extract_advanced_features(self, scan_result: Any) -> Dict[str, float]:
        """
        Extract advanced features with security context awareness.
        
        Args:
            scan_result: Vulnerability scan result object
            
        Returns:
            Dictionary of feature names and values
        """
        features = {}
        
        # Basic response features
        features['response_code'] = scan_result.response_code or 0
        features['response_time'] = scan_result.response_time or 0.0
        features['response_size'] = scan_result.response_size or 0
        
        # Calculate response entropy (simple character distribution)
        if scan_result.response_body:
            response_text = str(scan_result.response_body)
            if len(response_text) > 0:
                prob = [response_text.count(c) / len(response_text) 
                       for c in set(response_text)]
                features['response_entropy'] = -sum(p * np.log2(p) for p in prob if p > 0)
        
        # Payload features
        features['payload_length'] = len(scan_result.payload_used) if scan_result.payload_used else 0
        features['payload_complexity'] = self._calculate_payload_complexity(scan_result.payload_used)
        features['payload_entropy'] = self._calculate_string_entropy(scan_result.payload_used)
        
        # Vulnerability context
        features['vulnerability_type'] = self._encode_vulnerability_type(
            scan_result.vulnerability_type
        )
        features['parameter_type'] = self._encode_parameter_type_advanced(
            scan_result.parameter_tested
        )
        features['parameter_location'] = self._encode_parameter_location(
            scan_result.url_tested, 
            scan_result.parameter_tested
        )
        
        # Evidence quality metrics
        features['evidence_length'] = len(scan_result.evidence) if scan_result.evidence else 0
        features['evidence_specificity'] = self._calculate_evidence_specificity(
            scan_result.evidence
        )
        features['has_error_message'] = 1.0 if scan_result.error_message else 0.0
        features['error_message_specificity'] = self._calculate_error_specificity(
            scan_result.error_message
        )
        
        # Confidence metrics
        features['scanner_confidence'] = scan_result.confidence or 0.0
        features['severity_score'] = self._encode_severity_score(scan_result.severity)
        features['historical_accuracy'] = self._get_historical_accuracy(
            scan_result.vulnerability_type
        )
        
        # Contextual features
        features['url_complexity'] = scan_result.url_tested.count('/') if scan_result.url_tested else 0
        features['parameter_count'] = self._count_parameters(scan_result.url_tested)
        features['session_dependent'] = 1.0 if self._is_session_dependent(scan_result) else 0.0
        features['authentication_required'] = 1.0 if self._requires_auth(scan_result) else 0.0
        
        # Apply feature weights
        for feature_name, value in features.items():
            if feature_name in self.feature_weights:
                features[feature_name] = value * self.feature_weights[feature_name]
        
        return features
    
    def _calculate_payload_complexity(self, payload: Optional[str]) -> float:
        """Calculate payload complexity score."""
        if not payload:
            return 0.0
        
        complexity_score = 0.0
        
        # Check for SQL injection patterns
        sql_patterns = ['SELECT', 'UNION', 'OR 1=1', 'DROP', 'INSERT']
        if any(pattern in payload.upper() for pattern in sql_patterns):
            complexity_score += 0.3
        
        # Check for XSS patterns
        xss_patterns = ['<script>', 'javascript:', 'onerror=', 'alert(']
        if any(pattern in payload.lower() for pattern in xss_patterns):
            complexity_score += 0.3
        
        # Check for encoding
        if any(enc in payload for enc in ['%3C', '%3E', '%27', '%22']):
            complexity_score += 0.2
        
        # Check length
        if len(payload) > 100:
            complexity_score += 0.2
        
        return min(complexity_score, 1.0)
    
    def _calculate_string_entropy(self, text: Optional[str]) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        
        if len(text) <= 1:
            return 0.0
        
        # Calculate probability of each character
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        
        # Calculate entropy
        entropy = -sum(p * np.log2(p) for p in prob if p > 0)
        
        # Normalize to 0-1 range
        max_entropy = np.log2(len(set(text)))
        return entropy / max_entropy if max_entropy > 0 else 0.0
    
    def _encode_vulnerability_type(self, vuln_type: Optional[str]) -> float:
        """Encode vulnerability type as numerical feature."""
        if not vuln_type:
            return 0.0
        
        vuln_type = vuln_type.lower()
        
        # Map vulnerability types to risk scores
        risk_scores = {
            'sql': 0.9, 'xss': 0.8, 'rce': 1.0, 'lfi': 0.7,
            'csrf': 0.5, 'idor': 0.6, 'xxe': 0.8, 'ssrf': 0.7,
            'sqli': 0.9, 'injection': 0.8, 'traversal': 0.7,
            'info': 0.3, 'config': 0.4
        }
        
        for key, score in risk_scores.items():
            if key in vuln_type:
                return score
        
        return 0.5  # Default medium risk
    
    def _encode_parameter_type_advanced(self, parameter: Optional[str]) -> float:
        """Advanced parameter type encoding with security context."""
        if not parameter:
            return 0.0
        
        param_lower = parameter.lower()
        
        # High risk parameters
        high_risk = ['id', 'cmd', 'exec', 'file', 'path', 'url', 'redirect']
        if any(term in param_lower for term in high_risk):
            return 0.9
        
        # Medium risk parameters
        medium_risk = ['user', 'pass', 'email', 'token', 'session', 'auth']
        if any(term in param_lower for term in medium_risk):
            return 0.6
        
        # Low risk parameters
        low_risk = ['page', 'sort', 'filter', 'search', 'query']
        if any(term in param_lower for term in low_risk):
            return 0.3
        
        return 0.1  # Unknown parameter
    
    def _encode_parameter_location(self, url: Optional[str], param: Optional[str]) -> float:
        """Encode parameter location in URL."""
        if not url or not param:
            return 0.0
        
        # Check if parameter is in query string
        if '?' in url and param in url.split('?')[-1]:
            return 0.3
        
        # Check if parameter is in path (RESTful)
        if f'/{param}/' in url or url.endswith(f'/{param}'):
            return 0.7
        
        # Check if parameter is in fragment
        if '#' in url and param in url.split('#')[-1]:
            return 0.1
        
        return 0.5  # Unknown location
    
    def _calculate_evidence_specificity(self, evidence: Optional[str]) -> float:
        """Calculate how specific the evidence is."""
        if not evidence or len(evidence) < 10:
            return 0.0
        
        specificity = 0.0
        
        # Check for specific patterns
        specific_patterns = [
            (r'error.*(sql|syntax|mysql|oracle|postgres)', 0.4),
            (r'(table|column|database).*not.*found', 0.3),
            (r'warning.*(failed|invalid|illegal)', 0.2),
            (r'undefined.*variable|function', 0.2),
            (r'stack.*trace|exception.*at', 0.3)
        ]
        
        for pattern, score in specific_patterns:
            if re.search(pattern, evidence, re.IGNORECASE):
                specificity += score
        
        # Check length (very long or very short might be less specific)
        if 50 <= len(evidence) <= 500:
            specificity += 0.2
        
        return min(specificity, 1.0)
    
    def _calculate_error_specificity(self, error: Optional[str]) -> float:
        """Calculate specificity of error message."""
        if not error:
            return 0.0
        
        # Generic error messages get low scores
        generic_errors = [
            'error', 'exception', 'warning', 'failed', 'invalid',
            'not found', 'internal server error'
        ]
        
        if any(gen_err in error.lower() for gen_err in generic_errors):
            return 0.2
        
        # Specific error messages get higher scores
        specific_indicators = [
            'sql', 'syntax', 'mysql', 'oracle', 'postgresql',
            'javascript', 'xml', 'json', 'parse'
        ]
        
        if any(indicator in error.lower() for indicator in specific_indicators):
            return 0.7
        
        return 0.4  # Medium specificity
    
    def _encode_severity_score(self, severity: Optional[str]) -> float:
        """Encode severity as numerical score."""
        severity_map = {
            'critical': 1.0,
            'high': 0.75,
            'medium': 0.5,
            'low': 0.25,
            'informational': 0.1,
            'none': 0.0
        }
        
        if severity:
            return severity_map.get(severity.lower(), 0.3)
        
        return 0.3  # Default medium
    
    def _get_historical_accuracy(self, vuln_type: Optional[str]) -> float:
        """Get historical accuracy for this vulnerability type."""
        if not vuln_type or not self.performance_history:
            return 0.5  # Default medium accuracy
        
        # Calculate accuracy for this vulnerability type from history
        relevant_history = [
            h for h in self.performance_history 
            if h.get('vulnerability_type') == vuln_type
        ]
        
        if not relevant_history:
            return 0.5
        
        accuracies = [h.get('accuracy', 0.5) for h in relevant_history]
        return float(np.mean(accuracies))
    
    def _count_parameters(self, url: Optional[str]) -> float:
        """Count number of parameters in URL."""
        if not url or '?' not in url:
            return 0.0
        
        query_string = url.split('?')[-1].split('#')[0]
        parameters = [p for p in query_string.split('&') if '=' in p]
        return min(len(parameters) / 10.0, 1.0)  # Normalize
    
    def _is_session_dependent(self, scan_result: Any) -> bool:
        """Check if finding is session-dependent."""
        # Check for session indicators in URL or parameters
        session_indicators = ['session', 'token', 'auth', 'jwt', 'cookie']
        
        url = scan_result.url_tested or ''
        param = scan_result.parameter_tested or ''
        
        combined = f"{url} {param}".lower()
        return any(indicator in combined for indicator in session_indicators)
    
    def _requires_auth(self, scan_result: Any) -> bool:
        """Check if target requires authentication."""
        # Simple heuristic based on URL patterns
        auth_patterns = [
            '/admin/', '/login/', '/account/', '/user/',
            '/dashboard/', '/profile/', '/settings/'
        ]
        
        url = scan_result.url_tested or ''
        return any(pattern in url.lower() for pattern in auth_patterns)
    
    def train_with_hyperparameter_tuning(self, 
                                       historical_results: List[Dict],
                                       test_size: float = 0.2,
                                       n_folds: int = 5) -> Dict[str, Any]:
        """
        Train model with hyperparameter tuning and cross-validation.
        
        Args:
            historical_results: Historical scan results with labels
            test_size: Proportion of data for testing
            n_folds: Number of cross-validation folds
            
        Returns:
            Dictionary with training results and metrics
        """
        if not historical_results or len(historical_results) < 100:
            logger.warning(f"Insufficient training data: {len(historical_results)} samples")
            return {'success': False, 'reason': 'insufficient_data'}
        
        try:
            # Prepare features and labels
            X, y, feature_names = self._prepare_training_data(historical_results)
            
            if len(X) < 50:
                return {'success': False, 'reason': 'insufficient_valid_samples'}
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=42, stratify=y
            )
            
            # Handle imbalanced data
            if self.model_config['data_balancing'] == 'smote':
                smote = SMOTE(random_state=42)
                X_train, y_train = smote.fit_resample(X_train, y_train)
            elif self.model_config['data_balancing'] == 'undersample':
                rus = RandomUnderSampler(random_state=42)
                X_train, y_train = rus.fit_resample(X_train, y_train)
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Hyperparameter tuning if enabled
            if self.model_config['hyperparameter_tuning']:
                best_model = self._perform_hyperparameter_tuning(
                    X_train_scaled, y_train, n_folds
                )
                self.ensemble_model = best_model
            else:
                # Train ensemble model
                self.ensemble_model.fit(X_train_scaled, y_train)
            
            # Evaluate model
            train_metrics = self._evaluate_model(
                self.ensemble_model, X_train_scaled, y_train, "train"
            )
            test_metrics = self._evaluate_model(
                self.ensemble_model, X_test_scaled, y_test, "test"
            )
            
            # Cross-validation scores
            cv_scores = cross_val_score(
                self.ensemble_model, X_train_scaled, y_train,
                cv=StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42),
                scoring='f1_weighted',
                n_jobs=-1
            )
            
            # Store training data
            self.training_data.extend(historical_results)
            
            # Create model metadata
            self.model_metadata = ModelMetadata(
                version=self._generate_model_version(),
                created_at=datetime.now(),
                training_data_size=len(X_train),
                performance_metrics=test_metrics,
                feature_set_version="1.2",
                hyperparameters=self.ensemble_model.get_params(),
                cross_val_scores=cv_scores.tolist(),
                data_balance_info={
                    'original_samples': len(y),
                    'train_samples': len(y_train),
                    'test_samples': len(y_test),
                    'class_distribution': dict(zip(*np.unique(y, return_counts=True)))
                }
            )
            
            # Initialize SHAP explainer
            if self.enable_shap:
                self._initialize_shap_explainer(X_train_scaled)
            
            # Save model
            self._save_model_with_version()
            
            # Calculate feature importances
            feature_importances = self._calculate_feature_importances(
                X_train_scaled, feature_names
            )
            self.feature_importance_history.extend(feature_importances)
            
            result = {
                'success': True,
                'model_version': self.model_metadata.version,
                'train_metrics': train_metrics,
                'test_metrics': test_metrics,
                'cross_val_mean': float(np.mean(cv_scores)),
                'cross_val_std': float(np.std(cv_scores)),
                'feature_importances': [
                    asdict(fi) for fi in feature_importances[:10]  # Top 10
                ],
                'training_samples': len(X_train),
                'testing_samples': len(X_test)
            }
            
            logger.info(f"Model trained successfully. Test F1: {test_metrics['f1_weighted']:.3f}")
            return result
            
        except Exception as e:
            logger.error(f"Model training failed: {e}")
            return {'success': False, 'reason': str(e)}
    
    def _prepare_training_data(self, historical_results: List[Dict]) -> Tuple:
        """Prepare features and labels for training."""
        X = []
        y = []
        
        for result in historical_results:
            # Extract features
            features = self._extract_advanced_features(result)
            if not features:
                continue
            
            X.append(list(features.values()))
            
            # Get label (assuming result has 'is_false_positive' field)
            if result.get('is_false_positive') is True:
                y.append(0)  # 0 for false positive
            else:
                y.append(1)  # 1 for true positive
        
        # Convert to numpy arrays
        X = np.array(X)
        y = np.array(y)
        
        # Get feature names
        feature_names = list(self._extract_advanced_features(
            historical_results[0] if historical_results else {}
        ).keys())
        
        return X, y, feature_names
    
    def _perform_hyperparameter_tuning(self, X, y, n_folds: int):
        """Perform hyperparameter tuning using grid search."""
        from sklearn.model_selection import GridSearchCV
        
        # Define parameter grid for ensemble
        param_grid = {
            'random_forest__n_estimators': [100, 200, 300],
            'random_forest__max_depth': [10, 15, 20, None],
            'gradient_boosting__n_estimators': [100, 150, 200],
            'gradient_boosting__learning_rate': [0.01, 0.1, 0.2],
            'neural_network__hidden_layer_sizes': [(50,), (100, 50), (100, 100)]
        }
        
        # Create pipeline for tuning
        from sklearn.pipeline import Pipeline
        
        pipeline = Pipeline([
            ('ensemble', self.ensemble_model)
        ])
        
        # Perform grid search
        grid_search = GridSearchCV(
            pipeline,
            param_grid,
            cv=StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42),
            scoring='f1_weighted',
            n_jobs=-1,
            verbose=1
        )
        
        grid_search.fit(X, y)
        
        logger.info(f"Best parameters: {grid_search.best_params_}")
        logger.info(f"Best CV score: {grid_search.best_score_:.3f}")
        
        return grid_search.best_estimator_
    
    def _evaluate_model(self, model, X, y, dataset_name: str) -> Dict[str, float]:
        """Comprehensive model evaluation."""
        y_pred = model.predict(X)
        y_pred_proba = model.predict_proba(X)[:, 1] if hasattr(model, 'predict_proba') else None
        
        # Calculate metrics
        precision, recall, f1, _ = precision_recall_fscore_support(
            y, y_pred, average='weighted'
        )
        accuracy = accuracy_score(y, y_pred)
        
        metrics = {
            f'{dataset_name}_accuracy': float(accuracy),
            f'{dataset_name}_precision': float(precision),
            f'{dataset_name}_recall': float(recall),
            f'{dataset_name}_f1_weighted': float(f1),
        }
        
        # ROC-AUC if probabilities available
        if y_pred_proba is not None:
            try:
                roc_auc = roc_auc_score(y, y_pred_proba)
                metrics[f'{dataset_name}_roc_auc'] = float(roc_auc)
            except:
                pass
        
        # Confusion matrix
        cm = confusion_matrix(y, y_pred)
        self.confusion_matrices.append(cm)
        
        # Store in performance history
        self.performance_history.append({
            'timestamp': datetime.now().isoformat(),
            'dataset': dataset_name,
            'metrics': metrics,
            'confusion_matrix': cm.tolist()
        })
        
        return metrics
    
    def _initialize_shap_explainer(self, X_train):
        """Initialize SHAP explainer for model interpretability."""
        if not self.enable_shap or not SHAP_AVAILABLE:
            return
        
        try:
            # Use TreeExplainer for tree-based models
            if hasattr(self.ensemble_model, 'estimators_'):
                self.shap_explainer = shap.TreeExplainer(
                    self.ensemble_model.estimators_[0]  # Use first estimator
                )
            else:
                self.shap_explainer = shap.KernelExplainer(
                    self.ensemble_model.predict_proba,
                    shap.sample(X_train, 100)  # Use sample for efficiency
                )
            
            logger.info("SHAP explainer initialized successfully")
        except Exception as e:
            logger.warning(f"Failed to initialize SHAP explainer: {e}")
            self.shap_explainer = None
    
    def _calculate_feature_importances(self, X_train, feature_names):
        """Calculate feature importances using multiple methods."""
        importances = []
        
        # Get model feature importances if available
        if hasattr(self.ensemble_model, 'feature_importances_'):
            model_importances = self.ensemble_model.feature_importances_
        elif hasattr(self.ensemble_model, 'estimators_'):
            # For ensemble, average importances across estimators
            model_importances = np.mean([
                est.feature_importances_ 
                for est in self.ensemble_model.estimators_ 
                if hasattr(est, 'feature_importances_')
            ], axis=0)
        else:
            model_importances = np.zeros(len(feature_names))
        
        # Calculate SHAP values if available
        shap_values = None
        if self.shap_explainer:
            try:
                shap_values = np.abs(self.shap_explainer.shap_values(X_train[:100])).mean(axis=0)
            except:
                shap_values = None
        
        # Create FeatureImportance objects
        for i, feature_name in enumerate(feature_names):
            importance = FeatureImportance(
                feature_name=feature_name,
                importance_score=float(model_importances[i]) if i < len(model_importances) else 0.0,
                shap_value=float(shap_values[i]) if shap_values is not None and i < len(shap_values) else None,
                correlation_with_target=None,  # Could be calculated separately
                stability_score=None  # Could be calculated across folds
            )
            importances.append(importance)
        
        # Sort by importance score
        importances.sort(key=lambda x: x.importance_score, reverse=True)
        
        return importances
    
    def predict_with_confidence(self, scan_result: Any) -> Dict[str, Any]:
        """
        Predict with confidence intervals and explanations.
        
        Args:
            scan_result: Vulnerability scan result
            
        Returns:
            Dictionary with prediction and detailed explanation
        """
        if not self.ensemble_model:
            return self._rule_based_prediction_advanced(scan_result)
        
        try:
            # Extract features
            features = self._extract_advanced_features(scan_result)
            if not features:
                return self._rule_based_prediction_advanced(scan_result)
            
            # Convert to array and scale
            X = np.array([list(features.values())])
            try:
                X_scaled = self.scaler.transform(X)
            except Exception:
                return self._rule_based_prediction_advanced(scan_result)
            
            # Get prediction and probabilities
            prediction = self.ensemble_model.predict(X_scaled)[0]
            probabilities = self.ensemble_model.predict_proba(X_scaled)[0]
            
            # Calculate confidence with calibration
            confidence = self._calculate_calibrated_confidence(
                probabilities, prediction, scan_result
            )
            
            # Get SHAP explanation if available
            shap_explanation = None
            if self.shap_explainer and self.enable_shap:
                shap_explanation = self._get_shap_explanation(X_scaled[0], features)
            
            # Get feature impacts
            feature_impacts = self._get_feature_impacts(features, X_scaled[0])
            
            # Determine if false positive
            is_false_positive = (prediction == 0)
            
            # Check confidence threshold
            if confidence < self.model_config['confidence_threshold']:
                # Low confidence - use hybrid approach
                rule_based = self._rule_based_prediction_advanced(scan_result)
                return self._combine_predictions(
                    ml_prediction={
                        'is_false_positive': is_false_positive,
                        'confidence': confidence
                    },
                    rule_prediction=rule_based,
                    features=features
                )
            
            # Build result
            result = {
                'is_false_positive': is_false_positive,
                'confidence': confidence,
                'prediction_method': 'ml_ensemble',
                'probability_distribution': {
                    'false_positive': float(probabilities[0]),
                    'true_positive': float(probabilities[1])
                },
                'features': features,
                'feature_impacts': feature_impacts,
                'model_version': self.model_metadata.version if self.model_metadata else 'unknown',
                'explanation': self._generate_explanation(
                    is_false_positive, confidence, feature_impacts, shap_explanation
                )
            }
            
            # Add SHAP data if available
            if shap_explanation:
                result['shap_explanation'] = shap_explanation
            
            return result
            
        except Exception as e:
            logger.error(f"ML prediction failed: {e}")
            return self._rule_based_prediction_advanced(scan_result)
    
    def _calculate_calibrated_confidence(self, probabilities, prediction, scan_result):
        """Calculate calibrated confidence score."""
        base_confidence = float(max(probabilities))
        
        # Adjust based on scanner confidence
        scanner_conf = scan_result.confidence or 0.5
        confidence_adjustment = scanner_conf * 0.3  # Scanner confidence contributes 30%
        
        # Adjust based on historical accuracy for this vulnerability type
        vuln_type = scan_result.vulnerability_type
        historical_acc = self._get_historical_accuracy(vuln_type)
        historical_adjustment = historical_acc * 0.2  # Historical accuracy contributes 20%
        
        # Base model confidence contributes 50%
        calibrated = (base_confidence * 0.5) + confidence_adjustment + historical_adjustment
        
        return min(max(calibrated, 0.0), 1.0)
    
    def _get_shap_explanation(self, X_scaled, features):
        """Get SHAP explanation for prediction."""
        if not self.shap_explainer:
            return None
        
        try:
            # Calculate SHAP values
            shap_values = self.shap_explainer.shap_values(X_scaled.reshape(1, -1))
            
            # For binary classification
            if isinstance(shap_values, list):
                shap_values = shap_values[1]  # Positive class
            
            # Get top contributing features
            feature_names = list(features.keys())
            shap_contributions = list(zip(feature_names, shap_values[0]))
            shap_contributions.sort(key=lambda x: abs(x[1]), reverse=True)
            
            return {
                'shap_values': shap_values.tolist(),
                'top_contributors': [
                    {'feature': feat, 'impact': float(val)}
                    for feat, val in shap_contributions[:5]
                ],
                'base_value': float(self.shap_explainer.expected_value[1] 
                                  if isinstance(self.shap_explainer.expected_value, list) 
                                  else self.shap_explainer.expected_value)
            }
        except Exception as e:
            logger.warning(f"SHAP explanation failed: {e}")
            return None
    
    def _get_feature_impacts(self, features, X_scaled):
        """Calculate impact of each feature on prediction."""
        impacts = []
        
        # Use model coefficients or feature importances
        if hasattr(self.ensemble_model, 'coef_'):
            # Linear model coefficients
            coefficients = self.ensemble_model.coef_[0]
            for i, (feat_name, feat_value) in enumerate(features.items()):
                if i < len(coefficients):
                    impact = coefficients[i] * feat_value
                    impacts.append({
                        'feature': feat_name,
                        'value': feat_value,
                        'impact': float(impact),
                        'weight': float(coefficients[i])
                    })
        
        elif hasattr(self.ensemble_model, 'feature_importances_'):
            # Tree-based feature importances
            importances = self.ensemble_model.feature_importances_
            feature_names = list(features.keys())
            
            for i, feat_name in enumerate(feature_names):
                if i < len(importances):
                    impacts.append({
                        'feature': feat_name,
                        'value': features[feat_name],
                        'impact': float(importances[i] * features[feat_name]),
                        'weight': float(importances[i])
                    })
        
        # Sort by absolute impact
        impacts.sort(key=lambda x: abs(x['impact']), reverse=True)
        return impacts[:10]  # Return top 10
    
    def _rule_based_prediction_advanced(self, scan_result: Any) -> Dict[str, Any]:
        """Advanced rule-based prediction with weighted rules."""
        rules = []
        rule_weights = []
        rule_details = []
        
        # Rule categories with different weights
        rule_categories = {
            'confidence_based': 0.3,
            'pattern_based': 0.25,
            'context_based': 0.25,
            'behavior_based': 0.2
        }
        
        # 1. Confidence-based rules
        if scan_result.confidence < 0.2:
            rules.append('very_low_confidence')
            rule_weights.append(0.9 * rule_categories['confidence_based'])
            rule_details.append(f"Confidence too low: {scan_result.confidence}")
        elif scan_result.confidence < 0.4:
            rules.append('low_confidence')
            rule_weights.append(0.7 * rule_categories['confidence_based'])
            rule_details.append(f"Low confidence: {scan_result.confidence}")
        
        # 2. Pattern-based rules
        fp_patterns = [
            # (pattern, weight, description)
            (r'(error|exception|warning).*(generic|general)', 0.8, 'Generic error message'),
            (r'response.*time.*<.*10ms', 0.7, 'Response too fast'),
            (r'identical.*response.*size', 0.6, 'Identical responses'),
            (r'default.*error.*page', 0.9, 'Default error page'),
            (r'cloudflare.*block', 0.8, 'WAF/Cloudflare block'),
            (r'rate.*limit.*exceeded', 0.7, 'Rate limiting'),
        ]
        
        evidence = (scan_result.evidence or '').lower()
        for pattern, weight, description in fp_patterns:
            if re.search(pattern, evidence):
                rules.append(f'pattern_{description.lower().replace(" ", "_")}')
                rule_weights.append(weight * rule_categories['pattern_based'])
                rule_details.append(f"Pattern matched: {description}")
        
        # 3. Context-based rules
        # Informational findings
        if scan_result.severity and 'informational' in scan_result.severity.lower():
            rules.append('informational_finding')
            rule_weights.append(-0.4)  # Negative weight - less likely to be FP
            rule_details.append("Informational severity - often real")
        
        # High severity with strong evidence
        if scan_result.severity and 'high' in scan_result.severity.lower():
            if scan_result.evidence and len(scan_result.evidence) > 100:
                rules.append('high_severity_strong_evidence')
                rule_weights.append(-0.6)
                rule_details.append("High severity with strong evidence")
        
        # 4. Behavior-based rules
        # Check response time anomaly
        if scan_result.response_time and scan_result.response_time < 0.001:
            rules.append('suspiciously_fast_response')
            rule_weights.append(0.8 * rule_categories['behavior_based'])
            rule_details.append(f"Suspiciously fast response: {scan_result.response_time}s")
        
        # Check for WAF/IPS patterns
        waf_patterns = ['cloudflare', 'akamai', 'imperva', '403 forbidden', 'access denied']
        if any(pattern in evidence for pattern in waf_patterns):
            rules.append('waf_block')
            rule_weights.append(0.75 * rule_categories['behavior_based'])
            rule_details.append("WAF/IPS block detected")
        
        # Calculate weighted confidence
        if rules and rule_weights:
            confidence = sum(rule_weights) / len(rule_weights)
        else:
            confidence = 0.5  # Neutral
        
        # Normalize to 0-1 range
        confidence = max(0.0, min(1.0, confidence))
        is_false_positive = confidence > 0.65
        
        return {
            'is_false_positive': is_false_positive,
            'confidence': confidence,
            'rules_triggered': rules,
            'rule_details': rule_details,
            'rule_weights': rule_weights,
            'features': self._extract_advanced_features(scan_result),
            'prediction_method': 'advanced_rule_based',
            'explanation': self._generate_rule_based_explanation(rules, rule_details, confidence)
        }
    
    def _combine_predictions(self, ml_prediction, rule_prediction, features):
        """Combine ML and rule-based predictions."""
        ml_weight = 0.6  # ML gets 60% weight
        rule_weight = 0.4  # Rules get 40% weight
        
        # Weighted confidence
        combined_confidence = (
            ml_prediction['confidence'] * ml_weight +
            rule_prediction['confidence'] * rule_weight
        )
        
        # Weighted decision
        ml_vote = 0 if ml_prediction['is_false_positive'] else 1
        rule_vote = 0 if rule_prediction['is_false_positive'] else 1
        
        ml_contribution = ml_vote * ml_weight
        rule_contribution = rule_vote * rule_weight
        
        combined_vote = (ml_contribution + rule_contribution) > 0.5
        is_false_positive = not combined_vote
        
        return {
            'is_false_positive': is_false_positive,
            'confidence': combined_confidence,
            'ml_prediction': ml_prediction,
            'rule_prediction': rule_prediction,
            'features': features,
            'prediction_method': 'hybrid',
            'combination_weights': {'ml': ml_weight, 'rule': rule_weight},
            'explanation': f"Hybrid decision: ML ({ml_prediction['confidence']:.2f}) + "
                         f"Rules ({rule_prediction['confidence']:.2f}) = {combined_confidence:.2f}"
        }
    
    def _generate_explanation(self, is_fp, confidence, feature_impacts, shap_explanation):
        """Generate human-readable explanation."""
        explanation = []
        
        # Main prediction
        prediction_text = "False Positive" if is_fp else "True Positive"
        explanation.append(f"**Prediction:** {prediction_text}")
        explanation.append(f"**Confidence:** {confidence:.1%}")
        
        # Top features
        if feature_impacts:
            explanation.append("\n**Top Contributing Factors:**")
            for i, impact in enumerate(feature_impacts[:3], 1):
                direction = "increased" if impact['impact'] > 0 else "decreased"
                explanation.append(
                    f"{i}. {impact['feature']}: {impact['value']:.3f} "
                    f"({direction} probability by {abs(impact['impact']):.3f})"
                )
        
        # SHAP summary if available
        if shap_explanation and 'top_contributors' in shap_explanation:
            explanation.append("\n**SHAP Analysis:**")
            for contributor in shap_explanation['top_contributors'][:3]:
                effect = "increased" if contributor['impact'] > 0 else "decreased"
                explanation.append(
                    f"- {contributor['feature']}: {effect} probability "
                    f"by {abs(contributor['impact']):.3f}"
                )
        
        return "\n".join(explanation)
    
    def _generate_rule_based_explanation(self, rules, rule_details, confidence):
        """Generate explanation for rule-based prediction."""
        if not rules:
            return "No rules triggered. Default confidence: 50%"
        
        explanation = [f"**Rules Triggered ({len(rules)}):**"]
        
        for i, (rule, detail) in enumerate(zip(rules, rule_details), 1):
            explanation.append(f"{i}. {detail}")
        
        explanation.append(f"\n**Overall Confidence:** {confidence:.1%}")
        
        if confidence > 0.65:
            explanation.append("**Conclusion:** Likely False Positive")
        elif confidence < 0.35:
            explanation.append("**Conclusion:** Likely True Positive")
        else:
            explanation.append("**Conclusion:** Uncertain - requires manual review")
        
        return "\n".join(explanation)
    
    def add_human_feedback(self, scan_result: Any, is_false_positive: bool):
        """
        Add human feedback for active learning.
        
        Args:
            scan_result: Original scan result
            is_false_positive: Human verdict (True if false positive)
        """
        feedback_entry = {
            'timestamp': datetime.now().isoformat(),
            'scan_result': asdict(scan_result) if hasattr(scan_result, '__dict__') else scan_result,
            'human_verdict': is_false_positive,
            'features': self._extract_advanced_features(scan_result),
            'model_prediction': self.predict_with_confidence(scan_result)
        }
        
        self.human_feedback_data.append(feedback_entry)
        
        # Check if we should retrain
        if len(self.human_feedback_data) >= self.model_config['retrain_interval']:
            logger.info(f"Active learning: {len(self.human_feedback_data)} feedback samples. Retraining...")
            self._retrain_with_feedback()
    
    def _retrain_with_feedback(self):
        """Retrain model with human feedback data."""
        if not self.human_feedback_data:
            return
        
        # Combine feedback with existing training data
        training_data = self.training_data.copy()
        
        for feedback in self.human_feedback_data:
            result = feedback['scan_result']
            result['is_false_positive'] = feedback['human_verdict']
            training_data.append(result)
        
        # Retrain model
        self.train_with_hyperparameter_tuning(training_data)
        
        # Clear feedback data after retraining
        self.human_feedback_data.clear()
        
        logger.info(f"Model retrained with {len(training_data)} samples")
    
    def _generate_model_version(self) -> str:
        """Generate unique model version string."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        data_hash = hashlib.md5(
            str(len(self.training_data)).encode()
        ).hexdigest()[:8]
        
        return f"v1_{timestamp}_{data_hash}"
    
    def _save_model_with_version(self):
        """Save model with versioning."""
        if not self.model_metadata:
            return
        
        version = self.model_metadata.version
        save_path = os.path.join(self.model_storage_path, version)
        os.makedirs(save_path, exist_ok=True)
        
        try:
            # Save model artifacts
            model_data = {
                'ensemble_model': self.ensemble_model,
                'scaler': self.scaler,
                'encoders': self.encoders,
                'feature_weights': self.feature_weights,
                'model_metadata': asdict(self.model_metadata),
                'feature_importance_history': [
                    asdict(fi) for fi in self.feature_importance_history
                ],
                'performance_history': self.performance_history
            }
            
            # Save main model
            model_file = os.path.join(save_path, 'model.joblib')
            joblib.dump(model_data, model_file)
            
            # Save metadata separately
            metadata_file = os.path.join(save_path, 'metadata.json')
            with open(metadata_file, 'w') as f:
                json.dump(asdict(self.model_metadata), f, indent=2, default=str)
            
            # Update latest symlink
            latest_link = os.path.join(self.model_storage_path, 'latest')
            if os.path.islink(latest_link):
                os.unlink(latest_link)
            os.symlink(version, latest_link)
            
            logger.info(f"Model saved as version {version}")
            
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
    
    def load_model(self, version: str = 'latest'):
        """Load specific model version."""
        try:
            model_path = os.path.join(self.model_storage_path, version)
            
            if version == 'latest':
                # Resolve symlink
                model_path = os.path.realpath(model_path)
                version = os.path.basename(model_path)
            
            model_file = os.path.join(model_path, 'model.joblib')
            
            if not os.path.exists(model_file):
                logger.error(f"Model file not found: {model_file}")
                return False
            
            # Load model
            model_data = joblib.load(model_file)
            
            self.ensemble_model = model_data['ensemble_model']
            self.scaler = model_data['scaler']
            self.encoders = model_data.get('encoders', {})
            self.feature_weights = model_data.get('feature_weights', self.feature_weights)
            
            # Recreate metadata object
            metadata_dict = model_data.get('model_metadata', {})
            if metadata_dict:
                self.model_metadata = ModelMetadata(**metadata_dict)
            
            self.feature_importance_history = [
                FeatureImportance(**fi) for fi in 
                model_data.get('feature_importance_history', [])
            ]
            
            self.performance_history = model_data.get('performance_history', [])
            
            # Initialize SHAP if enabled
            if self.enable_shap and self.ensemble_model:
                # Need training data for SHAP - would need to be loaded separately
                pass
            
            logger.info(f"Model {version} loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False
    
    def get_detailed_statistics(self) -> Dict[str, Any]:
        """Get detailed statistics about the model and predictions."""
        stats = {
            'model_info': {
                'version': self.model_metadata.version if self.model_metadata else 'untrained',
                'type': type(self.ensemble_model).__name__ if self.ensemble_model else 'None',
                'ensemble_method': self.model_config['ensemble_method'],
                'feature_count': len(self.feature_weights),
            },
            'training_data': {
                'total_samples': len(self.training_data),
                'feedback_samples': len(self.human_feedback_data),
                'last_trained': self.model_metadata.created_at.isoformat() 
                              if self.model_metadata else None,
            },
            'performance': {
                'history_entries': len(self.performance_history),
                'latest_metrics': self.performance_history[-1] if self.performance_history else {},
                'average_accuracy': np.mean([
                    h['metrics'].get('test_accuracy', 0) 
                    for h in self.performance_history 
                    if 'metrics' in h
                ]) if self.performance_history else 0,
            },
            'feature_analysis': {
                'top_features': [
                    asdict(fi) for fi in self.feature_importance_history[:5]
                ] if self.feature_importance_history else [],
                'weight_distribution': self.feature_weights,
            },
            'capabilities': {
                'ml_available': ML_AVAILABLE,
                'shap_available': self.enable_shap and SHAP_AVAILABLE,
                'active_learning': self.enable_active_learning,
                'model_persistence': True,
            }
        }
        
        return stats
    
    def analyze_feature_drift(self, new_data: List[Dict]) -> Dict[str, Any]:
        """
        Analyze feature drift between training data and new data.
        
        Args:
            new_data: New scan results to compare
            
        Returns:
            Dictionary with drift analysis
        """
        if not self.training_data or not new_data:
            return {'error': 'Insufficient data for drift analysis'}
        
        try:
            # Extract features from both datasets
            train_features = []
            new_features = []
            
            for data in self.training_data[:1000]:  # Sample for efficiency
                features = self._extract_advanced_features(data)
                if features:
                    train_features.append(list(features.values()))
            
            for data in new_data[:1000]:  # Sample for efficiency
                features = self._extract_advanced_features(data)
                if features:
                    new_features.append(list(features.values()))
            
            if not train_features or not new_features:
                return {'error': 'Could not extract features'}
            
            train_features = np.array(train_features)
            new_features = np.array(new_features)
            
            # Calculate drift metrics
            drift_metrics = {}
            
            # Mean and std comparison
            for i, feature_name in enumerate(self.feature_weights.keys()):
                if i >= train_features.shape[1] or i >= new_features.shape[1]:
                    continue
                
                train_mean = np.mean(train_features[:, i])
                new_mean = np.mean(new_features[:, i])
                train_std = np.std(train_features[:, i])
                new_std = np.std(new_features[:, i])
                
                # Calculate drift score
                mean_drift = abs(train_mean - new_mean) / (train_std + 1e-10)
                std_drift = abs(train_std - new_std) / (train_std + 1e-10)
                
                drift_score = (mean_drift + std_drift) / 2
                
                drift_metrics[feature_name] = {
                    'drift_score': float(drift_score),
                    'train_mean': float(train_mean),
                    'new_mean': float(new_mean),
                    'train_std': float(train_std),
                    'new_std': float(new_std),
                    'mean_drift': float(mean_drift),
                    'std_drift': float(std_drift),
                }
            
            # Overall drift
            overall_drift = np.mean([m['drift_score'] for m in drift_metrics.values()])
            
            # Identify drifting features
            drifting_features = [
                (feat, metrics['drift_score'])
                for feat, metrics in drift_metrics.items()
                if metrics['drift_score'] > 0.5  # Threshold
            ]
            drifting_features.sort(key=lambda x: x[1], reverse=True)
            
            result = {
                'overall_drift_score': float(overall_drift),
                'drifting_features': [
                    {'feature': feat, 'score': score}
                    for feat, score in drifting_features[:10]
                ],
                'feature_drift_metrics': drift_metrics,
                'recommendation': 'Retrain model' if overall_drift > 0.3 else 'Model stable',
                'analysis_timestamp': datetime.now().isoformat()
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Feature drift analysis failed: {e}")
            return {'error': str(e)}
    
    def batch_predict_with_explanations(self, scan_results: List[Any]) -> List[Dict[str, Any]]:
        """
        Batch prediction with explanations for efficiency.
        
        Args:
            scan_results: List of scan results
            
        Returns:
            List of predictions with explanations
        """
        predictions = []
        
        for result in scan_results:
            prediction = self.predict_with_confidence(result)
            
            predictions.append({
                'result_id': getattr(result, 'vulnerability_id', id(result)),
                'url': getattr(result, 'url_tested', 'unknown'),
                'vulnerability_type': getattr(result, 'vulnerability_type', 'unknown'),
                'prediction': prediction,
                'timestamp': datetime.now().isoformat()
            })
        
        return predictions
    
    def export_model_report(self, output_path: str):
        """
        Export comprehensive model report.
        
        Args:
            output_path: Path to save report
        """
        try:
            report = {
                'export_timestamp': datetime.now().isoformat(),
                'model_statistics': self.get_detailed_statistics(),
                'performance_history': self.performance_history,
                'feature_importance_history': [
                    asdict(fi) for fi in self.feature_importance_history
                ],
                'configuration': self.model_config,
                'training_data_summary': {
                    'total_samples': len(self.training_data),
                    'feature_count': len(self.feature_weights),
                    'last_training': self.model_metadata.created_at.isoformat() 
                                   if self.model_metadata else None,
                },
                'human_feedback': {
                    'total_samples': len(self.human_feedback_data),
                    'recent_samples': [
                        {
                            'timestamp': fb['timestamp'],
                            'human_verdict': fb['human_verdict'],
                            'model_prediction': fb['model_prediction'].get('is_false_positive')
                        }
                        for fb in self.human_feedback_data[-10:]  # Last 10
                    ]
                }
            }
            
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            logger.info(f"Model report exported to {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to export model report: {e}")