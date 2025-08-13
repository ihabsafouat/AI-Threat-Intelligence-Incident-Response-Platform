from typing import Any, Dict, List, Optional, Tuple, Union
import logging
import json
import os
import torch
from datetime import datetime
from pathlib import Path

from transformers import (
    AutoTokenizer, AutoModelForCausalLM, AutoModelForSequenceClassification,
    TrainingArguments, Trainer, DataCollatorForLanguageModeling,
    EarlyStoppingCallback, set_seed
)
from datasets import Dataset, load_dataset, concatenate_datasets
from peft import LoraConfig, get_peft_model, TaskType
from trl import SFTTrainer
from accelerate import Accelerator
import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import wandb

from app.core.config import settings
from app.services.database.dynamodb_service import DynamoDBService

logger = logging.getLogger(__name__)


class CybersecurityFineTuningService:
    """Fine-tuning service for open-source LLMs on cybersecurity data.
    
    Supports multiple model architectures and training approaches:
    - Causal Language Modeling (text generation)
    - Sequence Classification (threat classification)
    - Parameter Efficient Fine-tuning (LoRA)
    - Multi-task learning
    """

    def __init__(self):
        self.device = self._setup_device()
        self.tokenizer = None
        self.model = None
        self.trainer = None
        self.accelerator = None
        
        # Training state
        self.is_training = False
        self.current_epoch = 0
        self.best_metric = 0.0
        
        # Initialize accelerator
        if settings.FINE_TUNING_USE_WANDB:
            wandb.init(project=settings.FINE_TUNING_WANDB_PROJECT)

    def _setup_device(self) -> torch.device:
        """Setup the training device."""
        if settings.FINE_TUNING_DEVICE == "auto":
            if torch.cuda.is_available():
                device = torch.device("cuda")
                logger.info(f"Using CUDA device: {torch.cuda.get_device_name()}")
            elif torch.backends.mps.is_available():
                device = torch.device("mps")
                logger.info("Using MPS device")
            else:
                device = torch.device("cpu")
                logger.info("Using CPU device")
        else:
            device = torch.device(settings.FINE_TUNING_DEVICE)
        
        return device

    async def prepare_training_data(self, 
                                  data_sources: List[str] = None,
                                  max_samples: Optional[int] = None) -> Dict[str, Dataset]:
        """Prepare training data from multiple sources."""
        try:
            logger.info("Preparing training data...")
            
            # Default data sources if none provided
            if data_sources is None:
                data_sources = [
                    "incident_reports",
                    "threat_intelligence", 
                    "remediation_guides"
                ]
            
            datasets = {}
            
            for source in data_sources:
                logger.info(f"Processing {source} data...")
                
                if source == "incident_reports":
                    dataset = await self._prepare_incident_reports_data()
                elif source == "threat_intelligence":
                    dataset = await self._prepare_threat_intelligence_data()
                elif source == "remediation_guides":
                    dataset = await self._prepare_remediation_guides_data()
                else:
                    logger.warning(f"Unknown data source: {source}")
                    continue
                
                if dataset is not None and len(dataset) > 0:
                    datasets[source] = dataset
                    logger.info(f"Loaded {len(dataset)} samples from {source}")
            
            # Combine datasets
            if datasets:
                combined_dataset = self._combine_datasets(list(datasets.values()))
                
                # Split into train/val/test
                splits = self._split_dataset(combined_dataset)
                
                # Apply max samples limit if specified
                if max_samples:
                    splits = self._limit_dataset_size(splits, max_samples)
                
                logger.info(f"Final dataset sizes - Train: {len(splits['train'])}, "
                          f"Val: {len(splits['validation'])}, Test: {len(splits['test'])}")
                
                return splits
            else:
                raise ValueError("No valid datasets found")
                
        except Exception as e:
            logger.error(f"Failed to prepare training data: {e}")
            raise

    async def _prepare_incident_reports_data(self) -> Optional[Dataset]:
        """Prepare incident reports data for training."""
        try:
            # This would typically come from your database or file system
            # For now, we'll create sample data structure
            
            sample_incidents = [
                {
                    "text": "Incident: Ransomware detected on endpoint 192.168.1.100. "
                           "Malware: WannaCry variant. Impact: Data encrypted, "
                           "business operations halted. Response: Isolated endpoint, "
                           "initiated incident response procedures.",
                    "type": "ransomware",
                    "severity": "critical",
                    "response": "isolated_endpoint"
                },
                {
                    "text": "Security Alert: Phishing email campaign targeting employees. "
                           "Indicator: Suspicious links in emails from external domains. "
                           "Action: Blocked domains, sent security awareness notification.",
                    "type": "phishing",
                    "severity": "medium",
                    "response": "blocked_domains"
                }
            ]
            
            # Convert to dataset format
            dataset = Dataset.from_list(sample_incidents)
            return dataset
            
        except Exception as e:
            logger.error(f"Failed to prepare incident reports data: {e}")
            return None

    async def _prepare_threat_intelligence_data(self) -> Optional[Dataset]:
        """Prepare threat intelligence data for training."""
        try:
            # Sample threat intelligence data
            sample_threats = [
                {
                    "text": "Threat: APT29 (Cozy Bear) targeting government networks. "
                           "TTPs: Spear phishing, credential harvesting, lateral movement. "
                           "Indicators: IP ranges, domain names, file hashes.",
                    "threat_actor": "APT29",
                    "tactics": ["phishing", "credential_access", "lateral_movement"],
                    "confidence": "high"
                },
                {
                    "text": "Malware: Emotet banking trojan resurgence. "
                           "Distribution: Malicious attachments, compromised websites. "
                           "Capabilities: Keylogging, credential theft, botnet formation.",
                    "threat_actor": "unknown",
                    "tactics": ["malware", "credential_access", "command_control"],
                    "confidence": "medium"
                }
            ]
            
            dataset = Dataset.from_list(sample_threats)
            return dataset
            
        except Exception as e:
            logger.error(f"Failed to prepare threat intelligence data: {e}")
            return None

    async def _prepare_remediation_guides_data(self) -> Optional[Dataset]:
        """Prepare remediation guides data for training."""
        try:
            # Sample remediation guides
            sample_remediations = [
                {
                    "text": "Remediation for Ransomware Attack: "
                           "1. Isolate affected systems immediately "
                           "2. Disconnect from network "
                           "3. Assess scope of infection "
                           "4. Restore from clean backups "
                           "5. Implement additional security controls",
                    "threat_type": "ransomware",
                    "steps": 5,
                    "priority": "immediate"
                },
                {
                    "text": "Phishing Incident Response: "
                           "1. Remove malicious emails from all users "
                           "2. Block reported domains and IPs "
                           "3. Scan systems for malware "
                           "4. Reset compromised credentials "
                           "5. Conduct security awareness training",
                    "threat_type": "phishing",
                    "steps": 5,
                    "priority": "high"
                }
            ]
            
            dataset = Dataset.from_list(sample_remediations)
            return dataset
            
        except Exception as e:
            logger.error(f"Failed to prepare remediation guides data: {e}")
            return None

    def _combine_datasets(self, datasets: List[Dataset]) -> Dataset:
        """Combine multiple datasets into one."""
        if len(datasets) == 1:
            return datasets[0]
        
        # Concatenate datasets
        combined = concatenate_datasets(datasets)
        logger.info(f"Combined dataset size: {len(combined)}")
        return combined

    def _split_dataset(self, dataset: Dataset) -> Dict[str, Dataset]:
        """Split dataset into train/validation/test sets."""
        total_size = len(dataset)
        
        train_size = int(settings.FINE_TUNING_TRAIN_SPLIT * total_size)
        val_size = int(settings.FINE_TUNING_VAL_SPLIT * total_size)
        test_size = total_size - train_size - val_size
        
        # Split dataset
        splits = dataset.train_test_split(test_size=val_size + test_size, seed=42)
        val_test = splits['test'].train_test_split(test_size=test_size, seed=42)
        
        return {
            'train': splits['train'],
            'validation': val_test['train'],
            'test': val_test['test']
        }

    def _limit_dataset_size(self, splits: Dict[str, Dataset], max_samples: int) -> Dict[str, Dataset]:
        """Limit dataset size for faster training/testing."""
        for split_name, dataset in splits.items():
            if len(dataset) > max_samples:
                splits[split_name] = dataset.select(range(max_samples))
                logger.info(f"Limited {split_name} to {max_samples} samples")
        
        return splits

    def initialize_model(self, model_name: str = None, task_type: str = "causal_lm"):
        """Initialize the model and tokenizer for fine-tuning."""
        try:
            model_name = model_name or settings.FINE_TUNING_MODEL
            logger.info(f"Initializing model: {model_name}")
            
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            
            # Add padding token if not present
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            
            # Load model based on task type
            if task_type == "causal_lm":
                self.model = AutoModelForCausalLM.from_pretrained(
                    model_name,
                    torch_dtype=torch.float16 if settings.FINE_TUNING_MIXED_PRECISION == "fp16" else torch.float32,
                    device_map="auto" if settings.FINE_TUNING_DEVICE == "auto" else None
                )
            elif task_type == "sequence_classification":
                self.model = AutoModelForSequenceClassification.from_pretrained(
                    model_name,
                    num_labels=len(self._get_label_mapping()),
                    torch_dtype=torch.float16 if settings.FINE_TUNING_MIXED_PRECISION == "fp16" else torch.float32
                )
            else:
                raise ValueError(f"Unsupported task type: {task_type}")
            
            # Move model to device
            if settings.FINE_TUNING_DEVICE != "auto":
                self.model = self.model.to(self.device)
            
            # Apply LoRA if enabled
            if settings.FINE_TUNING_USE_LORA:
                self.model = self._apply_lora_config()
            
            logger.info(f"Model initialized successfully on {self.device}")
            
        except Exception as e:
            logger.error(f"Failed to initialize model: {e}")
            raise

    def _apply_lora_config(self):
        """Apply LoRA configuration for parameter efficient fine-tuning."""
        try:
            lora_config = LoraConfig(
                r=settings.FINE_TUNING_LORA_R,
                lora_alpha=settings.FINE_TUNING_LORA_ALPHA,
                target_modules=["q_proj", "v_proj", "k_proj", "o_proj"],
                lora_dropout=settings.FINE_TUNING_LORA_DROPOUT,
                bias="none",
                task_type=TaskType.CAUSAL_LM
            )
            
            model = get_peft_model(self.model, lora_config)
            model.print_trainable_parameters()
            
            return model
            
        except Exception as e:
            logger.error(f"Failed to apply LoRA config: {e}")
            return self.model

    def _get_label_mapping(self) -> Dict[str, int]:
        """Get label mapping for classification tasks."""
        # This would be customized based on your specific classification needs
        return {
            "ransomware": 0,
            "phishing": 1,
            "apt": 2,
            "malware": 3,
            "ddos": 4,
            "data_breach": 5,
            "insider_threat": 6,
            "other": 7
        }

    def tokenize_function(self, examples):
        """Tokenize the examples for training."""
        if "text" in examples:
            # For causal language modeling
            return self.tokenizer(
                examples["text"],
                truncation=True,
                padding="max_length",
                max_length=settings.FINE_TUNING_MAX_SEQ_LENGTH,
                return_tensors="pt"
            )
        else:
            # For sequence classification
            return self.tokenizer(
                examples["text"],
                truncation=True,
                padding="max_length",
                max_length=settings.FINE_TUNING_MAX_SEQ_LENGTH,
                return_tensors="pt"
            )

    def compute_metrics(self, eval_pred):
        """Compute evaluation metrics."""
        predictions, labels = eval_pred
        predictions = np.argmax(predictions, axis=1)
        
        precision, recall, f1, _ = precision_recall_fscore_support(
            labels, predictions, average='weighted'
        )
        acc = accuracy_score(labels, predictions)
        
        return {
            'accuracy': acc,
            'f1': f1,
            'precision': precision,
            'recall': recall
        }

    async def start_training(self, 
                           train_dataset: Dataset,
                           eval_dataset: Dataset,
                           task_type: str = "causal_lm") -> bool:
        """Start the fine-tuning process."""
        try:
            if self.is_training:
                raise RuntimeError("Training already in progress")
            
            self.is_training = True
            logger.info("Starting fine-tuning process...")
            
            # Set random seed for reproducibility
            set_seed(42)
            
            # Initialize model if not already done
            if self.model is None:
                self.initialize_model(task_type=task_type)
            
            # Prepare training arguments
            training_args = TrainingArguments(
                output_dir=settings.FINE_TUNING_OUTPUT_PATH,
                num_train_epochs=3,  # Will be overridden by max_steps
                max_steps=settings.FINE_TUNING_MAX_STEPS,
                per_device_train_batch_size=settings.FINE_TUNING_BATCH_SIZE,
                per_device_eval_batch_size=settings.FINE_TUNING_BATCH_SIZE,
                gradient_accumulation_steps=settings.FINE_TUNING_GRADIENT_ACCUMULATION_STEPS,
                learning_rate=settings.FINE_TUNING_LEARNING_RATE,
                weight_decay=settings.FINE_TUNING_WEIGHT_DECAY,
                warmup_steps=settings.FINE_TUNING_WARMUP_STEPS,
                logging_steps=settings.FINE_TUNING_LOGGING_STEPS,
                evaluation_strategy="steps",
                eval_steps=settings.FINE_TUNING_EVAL_STEPS,
                save_steps=settings.FINE_TUNING_SAVE_STEPS,
                save_total_limit=3,
                load_best_model_at_end=True,
                metric_for_best_model="f1",
                greater_is_better=True,
                dataloader_pin_memory=False,
                remove_unused_columns=False,
                gradient_checkpointing=settings.FINE_TUNING_GRADIENT_CHECKPOINTING,
                fp16=settings.FINE_TUNING_MIXED_PRECISION == "fp16",
                bf16=settings.FINE_TUNING_MIXED_PRECISION == "bf16",
                report_to="wandb" if settings.FINE_TUNING_USE_WANDB else None,
                logging_dir=f"{settings.FINE_TUNING_OUTPUT_PATH}/logs",
            )
            
            # Initialize trainer
            if task_type == "causal_lm":
                self.trainer = SFTTrainer(
                    model=self.model,
                    train_dataset=train_dataset,
                    eval_dataset=eval_dataset,
                    tokenizer=self.tokenizer,
                    args=training_args,
                    data_collator=DataCollatorForLanguageModeling(
                        tokenizer=self.tokenizer,
                        mlm=False
                    ),
                    max_seq_length=settings.FINE_TUNING_MAX_SEQ_LENGTH,
                )
            else:
                self.trainer = Trainer(
                    model=self.model,
                    args=training_args,
                    train_dataset=train_dataset,
                    eval_dataset=eval_dataset,
                    tokenizer=self.tokenizer,
                    data_collator=DataCollatorForLanguageModeling(
                        tokenizer=self.tokenizer,
                        mlm=False
                    ),
                    compute_metrics=self.compute_metrics,
                    callbacks=[EarlyStoppingCallback(
                        early_stopping_patience=settings.FINE_TUNING_EARLY_STOPPING_PATIENCE,
                        early_stopping_threshold=settings.FINE_TUNING_EARLY_STOPPING_THRESHOLD
                    )]
                )
            
            # Start training
            logger.info("Training started...")
            train_result = self.trainer.train()
            
            # Save the final model
            self.trainer.save_model()
            self.tokenizer.save_pretrained(settings.FINE_TUNING_OUTPUT_PATH)
            
            # Log training results
            logger.info(f"Training completed. Loss: {train_result.training_loss}")
            
            # Evaluate on test set if available
            if eval_dataset:
                eval_results = self.trainer.evaluate()
                logger.info(f"Evaluation results: {eval_results}")
            
            self.is_training = False
            return True
            
        except Exception as e:
            logger.error(f"Training failed: {e}")
            self.is_training = False
            raise

    async def evaluate_model(self, test_dataset: Dataset) -> Dict[str, Any]:
        """Evaluate the fine-tuned model on test data."""
        try:
            if self.trainer is None:
                raise RuntimeError("No trained model available")
            
            logger.info("Evaluating model on test dataset...")
            
            # Run evaluation
            eval_results = self.trainer.evaluate(test_dataset)
            
            # Generate predictions for detailed analysis
            predictions = self.trainer.predict(test_dataset)
            
            # Calculate additional metrics
            detailed_metrics = self._calculate_detailed_metrics(predictions, test_dataset)
            
            # Combine results
            results = {
                "overall_metrics": eval_results,
                "detailed_metrics": detailed_metrics,
                "timestamp": datetime.now().isoformat(),
                "model_path": settings.FINE_TUNING_OUTPUT_PATH
            }
            
            logger.info(f"Evaluation completed: {results}")
            return results
            
        except Exception as e:
            logger.error(f"Model evaluation failed: {e}")
            raise

    def _calculate_detailed_metrics(self, predictions, test_dataset):
        """Calculate detailed metrics for model evaluation."""
        try:
            # This would be customized based on your specific evaluation needs
            return {
                "per_class_accuracy": {},
                "confusion_matrix": None,
                "sample_predictions": []
            }
        except Exception as e:
            logger.error(f"Failed to calculate detailed metrics: {e}")
            return {}

    async def save_checkpoint(self, checkpoint_name: str = None) -> str:
        """Save a training checkpoint."""
        try:
            if checkpoint_name is None:
                checkpoint_name = f"checkpoint_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            checkpoint_path = os.path.join(settings.FINE_TUNING_CHECKPOINT_PATH, checkpoint_name)
            
            if self.trainer:
                self.trainer.save_model(checkpoint_path)
                self.tokenizer.save_pretrained(checkpoint_path)
            
            logger.info(f"Checkpoint saved to: {checkpoint_path}")
            return checkpoint_path
            
        except Exception as e:
            logger.error(f"Failed to save checkpoint: {e}")
            raise

    async def load_checkpoint(self, checkpoint_path: str) -> bool:
        """Load a training checkpoint."""
        try:
            if not os.path.exists(checkpoint_path):
                raise FileNotFoundError(f"Checkpoint not found: {checkpoint_path}")
            
            # Load tokenizer and model
            self.tokenizer = AutoTokenizer.from_pretrained(checkpoint_path)
            
            # Determine model type and load accordingly
            if "causal" in checkpoint_path.lower():
                self.model = AutoModelForCausalLM.from_pretrained(checkpoint_path)
            else:
                self.model = AutoModelForSequenceClassification.from_pretrained(checkpoint_path)
            
            # Move to device
            if settings.FINE_TUNING_DEVICE != "auto":
                self.model = self.model.to(self.device)
            
            logger.info(f"Checkpoint loaded from: {checkpoint_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load checkpoint: {e}")
            raise

    def get_training_status(self) -> Dict[str, Any]:
        """Get current training status."""
        return {
            "is_training": self.is_training,
            "current_epoch": self.current_epoch,
            "best_metric": self.best_metric,
            "device": str(self.device),
            "model_loaded": self.model is not None,
            "tokenizer_loaded": self.tokenizer is not None
        }

    def cleanup(self):
        """Cleanup resources."""
        try:
            if self.trainer:
                del self.trainer
            if self.model:
                del self.model
            if self.tokenizer:
                del self.tokenizer
            
            # Clear CUDA cache if using GPU
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
            
            logger.info("Resources cleaned up successfully")
            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}") 