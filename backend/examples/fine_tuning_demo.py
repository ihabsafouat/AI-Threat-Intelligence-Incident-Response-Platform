#!/usr/bin/env python3
"""
Cybersecurity LLM Fine-tuning Demo

This script demonstrates the complete fine-tuning pipeline for open-source LLMs
on cybersecurity data including incident reports, threat intelligence, and remediation guides.

Usage:
    python fine_tuning_demo.py [--model MODEL_NAME] [--task-type TASK_TYPE] [--max-samples MAX_SAMPLES]

Example:
    python fine_tuning_demo.py --model "microsoft/DialoGPT-medium" --task-type "causal_lm" --max-samples 100
"""

import asyncio
import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Dict, Any, Optional

# Add the parent directory to the path to import our services
sys.path.append(str(Path(__file__).parent.parent))

from app.services.fine_tuning_service import CybersecurityFineTuningService
from app.services.data_preparation_service import CybersecurityDataPreparationService
from app.core.config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class FineTuningDemo:
    """Demonstrates the complete fine-tuning pipeline."""
    
    def __init__(self, model_name: str = None, task_type: str = "causal_lm", max_samples: int = None):
        self.model_name = model_name or settings.FINE_TUNING_MODEL
        self.task_type = task_type
        self.max_samples = max_samples
        
        # Initialize services
        self.fine_tuning_service = CybersecurityFineTuningService()
        self.data_preparation_service = CybersecurityDataPreparationService()
        
        # Training state
        self.training_start_time = None
        self.training_completed = False
        
    async def run_demo(self):
        """Run the complete fine-tuning demo."""
        try:
            logger.info("🚀 Starting Cybersecurity LLM Fine-tuning Demo")
            logger.info(f"Model: {self.model_name}")
            logger.info(f"Task Type: {self.task_type}")
            logger.info(f"Max Samples: {self.max_samples or 'All available'}")
            
            # Step 1: Prepare Training Data
            await self.prepare_training_data()
            
            # Step 2: Initialize Model
            await self.initialize_model()
            
            # Step 3: Start Training
            await self.start_training()
            
            # Step 4: Monitor Training
            await self.monitor_training()
            
            # Step 5: Evaluate Model
            await self.evaluate_model()
            
            # Step 6: Generate Sample Predictions
            await self.generate_sample_predictions()
            
            # Step 7: Save and Export Model
            await self.save_and_export_model()
            
            logger.info("✅ Fine-tuning demo completed successfully!")
            
        except Exception as e:
            logger.error(f"❌ Demo failed: {e}")
            raise
        finally:
            # Cleanup
            self.fine_tuning_service.cleanup()
    
    async def prepare_training_data(self):
        """Step 1: Prepare comprehensive training dataset."""
        logger.info("\n📊 Step 1: Preparing Training Data")
        logger.info("=" * 50)
        
        try:
            # Prepare the dataset
            splits = await self.data_preparation_service.prepare_comprehensive_dataset(
                include_synthetic=True,
                max_samples_per_category=self.max_samples
            )
            
            # Display dataset statistics
            total_samples = sum(len(dataset) for dataset in splits.values())
            logger.info(f"📈 Dataset prepared successfully:")
            logger.info(f"   - Total samples: {total_samples}")
            logger.info(f"   - Train: {len(splits['train'])}")
            logger.info(f"   - Validation: {len(splits['validation'])}")
            logger.info(f"   - Test: {len(splits['test'])}")
            
            # Get detailed statistics
            train_stats = self.data_preparation_service.get_dataset_statistics(splits['train'])
            logger.info(f"   - Text length range: {train_stats['text_length']['min']} - {train_stats['text_length']['max']} characters")
            
            # Validate dataset quality
            quality_report = await self.data_preparation_service.validate_dataset_quality(splits['train'])
            logger.info(f"   - Quality score: {quality_report.get('quality_score', 'N/A')}%")
            
            if quality_report.get('quality_issues'):
                logger.warning(f"   - Quality issues found: {len(quality_report['quality_issues'])}")
                for issue in quality_report['quality_issues'][:3]:  # Show first 3
                    logger.warning(f"     * {issue['type']}: {issue['count']} samples")
            
            # Save dataset info for later use
            self.dataset_splits = splits
            
        except Exception as e:
            logger.error(f"Failed to prepare training data: {e}")
            raise
    
    async def initialize_model(self):
        """Step 2: Initialize the model and tokenizer."""
        logger.info("\n🤖 Step 2: Initializing Model")
        logger.info("=" * 50)
        
        try:
            logger.info(f"Loading model: {self.model_name}")
            logger.info(f"Task type: {self.task_type}")
            
            # Initialize the model
            self.fine_tuning_service.initialize_model(
                model_name=self.model_name,
                task_type=self.task_type
            )
            
            # Get model status
            status = self.fine_tuning_service.get_training_status()
            logger.info(f"✅ Model initialized successfully:")
            logger.info(f"   - Device: {status['device']}")
            logger.info(f"   - Model loaded: {status['model_loaded']}")
            logger.info(f"   - Tokenizer loaded: {status['tokenizer_loaded']}")
            
            if status['device'] == 'cuda':
                import torch
                logger.info(f"   - GPU Memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")
            
        except Exception as e:
            logger.error(f"Failed to initialize model: {e}")
            raise
    
    async def start_training(self):
        """Step 3: Start the fine-tuning process."""
        logger.info("\n🏋️ Step 3: Starting Fine-tuning")
        logger.info("=" * 50)
        
        try:
            logger.info("Starting fine-tuning process...")
            
            # Start training
            success = await self.fine_tuning_service.start_training(
                train_dataset=self.dataset_splits['train'],
                eval_dataset=self.dataset_splits['validation'],
                task_type=self.task_type
            )
            
            if success:
                self.training_start_time = time.time()
                logger.info("✅ Training started successfully!")
                logger.info("   - Training is running in the background")
                logger.info("   - Use the status endpoint to monitor progress")
            else:
                raise RuntimeError("Training failed to start")
                
        except Exception as e:
            logger.error(f"Failed to start training: {e}")
            raise
    
    async def monitor_training(self):
        """Step 4: Monitor training progress."""
        logger.info("\n📊 Step 4: Monitoring Training Progress")
        logger.info("=" * 50)
        
        try:
            logger.info("Monitoring training progress...")
            
            # Monitor for a reasonable time or until completion
            max_monitoring_time = 300  # 5 minutes for demo
            check_interval = 10  # Check every 10 seconds
            
            start_time = time.time()
            
            while time.time() - start_time < max_monitoring_time:
                status = self.fine_tuning_service.get_training_status()
                
                if not status['is_training']:
                    logger.info("✅ Training completed!")
                    self.training_completed = True
                    break
                
                # Calculate elapsed time
                if self.training_start_time:
                    elapsed = time.time() - self.training_start_time
                    logger.info(f"   - Training in progress... ({elapsed:.0f}s elapsed)")
                
                # Wait before next check
                await asyncio.sleep(check_interval)
            
            if not self.training_completed:
                logger.warning("⚠️ Training monitoring timeout - training may still be running")
                logger.info("   - Check the status endpoint for current progress")
                logger.info("   - Training will continue in the background")
            
        except Exception as e:
            logger.error(f"Failed to monitor training: {e}")
            # Don't raise here, as training might still be successful
    
    async def evaluate_model(self):
        """Step 5: Evaluate the fine-tuned model."""
        logger.info("\n🔍 Step 5: Evaluating Model")
        logger.info("=" * 50)
        
        try:
            logger.info("Evaluating fine-tuned model...")
            
            # Evaluate on test dataset
            eval_results = await self.fine_tuning_service.evaluate_model(
                self.dataset_splits['test']
            )
            
            logger.info("✅ Model evaluation completed:")
            logger.info(f"   - Overall metrics:")
            
            # Display key metrics
            overall_metrics = eval_results['overall_metrics']
            for metric, value in overall_metrics.items():
                if isinstance(value, float):
                    logger.info(f"     * {metric}: {value:.4f}")
                else:
                    logger.info(f"     * {metric}: {value}")
            
            # Quality assessment
            quality_assessment = eval_results.get('quality_assessment', 'Unknown')
            logger.info(f"   - Quality assessment: {quality_assessment}")
            
            # Save evaluation results
            self.evaluation_results = eval_results
            
        except Exception as e:
            logger.error(f"Failed to evaluate model: {e}")
            # Don't raise here, as the model might still be usable
    
    async def generate_sample_predictions(self):
        """Step 6: Generate sample predictions with the fine-tuned model."""
        logger.info("\n🎯 Step 6: Sample Predictions")
        logger.info("=" * 50)
        
        try:
            logger.info("Generating sample predictions...")
            
            # Sample test cases
            sample_texts = [
                "Incident: Suspicious network activity detected on",
                "Threat: APT group targeting financial sector with",
                "Remediation: Steps to contain malware outbreak include"
            ]
            
            logger.info("Sample predictions (first few tokens):")
            for i, text in enumerate(sample_texts, 1):
                logger.info(f"   {i}. Input: '{text}...'")
                logger.info(f"      Output: [Model prediction would appear here]")
                logger.info("")
            
            logger.info("Note: Full text generation requires the model to be loaded and ready")
            
        except Exception as e:
            logger.error(f"Failed to generate sample predictions: {e}")
            # Don't raise here, as this is just a demo feature
    
    async def save_and_export_model(self):
        """Step 7: Save and export the fine-tuned model."""
        logger.info("\n💾 Step 7: Saving and Exporting Model")
        logger.info("=" * 50)
        
        try:
            logger.info("Saving fine-tuned model...")
            
            # Save checkpoint
            checkpoint_path = await self.fine_tuning_service.save_checkpoint()
            logger.info(f"✅ Checkpoint saved to: {checkpoint_path}")
            
            # Model output path
            model_path = settings.FINE_TUNING_OUTPUT_PATH
            logger.info(f"✅ Model saved to: {model_path}")
            
            # Check what was saved
            if Path(model_path).exists():
                saved_files = list(Path(model_path).rglob("*"))
                logger.info(f"   - Total files saved: {len(saved_files)}")
                
                # Show key files
                key_files = [f for f in saved_files if f.name in ['config.json', 'pytorch_model.bin', 'tokenizer.json']]
                for key_file in key_files:
                    logger.info(f"   - {key_file.name}: {key_file.stat().st_size / 1024:.1f} KB")
            
            logger.info("\n🎉 Fine-tuning pipeline completed successfully!")
            logger.info("Next steps:")
            logger.info("   1. Use the fine-tuned model in your RAG system")
            logger.info("   2. Integrate with your threat intelligence platform")
            logger.info("   3. Deploy for production use")
            
        except Exception as e:
            logger.error(f"Failed to save/export model: {e}")
            raise
    
    def print_summary(self):
        """Print a summary of the demo results."""
        logger.info("\n📋 Demo Summary")
        logger.info("=" * 50)
        
        if hasattr(self, 'dataset_splits'):
            total_samples = sum(len(dataset) for dataset in self.dataset_splits.values())
            logger.info(f"Dataset: {total_samples} total samples")
        
        if hasattr(self, 'evaluation_results'):
            metrics = self.evaluation_results['overall_metrics']
            logger.info(f"Model Performance:")
            for metric, value in metrics.items():
                if isinstance(value, float):
                    logger.info(f"  - {metric}: {value:.4f}")
        
        if self.training_completed:
            training_time = time.time() - self.training_start_time if self.training_start_time else 0
            logger.info(f"Training completed in {training_time:.0f} seconds")
        else:
            logger.info("Training status: In progress or completed in background")
        
        logger.info(f"Model saved to: {settings.FINE_TUNING_OUTPUT_PATH}")


async def main():
    """Main function to run the demo."""
    parser = argparse.ArgumentParser(description="Cybersecurity LLM Fine-tuning Demo")
    parser.add_argument("--model", type=str, help="Model name to fine-tune")
    parser.add_argument("--task-type", type=str, default="causal_lm", 
                       choices=["causal_lm", "sequence_classification"],
                       help="Type of task for fine-tuning")
    parser.add_argument("--max-samples", type=int, help="Maximum samples per category")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Create and run demo
        demo = FineTuningDemo(
            model_name=args.model,
            task_type=args.task_type,
            max_samples=args.max_samples
        )
        
        await demo.run_demo()
        demo.print_summary()
        
    except KeyboardInterrupt:
        logger.info("\n⚠️ Demo interrupted by user")
    except Exception as e:
        logger.error(f"❌ Demo failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Run the demo
    asyncio.run(main()) 