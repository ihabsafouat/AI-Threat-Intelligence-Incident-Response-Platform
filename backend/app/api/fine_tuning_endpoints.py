from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, UploadFile, File
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import asyncio
import logging
import json
import os
from datetime import datetime

from app.services.fine_tuning_service import CybersecurityFineTuningService
from app.services.data_preparation_service import CybersecurityDataPreparationService
from app.core import settings
from app.utils.dataset import Dataset

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/fine-tuning", tags=["Fine-tuning"])

# Pydantic models for requests and responses
class DataPreparationRequest(BaseModel):
    include_synthetic: bool = True
    max_samples_per_category: Optional[int] = None
    data_sources: Optional[List[str]] = None

class ModelInitializationRequest(BaseModel):
    model_name: Optional[str] = None
    task_type: str = "causal_lm"  # causal_lm, sequence_classification

class TrainingRequest(BaseModel):
    task_type: str = "causal_lm"
    max_samples: Optional[int] = None
    custom_hyperparameters: Optional[Dict[str, Any]] = None

class CheckpointRequest(BaseModel):
    checkpoint_name: Optional[str] = None

class EvaluationRequest(BaseModel):
    checkpoint_path: Optional[str] = None
    use_best_model: bool = True

class DataUploadRequest(BaseModel):
    data_type: str  # incident_reports, threat_intelligence, remediation_guides
    format: str = "json"  # json, csv, txt

class FineTuningStatus(BaseModel):
    is_training: bool
    current_epoch: int
    best_metric: float
    device: str
    model_loaded: bool
    tokenizer_loaded: bool
    training_progress: Optional[Dict[str, Any]] = None

class DatasetStatistics(BaseModel):
    total_samples: int
    columns: List[str]
    text_length: Optional[Dict[str, Any]] = None
    quality_score: Optional[float] = None
    split_info: Optional[Dict[str, int]] = None

class TrainingResult(BaseModel):
    success: bool
    model_path: str
    training_loss: Optional[float] = None
    evaluation_results: Optional[Dict[str, Any]] = None
    training_time: Optional[str] = None
    message: str

class EvaluationResult(BaseModel):
    overall_metrics: Dict[str, Any]
    detailed_metrics: Dict[str, Any]
    timestamp: str
    model_path: str
    quality_assessment: Optional[str] = None

# Service instances
fine_tuning_service = None
data_preparation_service = None

def get_fine_tuning_service():
    global fine_tuning_service
    if fine_tuning_service is None:
        fine_tuning_service = CybersecurityFineTuningService()
    return fine_tuning_service

def get_data_preparation_service():
    global data_preparation_service
    if data_preparation_service is None:
        data_preparation_service = CybersecurityDataPreparationService()
    return data_preparation_service

@router.post("/prepare-data", response_model=Dict[str, Any])
async def prepare_training_data(
    request: DataPreparationRequest,
    service: CybersecurityDataPreparationService = Depends(get_data_preparation_service)
):
    """Prepare comprehensive cybersecurity dataset for fine-tuning."""
    try:
        logger.info("Preparing training dataset...")
        
        # Prepare the dataset
        splits = await service.prepare_comprehensive_dataset(
            include_synthetic=request.include_synthetic,
            max_samples_per_category=request.max_samples_per_category
        )
        
        # Get statistics for each split
        stats = {}
        for split_name, dataset in splits.items():
            stats[split_name] = service.get_dataset_statistics(dataset)
        
        # Validate dataset quality
        quality_report = await service.validate_dataset_quality(splits['train'])
        
        return {
            "success": True,
            "message": "Dataset prepared successfully",
            "splits": {name: len(dataset) for name, dataset in splits.items()},
            "statistics": stats,
            "quality_report": quality_report,
            "total_samples": sum(len(dataset) for dataset in splits.values())
        }
        
    except Exception as e:
        logger.error(f"Failed to prepare training data: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/initialize-model", response_model=Dict[str, Any])
async def initialize_model(
    request: ModelInitializationRequest,
    service: CybersecurityFineTuningService = Depends(get_fine_tuning_service)
):
    """Initialize the model and tokenizer for fine-tuning."""
    try:
        logger.info(f"Initializing model: {request.model_name or 'default'}")
        
        service.initialize_model(
            model_name=request.model_name,
            task_type=request.task_type
        )
        
        status = service.get_training_status()
        
        return {
            "success": True,
            "message": "Model initialized successfully",
            "status": status,
            "model_name": request.model_name or "default",
            "task_type": request.task_type
        }
        
    except Exception as e:
        logger.error(f"Failed to initialize model: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/start-training", response_model=TrainingResult)
async def start_training(
    request: TrainingRequest,
    background_tasks: BackgroundTasks,
    service: CybersecurityFineTuningService = Depends(get_fine_tuning_service),
    data_service: CybersecurityDataPreparationService = Depends(get_data_preparation_service)
):
    """Start the fine-tuning process."""
    try:
        logger.info("Starting fine-tuning process...")
        
        # Check if model is initialized
        status = service.get_training_status()
        if not status["model_loaded"]:
            raise HTTPException(status_code=400, detail="Model not initialized. Call /initialize-model first.")
        
        # Prepare training data
        splits = await data_service.prepare_comprehensive_dataset(
            include_synthetic=True,
            max_samples_per_category=request.max_samples
        )
        
        # Start training in background
        background_tasks.add_task(
            service.start_training,
            train_dataset=splits['train'],
            eval_dataset=splits['validation'],
            task_type=request.task_type
        )
        
        return TrainingResult(
            success=True,
            model_path="Training started in background",
            message="Fine-tuning process started successfully. Check status with /status endpoint."
        )
        
    except Exception as e:
        logger.error(f"Failed to start training: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/status", response_model=FineTuningStatus)
async def get_training_status(
    service: CybersecurityFineTuningService = Depends(get_fine_tuning_service)
):
    """Get current training status."""
    try:
        status = service.get_training_status()
        return FineTuningStatus(**status)
        
    except Exception as e:
        logger.error(f"Failed to get training status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/save-checkpoint", response_model=Dict[str, Any])
async def save_checkpoint(
    request: CheckpointRequest,
    service: CybersecurityFineTuningService = Depends(get_fine_tuning_service)
):
    """Save a training checkpoint."""
    try:
        checkpoint_path = await service.save_checkpoint(request.checkpoint_name)
        
        return {
            "success": True,
            "message": "Checkpoint saved successfully",
            "checkpoint_path": checkpoint_path
        }
        
    except Exception as e:
        logger.error(f"Failed to save checkpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/load-checkpoint", response_model=Dict[str, Any])
async def load_checkpoint(
    request: CheckpointRequest,
    service: CybersecurityFineTuningService = Depends(get_fine_tuning_service)
):
    """Load a training checkpoint."""
    try:
        if not request.checkpoint_name:
            raise HTTPException(status_code=400, detail="checkpoint_name is required")
        
        success = await service.load_checkpoint(request.checkpoint_name)
        
        if success:
            return {
                "success": True,
                "message": "Checkpoint loaded successfully",
                "checkpoint_name": request.checkpoint_name
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to load checkpoint")
        
    except Exception as e:
        logger.error(f"Failed to load checkpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/evaluate", response_model=EvaluationResult)
async def evaluate_model(
    request: EvaluationRequest,
    service: CybersecurityFineTuningService = Depends(get_fine_tuning_service),
    data_service: CybersecurityDataPreparationService = Depends(get_data_preparation_service)
):
    """Evaluate the fine-tuned model."""
    try:
        logger.info("Evaluating fine-tuned model...")
        
        # Load checkpoint if specified
        if request.checkpoint_path:
            await service.load_checkpoint(request.checkpoint_path)
        
        # Prepare test dataset
        splits = await data_service.prepare_comprehensive_dataset(
            include_synthetic=False,
            max_samples_per_category=100  # Limit for evaluation
        )
        
        # Evaluate model
        eval_results = await service.evaluate_model(splits['test'])
        
        # Assess quality
        quality_assessment = "Good" if eval_results["overall_metrics"].get("f1", 0) > 0.7 else "Needs improvement"
        
        return EvaluationResult(
            overall_metrics=eval_results["overall_metrics"],
            detailed_metrics=eval_results["detailed_metrics"],
            timestamp=eval_results["timestamp"],
            model_path=eval_results["model_path"],
            quality_assessment=quality_assessment
        )
        
    except Exception as e:
        logger.error(f"Failed to evaluate model: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/datasets", response_model=List[str])
async def list_available_datasets(
    data_service: CybersecurityDataPreparationService = Depends(get_data_preparation_service)
):
    """List available dataset types."""
    return [
        "incident_reports",
        "threat_intelligence", 
        "remediation_guides",
        "cve_data",
        "synthetic"
    ]

@router.get("/dataset-stats/{dataset_type}", response_model=DatasetStatistics)
async def get_dataset_statistics(
    dataset_type: str,
    data_service: CybersecurityDataPreparationService = Depends(get_data_preparation_service)
):
    """Get statistics for a specific dataset type."""
    try:
        # Prepare the specific dataset
        if dataset_type == "incident_reports":
            dataset = await data_service._prepare_incident_reports_dataset()
        elif dataset_type == "threat_intelligence":
            dataset = await data_service._prepare_threat_intelligence_dataset()
        elif dataset_type == "remediation_guides":
            dataset = await data_service._prepare_remediation_guides_dataset()
        elif dataset_type == "cve_data":
            dataset = await data_service._prepare_cve_dataset()
        elif dataset_type == "synthetic":
            dataset = data_service._generate_synthetic_data()
        else:
            raise HTTPException(status_code=400, detail=f"Unknown dataset type: {dataset_type}")
        
        if dataset is None:
            raise HTTPException(status_code=404, detail=f"Dataset {dataset_type} not found")
        
        # Get statistics
        stats = data_service.get_dataset_statistics(dataset)
        
        # Validate quality
        quality_report = await data_service.validate_dataset_quality(dataset)
        
        return DatasetStatistics(
            total_samples=stats["total_samples"],
            columns=stats["columns"],
            text_length=stats.get("text_length"),
            quality_score=quality_report.get("quality_score"),
            split_info=None
        )
        
    except Exception as e:
        logger.error(f"Failed to get dataset statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/upload-data")
async def upload_training_data(
    file: UploadFile = File(...),
    data_type: str = None,
    data_service: CybersecurityDataPreparationService = Depends(get_data_preparation_service)
):
    """Upload custom training data."""
    try:
        if not data_type:
            raise HTTPException(status_code=400, detail="data_type is required")
        
        # Read file content
        content = await file.read()
        
        # Parse based on file type
        if file.filename.endswith('.json'):
            data = json.loads(content.decode())
        elif file.filename.endswith('.csv'):
            import pandas as pd
            import io
            df = pd.read_csv(io.StringIO(content.decode()))
            data = df.to_dict('records')
        else:
            raise HTTPException(status_code=400, detail="Unsupported file format. Use JSON or CSV.")
        
        # Convert to dataset
        dataset = Dataset.from_list(data)
        
        # Save to appropriate location
        output_file = data_service.output_path / f"uploaded_{data_type}_{file.filename}"
        dataset.to_json(str(output_file))
        
        return {
            "success": True,
            "message": f"Data uploaded successfully: {len(data)} samples",
            "file_path": str(output_file),
            "data_type": data_type
        }
        
    except Exception as e:
        logger.error(f"Failed to upload training data: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/download-model")
async def download_fine_tuned_model(
    service: CybersecurityFineTuningService = Depends(get_fine_tuning_service)
):
    """Download the fine-tuned model."""
    try:
        model_path = settings.FINE_TUNING_OUTPUT_PATH
        
        if not os.path.exists(model_path):
            raise HTTPException(status_code=404, detail="No fine-tuned model found")
        
        # Create a zip file of the model
        import zipfile
        import tempfile
        
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp_file:
            with zipfile.ZipFile(tmp_file.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(model_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, model_path)
                        zipf.write(file_path, arcname)
            
            return FileResponse(
                tmp_file.name,
                media_type='application/zip',
                filename='fine_tuned_model.zip'
            )
        
    except Exception as e:
        logger.error(f"Failed to download model: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/cleanup")
async def cleanup_resources(
    service: CybersecurityFineTuningService = Depends(get_fine_tuning_service)
):
    """Cleanup training resources."""
    try:
        service.cleanup()
        
        return {
            "success": True,
            "message": "Resources cleaned up successfully"
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup resources: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "Fine-tuning Service",
        "timestamp": datetime.now().isoformat()
    }

@router.get("/examples")
async def get_training_examples():
    """Get example training configurations."""
    return {
        "example_models": [
            "microsoft/DialoGPT-medium",
            "gpt2",
            "distilgpt2",
            "EleutherAI/gpt-neo-125M"
        ],
        "example_task_types": [
            "causal_lm",
            "sequence_classification"
        ],
        "example_hyperparameters": {
            "learning_rate": 2e-5,
            "batch_size": 4,
            "max_steps": 1000,
            "warmup_steps": 100
        }
    } 