# Cybersecurity LLM Fine-tuning System

## Overview

The Cybersecurity LLM Fine-tuning System enables you to train open-source Large Language Models on your specific cybersecurity data, creating specialized models that understand your organization's threat landscape, incident response procedures, and security terminology.

## 🎯 Key Features

- **Multi-Model Support**: Fine-tune various open-source LLMs (GPT-2, DialoGPT, GPT-Neo, etc.)
- **Cybersecurity-Specific Data**: Pre-built datasets for incident reports, threat intelligence, and remediation guides
- **Parameter Efficient Training**: LoRA (Low-Rank Adaptation) for faster, cheaper training
- **Flexible Task Types**: Support for both text generation and classification tasks
- **Comprehensive Evaluation**: Built-in metrics and quality assessment
- **Easy Integration**: Seamlessly integrates with your existing RAG system

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Data Sources  │    │ Data Preparation │    │ Fine-tuning     │
│                 │    │ Service          │    │ Service         │
├─────────────────┤    ├──────────────────┤    ├─────────────────┤
│ • Incident      │    │ • Data cleaning  │    │ • Model loading │
│   reports      │───▶│ • Normalization  │───▶│ • Training      │
│ • Threat intel │    │ • Dataset splits │    │ • Evaluation    │
│ • Remediation  │    │ • Quality checks │    │ • Checkpoints   │
│   guides       │    │ • Synthetic data │    │ • Export        │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │   Hugging Face   │    │   Fine-tuned    │
                       │   Datasets       │    │   Model         │
                       └──────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### 1. Prerequisites

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export FINE_TUNING_ENABLED=true
export FINE_TUNING_MODEL="microsoft/DialoGPT-medium"
export FINE_TUNING_USE_LORA=true
```

### 2. Run the Demo

```bash
# Basic demo
python examples/fine_tuning_demo.py

# Custom model and parameters
python examples/fine_tuning_demo.py \
    --model "gpt2" \
    --task-type "causal_lm" \
    --max-samples 100 \
    --verbose
```

### 3. Use the API

```python
from app.services.fine_tuning_service import CybersecurityFineTuningService

# Initialize service
service = CybersecurityFineTuningService()

# Prepare data
splits = await service.prepare_training_data()

# Initialize model
service.initialize_model("microsoft/DialoGPT-medium")

# Start training
await service.start_training(splits['train'], splits['validation'])
```

## 📊 Data Preparation

### Supported Data Types

1. **Incident Reports**
   - Security incidents and breaches
   - Response actions and timelines
   - Impact assessment and lessons learned

2. **Threat Intelligence**
   - APT groups and tactics
   - Malware analysis and indicators
   - Threat actor profiles and motivations

3. **Remediation Guides**
   - Step-by-step response procedures
   - Security control implementations
   - Best practices and recommendations

4. **CVE Data**
   - Vulnerability descriptions
   - CVSS scores and severity
   - Affected software and patches

5. **Synthetic Data**
   - AI-generated training examples
   - Augmented datasets for better coverage
   - Balanced class distributions

### Data Format

```json
{
  "text": "INCIDENT REPORT: Ransomware Attack\n\nDate: 2024-01-15\nSeverity: Critical\n...",
  "type": "ransomware",
  "severity": "critical",
  "response_time": "immediate",
  "business_impact": "high"
}
```

### Data Quality Features

- **Automatic Validation**: Checks for missing values, duplicates, and quality issues
- **Text Length Analysis**: Ensures appropriate training sample sizes
- **Quality Scoring**: Overall dataset quality assessment
- **Recommendations**: Suggestions for improving data quality

## 🤖 Model Configuration

### Supported Models

| Model Family | Examples | Parameters | Use Case |
|--------------|----------|------------|----------|
| **GPT-2** | `gpt2`, `distilgpt2` | 124M-1.5B | Text generation, conversation |
| **DialoGPT** | `microsoft/DialoGPT-medium` | 345M | Dialogue, Q&A |
| **GPT-Neo** | `EleutherAI/gpt-neo-125M` | 125M-2.7B | General purpose |
| **Custom** | Your own models | Variable | Specialized tasks |

### Task Types

1. **Causal Language Modeling (causal_lm)**
   - Text generation and completion
   - Incident report writing
   - Threat analysis generation

2. **Sequence Classification**
   - Threat type classification
   - Severity assessment
   - Response priority ranking

### LoRA Configuration

```python
# Parameter Efficient Fine-tuning
FINE_TUNING_USE_LORA = True
FINE_TUNING_LORA_R = 16          # Rank of low-rank matrices
FINE_TUNING_LORA_ALPHA = 32      # Scaling factor
FINE_TUNING_LORA_DROPOUT = 0.1   # Dropout rate
```

## ⚙️ Training Configuration

### Hyperparameters

```python
# Learning and Training
FINE_TUNING_LEARNING_RATE = 2e-5
FINE_TUNING_BATCH_SIZE = 4
FINE_TUNING_GRADIENT_ACCUMULATION_STEPS = 4
FINE_TUNING_MAX_STEPS = 1000
FINE_TUNING_WARMUP_STEPS = 100

# Model Configuration
FINE_TUNING_MAX_SEQ_LENGTH = 512
FINE_TUNING_WEIGHT_DECAY = 0.01
FINE_TUNING_GRADIENT_CHECKPOINTING = True

# Mixed Precision
FINE_TUNING_MIXED_PRECISION = "fp16"  # fp16, bf16, fp32
```

### Hardware Requirements

| Resource | Minimum | Recommended | High Performance |
|----------|---------|-------------|------------------|
| **GPU Memory** | 8GB | 16GB | 24GB+ |
| **RAM** | 16GB | 32GB | 64GB+ |
| **Storage** | 50GB | 100GB | 200GB+ |
| **CPU** | 4 cores | 8 cores | 16+ cores |

### Performance Optimization

```python
# Enable mixed precision for faster training
FINE_TUNING_MIXED_PRECISION = "fp16"

# Use gradient checkpointing for memory efficiency
FINE_TUNING_GRADIENT_CHECKPOINTING = True

# Optimize batch size for your hardware
FINE_TUNING_BATCH_SIZE = 4  # Adjust based on GPU memory
```

## 📈 Training Process

### Training Pipeline

1. **Data Preparation**
   ```python
   # Prepare comprehensive dataset
   splits = await service.prepare_training_data(
       include_synthetic=True,
       max_samples_per_category=100
   )
   ```

2. **Model Initialization**
   ```python
   # Load and configure model
   service.initialize_model(
       model_name="microsoft/DialoGPT-medium",
       task_type="causal_lm"
   )
   ```

3. **Training Execution**
   ```python
   # Start fine-tuning
   success = await service.start_training(
       train_dataset=splits['train'],
       eval_dataset=splits['validation'],
       task_type="causal_lm"
   )
   ```

4. **Progress Monitoring**
   ```python
   # Check training status
   status = service.get_training_status()
   print(f"Training: {status['is_training']}")
   print(f"Device: {status['device']}")
   ```

5. **Evaluation**
   ```python
   # Evaluate on test set
   eval_results = await service.evaluate_model(splits['test'])
   print(f"F1 Score: {eval_results['overall_metrics']['f1']:.4f}")
   ```

### Training Monitoring

- **Real-time Metrics**: Loss, accuracy, F1 score
- **Resource Usage**: GPU memory, CPU utilization
- **Progress Tracking**: Steps completed, time remaining
- **Early Stopping**: Automatic training termination on plateau

## 🔍 Model Evaluation

### Metrics

| Metric | Description | Target |
|--------|-------------|---------|
| **Accuracy** | Overall correct predictions | > 0.85 |
| **F1 Score** | Harmonic mean of precision/recall | > 0.80 |
| **Precision** | True positives / (True + False positives) | > 0.80 |
| **Recall** | True positives / (True + False negatives) | > 0.80 |

### Quality Assessment

```python
# Automatic quality assessment
quality_assessment = "Good" if f1_score > 0.7 else "Needs improvement"

# Detailed analysis
detailed_metrics = {
    "per_class_accuracy": {...},
    "confusion_matrix": [...],
    "sample_predictions": [...]
}
```

## 💾 Model Management

### Checkpoints

```python
# Save training checkpoint
checkpoint_path = await service.save_checkpoint("checkpoint_001")

# Load checkpoint for evaluation
await service.load_checkpoint("checkpoint_001")
```

### Model Export

```python
# Download fine-tuned model
GET /fine-tuning/download-model

# Model files included:
# - config.json: Model configuration
# - pytorch_model.bin: Model weights
# - tokenizer.json: Tokenizer configuration
# - special_tokens_map.json: Special token mappings
```

### Integration with RAG

```python
# Use fine-tuned model in RAG system
from app.services.rag_service import ThreatIntelligenceRAG

rag = ThreatIntelligenceRAG(
    model_path="./ml/fine_tuned_models/",
    use_fine_tuned=True
)
```

## 🚀 API Endpoints

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/fine-tuning/prepare-data` | POST | Prepare training dataset |
| `/fine-tuning/initialize-model` | POST | Initialize model and tokenizer |
| `/fine-tuning/start-training` | POST | Start fine-tuning process |
| `/fine-tuning/status` | GET | Get training status |
| `/fine-tuning/evaluate` | POST | Evaluate fine-tuned model |
| `/fine-tuning/save-checkpoint` | POST | Save training checkpoint |
| `/fine-tuning/load-checkpoint` | POST | Load training checkpoint |

### Data Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/fine-tuning/datasets` | GET | List available dataset types |
| `/fine-tuning/dataset-stats/{type}` | GET | Get dataset statistics |
| `/fine-tuning/upload-data` | POST | Upload custom training data |
| `/fine-tuning/download-model` | GET | Download fine-tuned model |

### Utility Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/fine-tuning/health` | GET | Service health check |
| `/fine-tuning/examples` | GET | Example configurations |
| `/fine-tuning/cleanup` | DELETE | Cleanup resources |

## 🔧 Configuration

### Environment Variables

```bash
# Enable fine-tuning
FINE_TUNING_ENABLED=true

# Model configuration
FINE_TUNING_MODEL=microsoft/DialoGPT-medium
FINE_TUNING_DATASET_PATH=./data/fine_tuning/
FINE_TUNING_OUTPUT_PATH=./ml/fine_tuned_models/

# Training parameters
FINE_TUNING_LEARNING_RATE=2e-5
FINE_TUNING_BATCH_SIZE=4
FINE_TUNING_MAX_STEPS=1000

# LoRA configuration
FINE_TUNING_USE_LORA=true
FINE_TUNING_LORA_R=16
FINE_TUNING_LORA_ALPHA=32

# Hardware configuration
FINE_TUNING_DEVICE=auto
FINE_TUNING_MIXED_PRECISION=fp16
```

### Configuration File

```python
# app/core/config.py
class Settings(BaseSettings):
    # Fine-tuning Configuration
    FINE_TUNING_ENABLED: bool = True
    FINE_TUNING_MODEL: str = "microsoft/DialoGPT-medium"
    FINE_TUNING_DATASET_PATH: str = "./data/fine_tuning/"
    FINE_TUNING_OUTPUT_PATH: str = "./ml/fine_tuned_models/"
    
    # Training Hyperparameters
    FINE_TUNING_LEARNING_RATE: float = 2e-5
    FINE_TUNING_BATCH_SIZE: int = 4
    FINE_TUNING_MAX_STEPS: int = 1000
    
    # LoRA Configuration
    FINE_TUNING_USE_LORA: bool = True
    FINE_TUNING_LORA_R: int = 16
    FINE_TUNING_LORA_ALPHA: int = 32
```

## 📚 Best Practices

### Data Quality

1. **Diverse Sources**: Include various types of cybersecurity data
2. **Consistent Format**: Standardize data structure and terminology
3. **Quality Validation**: Remove duplicates and low-quality samples
4. **Balanced Classes**: Ensure representative distribution of threat types

### Training Strategy

1. **Start Small**: Begin with smaller models and datasets
2. **Iterative Improvement**: Gradually increase complexity and data size
3. **Regular Evaluation**: Monitor performance throughout training
4. **Hyperparameter Tuning**: Experiment with learning rates and batch sizes

### Model Selection

1. **Task Alignment**: Choose models suitable for your specific task
2. **Resource Constraints**: Consider hardware limitations and training time
3. **Performance Requirements**: Balance accuracy with inference speed
4. **Domain Relevance**: Select models that align with cybersecurity domain

### Production Deployment

1. **Model Validation**: Thoroughly test before production use
2. **Performance Monitoring**: Track inference speed and accuracy
3. **Regular Updates**: Retrain with new data periodically
4. **Security Review**: Ensure model doesn't expose sensitive information

## 🐛 Troubleshooting

### Common Issues

#### Out of Memory (OOM)
```python
# Reduce batch size
FINE_TUNING_BATCH_SIZE = 2

# Enable gradient checkpointing
FINE_TUNING_GRADIENT_CHECKPOINTING = True

# Use mixed precision
FINE_TUNING_MIXED_PRECISION = "fp16"
```

#### Slow Training
```python
# Increase batch size if memory allows
FINE_TUNING_BATCH_SIZE = 8

# Reduce sequence length
FINE_TUNING_MAX_SEQ_LENGTH = 256

# Use gradient accumulation
FINE_TUNING_GRADIENT_ACCUMULATION_STEPS = 8
```

#### Poor Performance
```python
# Check data quality
quality_report = await service.validate_dataset_quality(dataset)

# Adjust learning rate
FINE_TUNING_LEARNING_RATE = 1e-5  # Try lower values

# Increase training steps
FINE_TUNING_MAX_STEPS = 2000
```

### Debug Mode

```python
# Enable verbose logging
logging.getLogger().setLevel(logging.DEBUG)

# Check service status
status = service.get_training_status()
print(json.dumps(status, indent=2))

# Validate dataset
stats = service.get_dataset_statistics(dataset)
print(json.dumps(stats, indent=2))
```

## 🔮 Future Enhancements

### Planned Features

1. **Multi-Modal Training**: Support for images, logs, and structured data
2. **Active Learning**: Intelligent data selection for training
3. **Federated Learning**: Distributed training across organizations
4. **AutoML Integration**: Automatic hyperparameter optimization
5. **Model Compression**: Quantization and pruning for deployment

### Research Areas

1. **Few-Shot Learning**: Training with minimal examples
2. **Continual Learning**: Incremental model updates
3. **Adversarial Training**: Robustness against adversarial inputs
4. **Interpretability**: Understanding model decisions
5. **Bias Detection**: Identifying and mitigating model biases

## 📖 Additional Resources

### Documentation

- [Hugging Face Transformers](https://huggingface.co/docs/transformers/)
- [PEFT (Parameter Efficient Fine-tuning)](https://github.com/huggingface/peft)
- [TRL (Transformer Reinforcement Learning)](https://github.com/huggingface/trl)
- [Accelerate](https://huggingface.co/docs/accelerate/)

### Research Papers

- [LoRA: Low-Rank Adaptation of Large Language Models](https://arxiv.org/abs/2106.09685)
- [Parameter-Efficient Transfer Learning with Diff Pruning](https://arxiv.org/abs/2012.12877)
- [The Power of Scale for Parameter-Efficient Prompt Tuning](https://arxiv.org/abs/2104.08691)

### Community

- [Hugging Face Forums](https://discuss.huggingface.co/)
- [PyTorch Community](https://discuss.pytorch.org/)
- [AI Security Community](https://github.com/topics/ai-security)

## 🤝 Contributing

We welcome contributions to improve the fine-tuning system:

1. **Bug Reports**: Open issues for bugs and problems
2. **Feature Requests**: Suggest new features and improvements
3. **Code Contributions**: Submit pull requests with enhancements
4. **Documentation**: Help improve guides and examples
5. **Testing**: Test with different models and datasets

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:

- **Documentation**: Check this README and related docs
- **Issues**: Open GitHub issues for bugs and problems
- **Discussions**: Use GitHub discussions for questions
- **Email**: Contact the development team directly

---

**Happy Fine-tuning! 🚀**

Transform your cybersecurity data into intelligent, specialized AI models that understand your unique threat landscape and response procedures. 