from typing import List, Optional
from pydantic import BaseSettings, validator
import os


class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    APP_NAME: str = "AI Threat Intelligence Platform"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    JWT_SECRET_KEY: str = "your-jwt-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Database
    DATABASE_URL: str = "postgresql://user:password@localhost/threat_intel"
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379"
    
    # CORS
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080"
    ]
    
    # Trusted hosts
    ALLOWED_HOSTS: List[str] = ["*"]
    
    # External APIs
    CVE_API_KEY: Optional[str] = None
    THREAT_FEED_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ALIENVAULT_API_KEY: Optional[str] = None
    
    # AI/ML Configuration
    MODEL_PATH: str = "./ml/models/"
    ML_ENABLED: bool = True
    
    # Embeddings
    EMBEDDING_PROVIDER: str = "huggingface"  # Options: "openai", "huggingface"
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_EMBEDDING_MODEL: str = "text-embedding-3-small"
    HF_EMBEDDING_MODEL: str = "sentence-transformers/all-MiniLM-L6-v2"
    HF_API_TOKEN: Optional[str] = None

    # Vector Database
    VECTOR_DB_PROVIDER: str = "pinecone"  # Options: "pinecone", "weaviate"
    VECTOR_INDEX_NAME: str = "threat-intel"
    VECTOR_NAMESPACE: str = "default"
    VECTOR_DIMENSION: Optional[int] = None  # If None, will infer from first vector
    VECTOR_METRIC: str = "cosine"  # cosine | dotproduct | euclidean

    # Pinecone
    PINECONE_API_KEY: Optional[str] = None
    PINECONE_ENVIRONMENT: Optional[str] = None  # e.g., "us-east-1-gcp" (legacy clients)

    # Weaviate
    WEAVIATE_URL: Optional[str] = None  # e.g., "https://your-weaviate.instance"
    WEAVIATE_API_KEY: Optional[str] = None
    WEAVIATE_CLASS_NAME: str = "ThreatIntel"
    
    # LangChain and RAG Configuration
    LLM_PROVIDER: str = "openai"  # Options: "openai", "anthropic", "local"
    OPENAI_MODEL: str = "gpt-4-turbo-preview"
    OPENAI_TEMPERATURE: float = 0.1
    OPENAI_MAX_TOKENS: int = 4000
    
    # RAG Settings
    RAG_CHUNK_SIZE: int = 1000
    RAG_CHUNK_OVERLAP: int = 200
    RAG_TOP_K_RETRIEVAL: int = 8
    RAG_TOP_K_GENERATION: int = 5
    RAG_SIMILARITY_THRESHOLD: float = 0.7
    RAG_MAX_CONTEXT_LENGTH: int = 8000

    # Fine-tuning Configuration
    FINE_TUNING_ENABLED: bool = True
    FINE_TUNING_MODEL: str = "microsoft/DialoGPT-medium"  # Base model for fine-tuning
    FINE_TUNING_DATASET_PATH: str = "./data/fine_tuning/"
    FINE_TUNING_OUTPUT_PATH: str = "./ml/fine_tuned_models/"
    FINE_TUNING_CHECKPOINT_PATH: str = "./ml/checkpoints/"
    
    # Fine-tuning Hyperparameters
    FINE_TUNING_LEARNING_RATE: float = 2e-5
    FINE_TUNING_BATCH_SIZE: int = 4
    FINE_TUNING_GRADIENT_ACCUMULATION_STEPS: int = 4
    FINE_TUNING_WARMUP_STEPS: int = 100
    FINE_TUNING_MAX_STEPS: int = 1000
    FINE_TUNING_SAVE_STEPS: int = 500
    FINE_TUNING_EVAL_STEPS: int = 500
    FINE_TUNING_LOGGING_STEPS: int = 10
    FINE_TUNING_MAX_SEQ_LENGTH: int = 512
    FINE_TUNING_WEIGHT_DECAY: float = 0.01
    FINE_TUNING_GRADIENT_CHECKPOINTING: bool = True
    
    # LoRA Configuration (Parameter Efficient Fine-tuning)
    FINE_TUNING_USE_LORA: bool = True
    FINE_TUNING_LORA_R: int = 16
    FINE_TUNING_LORA_ALPHA: int = 32
    FINE_TUNING_LORA_DROPOUT: float = 0.1
    
    # Training Data Configuration
    FINE_TUNING_TRAIN_SPLIT: float = 0.8
    FINE_TUNING_VAL_SPLIT: float = 0.1
    FINE_TUNING_TEST_SPLIT: float = 0.1
    FINE_TUNING_MAX_SAMPLES: Optional[int] = None  # None for all data
    
    # Model Evaluation
    FINE_TUNING_EVAL_METRICS: List[str] = ["accuracy", "f1", "precision", "recall"]
    FINE_TUNING_EARLY_STOPPING_PATIENCE: int = 3
    FINE_TUNING_EARLY_STOPPING_THRESHOLD: float = 0.001
    
    # Hardware Configuration
    FINE_TUNING_DEVICE: str = "auto"  # auto, cpu, cuda, mps
    FINE_TUNING_MIXED_PRECISION: str = "fp16"  # fp16, bf16, fp32
    FINE_TUNING_USE_8BIT: bool = False
    FINE_TUNING_USE_4BIT: bool = False
    
    # Logging and Monitoring
    FINE_TUNING_USE_WANDB: bool = False
    FINE_TUNING_WANDB_PROJECT: str = "cybersecurity-llm-finetuning"
    FINE_TUNING_USE_TENSORBOARD: bool = True
    FINE_TUNING_LOG_LEVEL: str = "INFO"
    
    # Threat Intelligence Sources
    THREAT_FEEDS: List[str] = [
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/alienvault_reputation.ipset",
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/emerging_threats.rules",
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/tor_exit_nodes.ipset"
    ]
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/threat_intel.log"
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 100
    
    # File Upload
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB
    UPLOAD_DIR: str = "uploads/"
    
    # Email (for notifications)
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_TLS: bool = True
    
    # Cloud Storage (for file uploads)
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None
    AWS_REGION: str = "us-east-1"
    S3_BUCKET: Optional[str] = None
    
    @validator("DATABASE_URL")
    def validate_database_url(cls, v):
        if not v.startswith(("postgresql://", "postgresql+asyncpg://")):
            raise ValueError("DATABASE_URL must be a valid PostgreSQL URL")
        return v
    
    @validator("SECRET_KEY")
    def validate_secret_key(cls, v):
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long")
        return v
    
    class Config:
        env_file = ".env"
        case_sensitive = True


# Create settings instance
settings = Settings()

# Create necessary directories
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(os.path.dirname(settings.LOG_FILE), exist_ok=True)
os.makedirs(settings.MODEL_PATH, exist_ok=True)
os.makedirs(settings.FINE_TUNING_DATASET_PATH, exist_ok=True)
os.makedirs(settings.FINE_TUNING_OUTPUT_PATH, exist_ok=True)
os.makedirs(settings.FINE_TUNING_CHECKPOINT_PATH, exist_ok=True) 