from typing import List, Optional, Union
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)


class EmbeddingService:
    """Unified embedding service supporting OpenAI and Hugging Face.

    Provides simple methods to embed text(s) using the configured provider.
    """

    def __init__(self,
                 provider: Optional[str] = None,
                 model_name: Optional[str] = None,
                 openai_api_key: Optional[str] = None):
        self.provider = (provider or settings.EMBEDDING_PROVIDER).lower()
        self.model_name = model_name
        self._client = None

        if self.provider == "openai":
            try:
                from openai import OpenAI  # type: ignore
                api_key = openai_api_key or settings.OPENAI_API_KEY
                if not api_key:
                    raise ValueError("OPENAI_API_KEY is not set")
                self._client = OpenAI(api_key=api_key)
                self.model_name = self.model_name or settings.OPENAI_EMBEDDING_MODEL
                logger.info(f"Initialized OpenAI Embedding client with model: {self.model_name}")
            except Exception as e:
                logger.error(f"Failed to initialize OpenAI client: {e}")
                raise
        else:
            # Default to Hugging Face sentence-transformers
            try:
                from sentence_transformers import SentenceTransformer  # type: ignore
                hf_model = self.model_name or settings.HF_EMBEDDING_MODEL
                hf_token = settings.HF_API_TOKEN
                if hf_token:
                    import os
                    os.environ["HF_API_TOKEN"] = hf_token
                self._client = SentenceTransformer(hf_model)
                self.model_name = hf_model
                logger.info(f"Initialized SentenceTransformer model: {hf_model}")
            except Exception as e:
                logger.error(f"Failed to initialize Hugging Face model: {e}")
                raise

    async def embed_text(self, text: str) -> List[float]:
        """Create an embedding vector for a single text."""
        vectors = await self.embed_texts([text])
        return vectors[0]

    async def embed_texts(self, texts: List[str]) -> List[List[float]]:
        """Create embedding vectors for a list of texts."""
        if not texts:
            return []

        if self.provider == "openai":
            try:
                result = self._client.embeddings.create(
                    model=self.model_name,
                    input=texts,
                )
                return [data.embedding for data in result.data]
            except Exception as e:
                logger.error(f"OpenAI embeddings failed: {e}")
                raise
        else:
            try:
                # Normalize embeddings for better vector similarity behavior
                vectors = self._client.encode(
                    texts,
                    convert_to_numpy=False,
                    normalize_embeddings=True,
                    show_progress_bar=False,
                )
                # SentenceTransformer returns a list-like object; ensure pure python lists
                return [list(map(float, vec)) for vec in vectors]
            except Exception as e:
                logger.error(f"Hugging Face embeddings failed: {e}")
                raise

    def info(self) -> dict:
        """Return provider and model information."""
        return {
            "provider": self.provider,
            "model": self.model_name,
        } 