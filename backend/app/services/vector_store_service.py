from typing import Any, Dict, List, Optional, Tuple
import logging
import json

from app.core.config import settings

logger = logging.getLogger(__name__)


class VectorStoreService:
    """Unified Vector Store service supporting Pinecone and Weaviate.

    - Lazily creates index/schema on first upsert if needed
    - Infers vector dimension from first payload when not configured
    - Stores arbitrary metadata alongside vectors
    """

    def __init__(self,
                 provider: Optional[str] = None,
                 index_name: Optional[str] = None,
                 namespace: Optional[str] = None,
                 dimension: Optional[int] = None,
                 metric: Optional[str] = None):
        self.provider = (provider or settings.VECTOR_DB_PROVIDER).lower()
        self.index_name = index_name or settings.VECTOR_INDEX_NAME
        self.namespace = namespace or settings.VECTOR_NAMESPACE
        self.dimension = dimension or settings.VECTOR_DIMENSION
        self.metric = (metric or settings.VECTOR_METRIC).lower()

        self._client = None
        self._index = None

        if self.provider == "pinecone":
            self._init_pinecone()
        elif self.provider == "weaviate":
            self._init_weaviate()
        else:
            raise ValueError("Unsupported VECTOR_DB_PROVIDER. Use 'pinecone' or 'weaviate'.")

    # ---------- Pinecone ----------
    def _init_pinecone(self) -> None:
        try:
            import pinecone  # type: ignore
            api_key = settings.PINECONE_API_KEY
            if not api_key:
                raise ValueError("PINECONE_API_KEY is not set")
            # Support legacy env init if provided
            if getattr(settings, "PINECONE_ENVIRONMENT", None):
                pinecone.init(api_key=api_key, environment=settings.PINECONE_ENVIRONMENT)
            else:
                pinecone.init(api_key=api_key)
            self._client = pinecone
            self._pinecone = pinecone
            logger.info("Initialized Pinecone client")
        except Exception as e:
            logger.error(f"Failed to initialize Pinecone: {e}")
            raise

    def _ensure_pinecone_index(self, dimension: int) -> None:
        assert self._client is not None
        try:
            existing = [idx["name"] if isinstance(idx, dict) else idx.name for idx in self._pinecone.list_indexes()]
        except Exception:
            # Some clients return list[str]
            existing = self._pinecone.list_indexes()  # type: ignore

        if self.index_name not in existing:
            logger.info(f"Creating Pinecone index '{self.index_name}' (dim={dimension}, metric={self.metric})")
            self._pinecone.create_index(name=self.index_name, dimension=dimension, metric=self.metric)
        self._index = self._pinecone.Index(self.index_name)

    # ---------- Weaviate ----------
    def _init_weaviate(self) -> None:
        try:
            import weaviate  # type: ignore
            url = settings.WEAVIATE_URL
            if not url:
                raise ValueError("WEAVIATE_URL is not set")
            if settings.WEAVIATE_API_KEY:
                from weaviate.auth import AuthApiKey  # type: ignore
                auth = AuthApiKey(api_key=settings.WEAVIATE_API_KEY)
                client = weaviate.Client(url=url, auth_client_secret=auth, additional_headers={"X-OpenAI-Api-Key": settings.OPENAI_API_KEY} if settings.OPENAI_API_KEY else None)
            else:
                client = weaviate.Client(url=url)
            self._client = client
            logger.info("Initialized Weaviate client")
            self._ensure_weaviate_class()
        except Exception as e:
            logger.error(f"Failed to initialize Weaviate: {e}")
            raise

    def _ensure_weaviate_class(self) -> None:
        assert self._client is not None
        class_name = settings.WEAVIATE_CLASS_NAME
        try:
            schema = self._client.schema.get()
            classes = [c.get("class") for c in schema.get("classes", [])]
            if class_name not in classes:
                logger.info(f"Creating Weaviate class '{class_name}' with 'none' vectorizer")
                self._client.schema.create_class({
                    "class": class_name,
                    "vectorizer": "none",
                    "properties": [
                        {"name": "meta", "dataType": ["text"]},
                        {"name": "id", "dataType": ["text"]},
                    ]
                })
        except Exception as e:
            logger.error(f"Failed to ensure Weaviate class: {e}")
            raise

    # ---------- Public API ----------
    async def upsert_vectors(self, *, vectors: List[List[float]], ids: List[str], metadatas: Optional[List[Dict[str, Any]]] = None) -> int:
        """Upsert vectors with optional per-item metadata.

        Returns number of upserted items.
        """
        if not vectors or not ids or len(vectors) != len(ids):
            raise ValueError("vectors and ids must be the same non-zero length")

        metadatas = metadatas or [{} for _ in ids]

        if self.provider == "pinecone":
            return await self._pinecone_upsert(vectors=vectors, ids=ids, metadatas=metadatas)
        else:
            return await self._weaviate_upsert(vectors=vectors, ids=ids, metadatas=metadatas)

    async def query(self, *, vector: List[float], top_k: int = 5, filter: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Query nearest neighbors and return matches with ids, scores and metadata."""
        if self.provider == "pinecone":
            return await self._pinecone_query(vector=vector, top_k=top_k, filter=filter)
        else:
            return await self._weaviate_query(vector=vector, top_k=top_k, filter=filter)

    async def delete(self, *, ids: Optional[List[str]] = None, delete_all: bool = False) -> int:
        """Delete by ids or all in namespace. Returns number of deleted items when available."""
        if self.provider == "pinecone":
            return await self._pinecone_delete(ids=ids, delete_all=delete_all)
        else:
            return await self._weaviate_delete(ids=ids, delete_all=delete_all)

    # ---------- Pinecone ops ----------
    async def _pinecone_upsert(self, *, vectors: List[List[float]], ids: List[str], metadatas: List[Dict[str, Any]]) -> int:
        try:
            dimension = self.dimension or len(vectors[0])
            self._ensure_pinecone_index(dimension)
            assert self._index is not None

            # Prepare items
            items = []
            for i, vec in enumerate(vectors):
                md = metadatas[i] if i < len(metadatas) else {}
                items.append({
                    "id": ids[i],
                    "values": vec,
                    "metadata": md
                })

            # Upsert in batches of 100
            batch_size = 100
            upserted = 0
            for start in range(0, len(items), batch_size):
                batch = items[start:start + batch_size]
                self._index.upsert(vectors=batch, namespace=self.namespace)
                upserted += len(batch)
            return upserted
        except Exception as e:
            logger.error(f"Pinecone upsert failed: {e}")
            raise

    async def _pinecone_query(self, *, vector: List[float], top_k: int, filter: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        try:
            # Ensure index exists when querying
            if self._index is None:
                dim = self.dimension or len(vector)
                self._ensure_pinecone_index(dim)
            assert self._index is not None
            res = self._index.query(vector=vector, top_k=top_k, include_metadata=True, namespace=self.namespace, filter=filter)
            matches = []
            for m in res.get("matches", []):
                matches.append({
                    "id": m.get("id"),
                    "score": m.get("score"),
                    "metadata": m.get("metadata", {}),
                })
            return matches
        except Exception as e:
            logger.error(f"Pinecone query failed: {e}")
            raise

    async def _pinecone_delete(self, *, ids: Optional[List[str]], delete_all: bool) -> int:
        try:
            if self._index is None:
                # Nothing to delete from yet
                return 0
            if delete_all:
                self._index.delete(deleteAll=True, namespace=self.namespace)
                return -1  # unknown count
            if ids:
                self._index.delete(ids=ids, namespace=self.namespace)
                return len(ids)
            return 0
        except Exception as e:
            logger.error(f"Pinecone delete failed: {e}")
            raise

    # ---------- Weaviate ops ----------
    async def _weaviate_upsert(self, *, vectors: List[List[float]], ids: List[str], metadatas: List[Dict[str, Any]]) -> int:
        try:
            assert self._client is not None
            class_name = settings.WEAVIATE_CLASS_NAME
            with self._client.batch as batch:
                batch.batch_size = 100
                for i, vec in enumerate(vectors):
                    props = {
                        "id": ids[i],
                        "meta": json.dumps(metadatas[i] if i < len(metadatas) else {}),
                    }
                    batch.add_data_object(
                        data_object=props,
                        class_name=class_name,
                        vector=vec,
                    )
            return len(vectors)
        except Exception as e:
            logger.error(f"Weaviate upsert failed: {e}")
            raise

    async def _weaviate_query(self, *, vector: List[float], top_k: int, filter: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        try:
            assert self._client is not None
            class_name = settings.WEAVIATE_CLASS_NAME
            qb = self._client.query.get(class_name, ["id", "meta"]).with_near_vector({"vector": vector}).with_limit(top_k)
            if filter:
                # Convert a simple equality filter {"field": "value"} to Weaviate 'where'
                for key, value in filter.items():
                    qb = qb.with_where({
                        "path": [key],
                        "operator": "Equal",
                        "valueText": str(value)
                    })
            result = qb.do()
            data = result.get("data", {}).get("Get", {}).get(class_name, [])
            matches: List[Dict[str, Any]] = []
            # Note: distance is returned when using hybrid/nearVector with settings. Some clusters return _additional.score
            for obj in data:
                md = {}
                try:
                    md = json.loads(obj.get("meta") or "{}")
                except Exception:
                    md = {"meta": obj.get("meta")}
                matches.append({
                    "id": obj.get("id"),
                    "score": None,
                    "metadata": md,
                })
            return matches
        except Exception as e:
            logger.error(f"Weaviate query failed: {e}")
            raise

    async def _weaviate_delete(self, *, ids: Optional[List[str]], delete_all: bool) -> int:
        try:
            assert self._client is not None
            class_name = settings.WEAVIATE_CLASS_NAME
            if delete_all:
                self._client.schema.delete_class(class_name)
                self._ensure_weaviate_class()
                return -1
            if ids:
                deleted = 0
                for _id in ids:
                    try:
                        self._client.data_object.delete(uuid=_id, class_name=class_name)
                        deleted += 1
                    except Exception:
                        continue
                return deleted
            return 0
        except Exception as e:
            logger.error(f"Weaviate delete failed: {e}")
            raise 