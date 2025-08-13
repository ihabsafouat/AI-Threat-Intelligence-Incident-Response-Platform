from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import logging

from app.services.rag_service import ThreatIntelligenceRAG
from app.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/rag", tags=["RAG"])


class QueryRequest(BaseModel):
    """Request model for RAG queries."""
    question: str
    include_recommendations: bool = True


class AnalysisRequest(BaseModel):
    """Request model for threat analysis."""
    query: str


class DocumentRequest(BaseModel):
    """Request model for adding documents."""
    documents: List[str]
    metadatas: Optional[List[Dict[str, Any]]] = None


class QueryResponse(BaseModel):
    """Response model for RAG queries."""
    answer: str
    timestamp: str


class AnalysisResponse(BaseModel):
    """Response model for threat analysis."""
    query: str
    analysis: str
    recommendations: List[str]
    risk_score: float
    confidence: float
    retrieved_docs_count: int
    timestamp: str


class ThreatReportResponse(BaseModel):
    """Response model for threat reports."""
    query: str
    timestamp: str
    analysis: Dict[str, Any]
    similar_threats: List[Dict[str, Any]]
    summary: Dict[str, Any]
    recommendations: Optional[List[str]] = None


class SimilarThreatsResponse(BaseModel):
    """Response model for similar threats search."""
    threats: List[Dict[str, Any]]
    query: str
    timestamp: str


class StatsResponse(BaseModel):
    """Response model for RAG system statistics."""
    vector_store_provider: str
    embedding_provider: str
    llm_provider: str
    llm_model: str
    retrieval_settings: Dict[str, Any]


# Dependency to get RAG service instance
def get_rag_service() -> ThreatIntelligenceRAG:
    """Get RAG service instance."""
    try:
        return ThreatIntelligenceRAG()
    except Exception as e:
        logger.error(f"Failed to initialize RAG service: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to initialize RAG service. Check configuration and API keys."
        )


@router.post("/query", response_model=QueryResponse)
async def query_threat_intelligence(
    request: QueryRequest,
    rag_service: ThreatIntelligenceRAG = Depends(get_rag_service)
):
    """Query threat intelligence using RAG."""
    try:
        answer = await rag_service.query(request.question)
        return QueryResponse(
            answer=answer,
            timestamp=rag_service.get_stats().get("timestamp", "")
        )
    except Exception as e:
        logger.error(f"RAG query failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_threats(
    request: AnalysisRequest,
    rag_service: ThreatIntelligenceRAG = Depends(get_rag_service)
):
    """Perform comprehensive threat analysis using LangGraph."""
    try:
        result = await rag_service.analyze_threats(request.query)
        
        if "error" in result:
            raise HTTPException(status_code=500, detail=result["error"])
        
        return AnalysisResponse(
            query=result["query"],
            analysis=result["analysis"],
            recommendations=result["recommendations"],
            risk_score=result["risk_score"],
            confidence=result["confidence"],
            retrieved_docs_count=result["retrieved_docs_count"],
            timestamp=result["timestamp"]
        )
    except Exception as e:
        logger.error(f"Threat analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/report", response_model=ThreatReportResponse)
async def generate_threat_report(
    request: QueryRequest,
    rag_service: ThreatIntelligenceRAG = Depends(get_rag_service)
):
    """Generate comprehensive threat report with analysis and recommendations."""
    try:
        report = await rag_service.generate_threat_report(
            request.query,
            include_recommendations=request.include_recommendations
        )
        
        if "error" in report:
            raise HTTPException(status_code=500, detail=report["error"])
        
        return ThreatReportResponse(**report)
    except Exception as e:
        logger.error(f"Threat report generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/search-similar", response_model=SimilarThreatsResponse)
async def search_similar_threats(
    request: AnalysisRequest,
    top_k: int = 5,
    rag_service: ThreatIntelligenceRAG = Depends(get_rag_service)
):
    """Search for similar threats using vector similarity."""
    try:
        threats = await rag_service.search_similar_threats(request.query, top_k)
        return SimilarThreatsResponse(
            threats=threats,
            query=request.query,
            timestamp=rag_service.get_stats().get("timestamp", "")
        )
    except Exception as e:
        logger.error(f"Similar threats search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/documents")
async def add_documents(
    request: DocumentRequest,
    rag_service: ThreatIntelligenceRAG = Depends(get_rag_service)
):
    """Add new documents to the vector store."""
    try:
        success = await rag_service.add_documents(
            request.documents,
            request.metadatas
        )
        
        if success:
            return {"message": f"Successfully added {len(request.documents)} documents"}
        else:
            raise HTTPException(status_code=500, detail="Failed to add documents")
            
    except Exception as e:
        logger.error(f"Document addition failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats", response_model=StatsResponse)
async def get_rag_stats(
    rag_service: ThreatIntelligenceRAG = Depends(get_rag_service)
):
    """Get RAG system statistics and configuration."""
    try:
        stats = rag_service.get_stats()
        
        if "error" in stats:
            raise HTTPException(status_code=500, detail=stats["error"])
        
        return StatsResponse(**stats)
    except Exception as e:
        logger.error(f"Failed to get RAG stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check():
    """Health check endpoint for RAG service."""
    return {
        "status": "healthy",
        "service": "RAG",
        "timestamp": "2024-01-01T00:00:00Z"
    }


# Example usage endpoints
@router.get("/examples")
async def get_example_queries():
    """Get example queries for testing the RAG system."""
    return {
        "examples": [
            {
                "category": "CVE Analysis",
                "queries": [
                    "What are the latest critical vulnerabilities in web applications?",
                    "Tell me about CVE-2023-1234 and its impact",
                    "What software is affected by buffer overflow vulnerabilities?"
                ]
            },
            {
                "category": "Threat Hunting",
                "queries": [
                    "What indicators suggest APT activity?",
                    "How do I detect ransomware in my network?",
                    "What are common phishing indicators?"
                ]
            },
            {
                "category": "Risk Assessment",
                "queries": [
                    "What is the risk level of this IP address?",
                    "How severe is this malware threat?",
                    "What are the potential impacts of this vulnerability?"
                ]
            },
            {
                "category": "Mitigation",
                "queries": [
                    "How can I protect against SQL injection attacks?",
                    "What are the best practices for endpoint security?",
                    "How do I respond to a data breach?"
                ]
            }
        ]
    } 