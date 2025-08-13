from typing import Any, Dict, List, Optional, Tuple
import logging
import json
from datetime import datetime

from langchain_core.documents import Document
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_openai import ChatOpenAI
from langchain_community.vectorstores import Pinecone, Weaviate
from langchain_community.embeddings import OpenAIEmbeddings, HuggingFaceEmbeddings
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema import BaseRetriever
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolExecutor
from langchain_core.tools import tool

from app.core.config import settings
from app.services.vector_store_service import VectorStoreService
from app.services.embedding_service import EmbeddingService

logger = logging.getLogger(__name__)


class ThreatIntelligenceRAG:
    """RAG system for threat intelligence using LangChain and LangGraph.
    
    Provides intelligent querying, analysis, and generation based on stored threat data.
    """

    def __init__(self):
        self.llm = self._initialize_llm()
        self.embeddings = self._initialize_embeddings()
        self.vector_store = self._initialize_vector_store()
        self.retriever = self._initialize_retriever()
        self.rag_chain = self._build_rag_chain()
        self.analysis_graph = self._build_analysis_graph()

    def _initialize_llm(self) -> ChatOpenAI:
        """Initialize the language model."""
        if not settings.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY is required for RAG functionality")
        
        return ChatOpenAI(
            model=settings.OPENAI_MODEL,
            temperature=settings.OPENAI_TEMPERATURE,
            max_tokens=settings.OPENAI_MAX_TOKENS,
            api_key=settings.OPENAI_API_KEY
        )

    def _initialize_embeddings(self):
        """Initialize embeddings based on configuration."""
        if settings.EMBEDDING_PROVIDER == "openai":
            return OpenAIEmbeddings(
                model=settings.OPENAI_EMBEDDING_MODEL,
                openai_api_key=settings.OPENAI_API_KEY
            )
        else:
            return HuggingFaceEmbeddings(
                model_name=settings.HF_EMBEDDING_MODEL,
                model_kwargs={'device': 'cpu'},
                encode_kwargs={'normalize_embeddings': True}
            )

    def _initialize_vector_store(self):
        """Initialize vector store based on configuration."""
        if settings.VECTOR_DB_PROVIDER == "pinecone":
            import pinecone
            pinecone.init(
                api_key=settings.PINECONE_API_KEY,
                environment=settings.PINECONE_ENVIRONMENT
            )
            return Pinecone.from_existing_index(
                index_name=settings.VECTOR_INDEX_NAME,
                embedding=self.embeddings,
                namespace=settings.VECTOR_NAMESPACE
            )
        elif settings.VECTOR_DB_PROVIDER == "weaviate":
            import weaviate
            client = weaviate.Client(
                url=settings.WEAVIATE_URL,
                auth_client_secret=weaviate.auth.AuthApiKey(settings.WEAVIATE_API_KEY) if settings.WEAVIATE_API_KEY else None
            )
            return Weaviate(
                client=client,
                index_name=settings.WEAVIATE_CLASS_NAME,
                text_key="meta",
                embedding=self.embeddings
            )
        else:
            raise ValueError(f"Unsupported vector store provider: {settings.VECTOR_DB_PROVIDER}")

    def _initialize_retriever(self) -> BaseRetriever:
        """Initialize the retriever with custom settings."""
        retriever = self.vector_store.as_retriever(
            search_type="similarity",
            search_kwargs={
                "k": settings.RAG_TOP_K_RETRIEVAL,
                "score_threshold": settings.RAG_SIMILARITY_THRESHOLD
            }
        )
        return retriever

    def _build_rag_chain(self):
        """Build the RAG chain for question answering."""
        # Template for threat intelligence analysis
        template = """You are an expert cybersecurity analyst specializing in threat intelligence analysis.

        Use the following context to answer the user's question about cybersecurity threats, vulnerabilities, or indicators of compromise.

        Context:
        {context}

        Question: {question}

        Instructions:
        1. Analyze the provided context thoroughly
        2. Provide accurate, actionable insights
        3. If the context doesn't contain enough information, say so
        4. Use technical terminology appropriately
        5. Provide specific examples when possible
        6. Include risk assessment and recommendations if applicable

        Answer:"""

        prompt = ChatPromptTemplate.from_template(template)
        
        # Build the RAG chain
        rag_chain = (
            {"context": self.retriever, "question": RunnablePassthrough()}
            | prompt
            | self.llm
            | StrOutputParser()
        )
        
        return rag_chain

    def _build_analysis_graph(self) -> StateGraph:
        """Build a LangGraph for complex threat analysis workflows."""
        
        # Define the state schema
        class ThreatAnalysisState:
            def __init__(self):
                self.query: str = ""
                self.retrieved_docs: List[Document] = []
                self.analysis: str = ""
                self.recommendations: List[str] = []
                self.risk_score: float = 0.0
                self.confidence: float = 0.0

        # Define nodes
        def retrieve_node(state: ThreatAnalysisState) -> ThreatAnalysisState:
            """Retrieve relevant documents."""
            try:
                state.retrieved_docs = self.retriever.get_relevant_documents(state.query)
                logger.info(f"Retrieved {len(state.retrieved_docs)} documents")
            except Exception as e:
                logger.error(f"Retrieval failed: {e}")
                state.retrieved_docs = []
            return state

        def analyze_node(state: ThreatAnalysisState) -> ThreatAnalysisState:
            """Analyze the retrieved documents."""
            if not state.retrieved_docs:
                state.analysis = "No relevant documents found for analysis."
                return state

            try:
                # Build context from documents
                context = "\n\n".join([doc.page_content for doc in state.retrieved_docs])
                
                # Create analysis prompt
                analysis_prompt = ChatPromptTemplate.from_template("""
                Analyze the following threat intelligence data and provide a comprehensive analysis:

                Data:
                {context}

                Query: {query}

                Provide:
                1. Summary of findings
                2. Threat assessment
                3. Risk analysis
                4. Key indicators
                5. Recommendations

                Analysis:""")

                # Generate analysis
                analysis_chain = analysis_prompt | self.llm | StrOutputParser()
                state.analysis = analysis_chain.invoke({
                    "context": context,
                    "query": state.query
                })
                
                # Extract risk score and confidence
                state.risk_score = self._extract_risk_score(state.analysis)
                state.confidence = self._extract_confidence(state.analysis)
                
            except Exception as e:
                logger.error(f"Analysis failed: {e}")
                state.analysis = f"Analysis failed: {str(e)}"
            
            return state

        def generate_recommendations_node(state: ThreatAnalysisState) -> ThreatAnalysisState:
            """Generate actionable recommendations."""
            if not state.analysis or "Analysis failed" in state.analysis:
                state.recommendations = ["Unable to generate recommendations due to analysis failure."]
                return state

            try:
                rec_prompt = ChatPromptTemplate.from_template("""
                Based on the following threat analysis, provide 3-5 specific, actionable recommendations:

                Analysis:
                {analysis}

                Recommendations should be:
                - Specific and actionable
                - Prioritized by impact
                - Include technical details
                - Consider both immediate and long-term actions

                Recommendations:""")

                rec_chain = rec_prompt | self.llm | StrOutputParser()
                recommendations = rec_chain.invoke({"analysis": state.analysis})
                
                # Parse recommendations into list
                state.recommendations = self._parse_recommendations(recommendations)
                
            except Exception as e:
                logger.error(f"Recommendation generation failed: {e}")
                state.recommendations = ["Unable to generate recommendations."]
            
            return state

        # Build the graph
        workflow = StateGraph(ThreatAnalysisState)
        
        # Add nodes
        workflow.add_node("retrieve", retrieve_node)
        workflow.add_node("analyze", analyze_node)
        workflow.add_node("recommendations", generate_recommendations_node)
        
        # Set entry point
        workflow.set_entry_point("retrieve")
        
        # Add edges
        workflow.add_edge("retrieve", "analyze")
        workflow.add_edge("analyze", "recommendations")
        workflow.add_edge("recommendations", END)
        
        return workflow.compile()

    async def query(self, question: str) -> str:
        """Simple RAG query using the basic chain."""
        try:
            result = await self.rag_chain.ainvoke(question)
            return result
        except Exception as e:
            logger.error(f"RAG query failed: {e}")
            return f"Query failed: {str(e)}"

    async def analyze_threats(self, query: str) -> Dict[str, Any]:
        """Complex threat analysis using LangGraph."""
        try:
            # Initialize state
            state = ThreatAnalysisState()
            state.query = query
            
            # Run the analysis graph
            result = self.analysis_graph.invoke(state)
            
            return {
                "query": result.query,
                "analysis": result.analysis,
                "recommendations": result.recommendations,
                "risk_score": result.risk_score,
                "confidence": result.confidence,
                "retrieved_docs_count": len(result.retrieved_docs),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Threat analysis failed: {e}")
            return {
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

    async def search_similar_threats(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Search for similar threats using vector similarity."""
        try:
            # Get query embedding
            query_embedding = self.embeddings.embed_query(query)
            
            # Search vector store
            docs = self.vector_store.similarity_search_with_score(
                query,
                k=top_k,
                score_threshold=settings.RAG_SIMILARITY_THRESHOLD
            )
            
            results = []
            for doc, score in docs:
                results.append({
                    "content": doc.page_content,
                    "metadata": doc.metadata,
                    "similarity_score": score,
                    "source": doc.metadata.get("source", "unknown")
                })
            
            return results
            
        except Exception as e:
            logger.error(f"Similar threat search failed: {e}")
            return []

    async def generate_threat_report(self, query: str, include_recommendations: bool = True) -> Dict[str, Any]:
        """Generate a comprehensive threat report."""
        try:
            # Get analysis
            analysis_result = await self.analyze_threats(query)
            
            # Get similar threats
            similar_threats = await self.search_similar_threats(query)
            
            # Build report
            report = {
                "query": query,
                "timestamp": datetime.now().isoformat(),
                "analysis": analysis_result,
                "similar_threats": similar_threats,
                "summary": {
                    "total_threats_found": len(similar_threats),
                    "risk_level": self._categorize_risk(analysis_result.get("risk_score", 0)),
                    "confidence": analysis_result.get("confidence", 0)
                }
            }
            
            if include_recommendations:
                report["recommendations"] = analysis_result.get("recommendations", [])
            
            return report
            
        except Exception as e:
            logger.error(f"Threat report generation failed: {e}")
            return {"error": str(e), "timestamp": datetime.now().isoformat()}

    def _extract_risk_score(self, analysis: str) -> float:
        """Extract risk score from analysis text."""
        try:
            # Simple extraction - look for risk-related keywords
            risk_keywords = {
                "critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0, "minimal": 1.0
            }
            
            analysis_lower = analysis.lower()
            for keyword, score in risk_keywords.items():
                if keyword in analysis_lower:
                    return score
            
            return 5.0  # Default medium risk
        except:
            return 5.0

    def _extract_confidence(self, analysis: str) -> float:
        """Extract confidence score from analysis text."""
        try:
            # Look for confidence indicators
            if "high confidence" in analysis.lower():
                return 0.9
            elif "medium confidence" in analysis.lower():
                return 0.7
            elif "low confidence" in analysis.lower():
                return 0.5
            else:
                return 0.7  # Default medium confidence
        except:
            return 0.7

    def _parse_recommendations(self, recommendations_text: str) -> List[str]:
        """Parse recommendations text into a list."""
        try:
            # Split by common delimiters
            lines = recommendations_text.split('\n')
            recommendations = []
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith(('#', '-', '*', '•')):
                    # Remove numbering if present
                    if line[0].isdigit() and line[1] in ['.', ')', ':']:
                        line = line[2:].strip()
                    recommendations.append(line)
            
            return recommendations[:5]  # Limit to 5 recommendations
        except:
            return ["Unable to parse recommendations."]

    def _categorize_risk(self, risk_score: float) -> str:
        """Categorize risk score into risk level."""
        if risk_score >= 8.0:
            return "Critical"
        elif risk_score >= 6.0:
            return "High"
        elif risk_score >= 4.0:
            return "Medium"
        elif risk_score >= 2.0:
            return "Low"
        else:
            return "Minimal"

    async def add_documents(self, documents: List[str], metadatas: Optional[List[Dict[str, Any]]] = None) -> bool:
        """Add new documents to the vector store."""
        try:
            if metadatas is None:
                metadatas = [{} for _ in documents]
            
            # Create Document objects
            docs = [
                Document(page_content=doc, metadata=meta)
                for doc, meta in zip(documents, metadatas)
            ]
            
            # Add to vector store
            self.vector_store.add_documents(docs)
            
            logger.info(f"Added {len(documents)} documents to vector store")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add documents: {e}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get RAG system statistics."""
        try:
            return {
                "vector_store_provider": settings.VECTOR_DB_PROVIDER,
                "embedding_provider": settings.EMBEDDING_PROVIDER,
                "llm_provider": settings.LLM_PROVIDER,
                "llm_model": settings.OPENAI_MODEL,
                "retrieval_settings": {
                    "top_k": settings.RAG_TOP_K_RETRIEVAL,
                    "similarity_threshold": settings.RAG_SIMILARITY_THRESHOLD,
                    "chunk_size": settings.RAG_CHUNK_SIZE,
                    "chunk_overlap": settings.RAG_CHUNK_OVERLAP
                }
            }
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {"error": str(e)} 