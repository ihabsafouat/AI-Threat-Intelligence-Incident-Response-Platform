# Threat Intelligence RAG System

A comprehensive Retrieval-Augmented Generation (RAG) system for threat intelligence analysis using LangChain and LangGraph.

## 🚀 Features

### Core RAG Capabilities
- **Intelligent Querying**: Natural language questions about cybersecurity threats
- **Vector Similarity Search**: Find similar threats using semantic search
- **Comprehensive Analysis**: Multi-step threat analysis using LangGraph workflows
- **Automated Recommendations**: AI-generated actionable security recommendations
- **Threat Report Generation**: Complete reports with analysis and mitigation strategies

### Technical Features
- **Multi-Provider Support**: OpenAI and Hugging Face embeddings
- **Vector Database Integration**: Pinecone and Weaviate support
- **LangGraph Workflows**: Complex analysis pipelines with state management
- **Async Operations**: Full async/await support for high performance
- **Configurable Retrieval**: Adjustable similarity thresholds and result counts

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   User Query    │───▶│   RAG Service    │───▶│  Vector Store   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │   LangGraph      │
                       │   Workflow       │
                       └──────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │   LLM (OpenAI)   │
                       └──────────────────┘
```

## 📋 Prerequisites

### Required Dependencies
- Python 3.8+
- OpenAI API key
- Vector database (Pinecone or Weaviate)
- LangChain and LangGraph packages

### Environment Variables
```bash
# OpenAI Configuration
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-4-turbo-preview
OPENAI_TEMPERATURE=0.1
OPENAI_MAX_TOKENS=4000

# Embedding Configuration
EMBEDDING_PROVIDER=openai  # or "huggingface"
OPENAI_EMBEDDING_MODEL=text-embedding-3-small
HF_EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2

# Vector Database Configuration
VECTOR_DB_PROVIDER=pinecone  # or "weaviate"
VECTOR_INDEX_NAME=threat-intel
VECTOR_NAMESPACE=default

# Pinecone Configuration
PINECONE_API_KEY=your_pinecone_api_key
PINECONE_ENVIRONMENT=us-east-1-gcp

# Weaviate Configuration
WEAVIATE_URL=https://your-weaviate.instance
WEAVIATE_API_KEY=your_weaviate_api_key
WEAVIATE_CLASS_NAME=ThreatIntel

# RAG Settings
RAG_CHUNK_SIZE=1000
RAG_CHUNK_OVERLAP=200
RAG_TOP_K_RETRIEVAL=8
RAG_TOP_K_GENERATION=5
RAG_SIMILARITY_THRESHOLD=0.7
RAG_MAX_CONTEXT_LENGTH=8000
```

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env with your API keys and configuration
```

### 3. Initialize RAG Service
```python
from app.services.rag_service import ThreatIntelligenceRAG

# Initialize RAG service
rag_service = ThreatIntelligenceRAG()

# Simple query
answer = await rag_service.query("What are common ransomware indicators?")
print(answer)
```

### 4. Run Demo
```bash
cd backend/examples
python rag_demo.py
```

## 📚 API Usage

### Basic Query
```python
from app.services.rag_service import ThreatIntelligenceRAG

rag_service = ThreatIntelligenceRAG()

# Simple question answering
answer = await rag_service.query("How do I detect APT activity?")
```

### Threat Analysis
```python
# Comprehensive threat analysis using LangGraph
analysis = await rag_service.analyze_threats(
    "Analyze the threat posed by CVE-2023-1234"
)

print(f"Risk Score: {analysis['risk_score']}")
print(f"Confidence: {analysis['confidence']}")
print(f"Recommendations: {analysis['recommendations']}")
```

### Threat Report Generation
```python
# Generate comprehensive threat report
report = await rag_service.generate_threat_report(
    "Generate a report on APT threats and indicators",
    include_recommendations=True
)

print(f"Risk Level: {report['summary']['risk_level']}")
print(f"Total Threats: {report['summary']['total_threats_found']}")
```

### Similar Threats Search
```python
# Find similar threats using vector similarity
similar_threats = await rag_service.search_similar_threats(
    "malware command and control servers",
    top_k=5
)

for threat in similar_threats:
    print(f"Score: {threat['similarity_score']}")
    print(f"Content: {threat['content'][:100]}...")
```

### Adding Documents
```python
# Add new threat intelligence documents
documents = [
    "New malware variant detected in the wild",
    "Phishing campaign targeting financial institutions"
]

metadatas = [
    {"source": "threat_feed_1", "date": "2024-01-01"},
    {"source": "threat_feed_2", "date": "2024-01-01"}
]

success = await rag_service.add_documents(documents, metadatas)
```

## 🔧 Configuration

### RAG Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `RAG_CHUNK_SIZE` | 1000 | Size of text chunks for processing |
| `RAG_CHUNK_OVERLAP` | 200 | Overlap between chunks |
| `RAG_TOP_K_RETRIEVAL` | 8 | Number of documents to retrieve |
| `RAG_TOP_K_GENERATION` | 5 | Number of documents for generation |
| `RAG_SIMILARITY_THRESHOLD` | 0.7 | Minimum similarity score for retrieval |
| `RAG_MAX_CONTEXT_LENGTH` | 8000 | Maximum context length for LLM |

### LLM Configuration
| Setting | Default | Description |
|---------|---------|-------------|
| `LLM_PROVIDER` | "openai" | Language model provider |
| `OPENAI_MODEL` | "gpt-4-turbo-preview" | OpenAI model to use |
| `OPENAI_TEMPERATURE` | 0.1 | Creativity level (0-1) |
| `OPENAI_MAX_TOKENS` | 4000 | Maximum tokens per response |

## 🎯 Use Cases

### 1. Threat Intelligence Analysis
- Analyze new threats and vulnerabilities
- Identify patterns and trends
- Assess risk levels and impact

### 2. Incident Response
- Quick threat assessment
- Similar incident search
- Mitigation strategy generation

### 3. Security Research
- Literature review and analysis
- Threat landscape understanding
- Best practice identification

### 4. Security Operations
- Threat hunting support
- Indicator analysis
- Risk assessment automation

## 🔍 API Endpoints

### RAG Endpoints
- `POST /rag/query` - Simple RAG query
- `POST /rag/analyze` - Comprehensive threat analysis
- `POST /rag/report` - Generate threat report
- `POST /rag/search-similar` - Find similar threats
- `POST /rag/documents` - Add new documents
- `GET /rag/stats` - System statistics
- `GET /rag/health` - Health check
- `GET /rag/examples` - Example queries

### Example API Usage
```bash
# Simple query
curl -X POST "http://localhost:8000/rag/query" \
  -H "Content-Type: application/json" \
  -d '{"question": "What are ransomware indicators?"}'

# Threat analysis
curl -X POST "http://localhost:8000/rag/analyze" \
  -H "Content-Type: application/json" \
  -d '{"query": "Analyze CVE-2023-1234"}'

# Generate report
curl -X POST "http://localhost:8000/rag/report" \
  -H "Content-Type: application/json" \
  -d '{"question": "APT threat report", "include_recommendations": true}'
```

## 🧪 Testing

### Run Demo Script
```bash
cd backend/examples
python rag_demo.py
```

### Test Individual Components
```python
# Test RAG service
from app.services.rag_service import ThreatIntelligenceRAG

rag = ThreatIntelligenceRAG()

# Test query
result = await rag.query("Test question")
assert result is not None

# Test analysis
analysis = await rag.analyze_threats("Test analysis")
assert "analysis" in analysis
```

## 🚨 Troubleshooting

### Common Issues

#### 1. OpenAI API Key Error
```
ValueError: OPENAI_API_KEY is required for RAG functionality
```
**Solution**: Set `OPENAI_API_KEY` environment variable

#### 2. Vector Store Connection Error
```
Failed to initialize vector store
```
**Solution**: Check vector database configuration and API keys

#### 3. Embedding Service Error
```
Failed to initialize embeddings
```
**Solution**: Verify embedding provider configuration

#### 4. Memory Issues
```
CUDA out of memory
```
**Solution**: Use CPU-based embeddings or reduce batch sizes

### Debug Mode
Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 🔒 Security Considerations

### API Key Management
- Store API keys in environment variables
- Use AWS Secrets Manager for production
- Rotate keys regularly

### Access Control
- Implement authentication for RAG endpoints
- Rate limit API calls
- Monitor usage patterns

### Data Privacy
- Sanitize input data
- Log access to sensitive information
- Implement data retention policies

## 📈 Performance Optimization

### Vector Search Optimization
- Adjust similarity thresholds
- Use appropriate chunk sizes
- Implement caching strategies

### LLM Optimization
- Batch similar queries
- Use streaming for long responses
- Implement response caching

### Database Optimization
- Use connection pooling
- Implement query optimization
- Monitor performance metrics

## 🔮 Future Enhancements

### Planned Features
- Multi-modal threat analysis (images, files)
- Real-time threat streaming
- Advanced workflow orchestration
- Integration with SIEM systems
- Automated threat correlation

### Research Areas
- Few-shot learning for threat detection
- Advanced prompt engineering
- Multi-agent threat analysis
- Explainable AI for security decisions

## 📚 Additional Resources

### Documentation
- [LangChain Documentation](https://python.langchain.com/)
- [LangGraph Documentation](https://langchain-ai.github.io/langgraph/)
- [OpenAI API Documentation](https://platform.openai.com/docs)

### Community
- [LangChain Discord](https://discord.gg/langchain)
- [OpenAI Community](https://community.openai.com/)
- [Security Research Groups](https://www.first.org/)

### Support
For issues and questions:
1. Check this documentation
2. Review error logs
3. Test with demo script
4. Open GitHub issue

---

**Note**: This RAG system is designed for threat intelligence analysis and should be used in accordance with your organization's security policies and procedures. 