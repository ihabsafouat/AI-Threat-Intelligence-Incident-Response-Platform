#!/usr/bin/env python3
"""
RAG Demo Script for Threat Intelligence Platform

This script demonstrates how to use the RAG service for:
- Querying threat intelligence
- Analyzing threats with LangGraph
- Generating comprehensive reports
- Searching for similar threats

Usage:
    python rag_demo.py
"""

import asyncio
import json
import sys
import os
from typing import Dict, Any

# Add the app directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from app.services.rag_service import ThreatIntelligenceRAG
from app.services.database.dynamodb_service import DynamoDBService


class RAGDemo:
    """Demo class for showcasing RAG capabilities."""
    
    def __init__(self):
        self.rag_service = None
        self.db_service = None
        
    async def initialize(self):
        """Initialize the RAG and database services."""
        try:
            print("🚀 Initializing RAG Service...")
            self.rag_service = ThreatIntelligenceRAG()
            print("✅ RAG Service initialized successfully")
            
            print("🔧 Initializing Database Service...")
            self.db_service = DynamoDBService(enable_vector_indexing=True)
            print("✅ Database Service initialized successfully")
            
        except Exception as e:
            print(f"❌ Initialization failed: {e}")
            print("Please check your configuration and API keys")
            return False
        return True
    
    async def demo_simple_query(self):
        """Demonstrate simple RAG querying."""
        print("\n" + "="*50)
        print("🔍 DEMO: Simple RAG Query")
        print("="*50)
        
        question = "What are the common indicators of a ransomware attack?"
        
        try:
            print(f"Question: {question}")
            answer = await self.rag_service.query(question)
            print(f"\nAnswer:\n{answer}")
            
        except Exception as e:
            print(f"❌ Query failed: {e}")
    
    async def demo_threat_analysis(self):
        """Demonstrate comprehensive threat analysis using LangGraph."""
        print("\n" + "="*50)
        print("🧠 DEMO: Threat Analysis with LangGraph")
        print("="*50)
        
        query = "Analyze the threat posed by CVE-2023-1234 and provide recommendations"
        
        try:
            print(f"Analysis Query: {query}")
            result = await self.rag_service.analyze_threats(query)
            
            print(f"\n📊 Analysis Results:")
            print(f"Risk Score: {result.get('risk_score', 'N/A')}")
            print(f"Confidence: {result.get('confidence', 'N/A')}")
            print(f"Documents Retrieved: {result.get('retrieved_docs_count', 'N/A')}")
            
            print(f"\n📝 Analysis:")
            print(result.get('analysis', 'No analysis available'))
            
            print(f"\n💡 Recommendations:")
            for i, rec in enumerate(result.get('recommendations', []), 1):
                print(f"{i}. {rec}")
                
        except Exception as e:
            print(f"❌ Analysis failed: {e}")
    
    async def demo_threat_report(self):
        """Demonstrate comprehensive threat report generation."""
        print("\n" + "="*50)
        print("📋 DEMO: Comprehensive Threat Report")
        print("="*50)
        
        query = "Generate a comprehensive report on APT threats and their indicators"
        
        try:
            print(f"Report Query: {query}")
            report = await self.rag_service.generate_threat_report(query)
            
            print(f"\n📋 Threat Report:")
            print(f"Query: {report.get('query', 'N/A')}")
            print(f"Timestamp: {report.get('timestamp', 'N/A')}")
            
            summary = report.get('summary', {})
            print(f"\n📊 Summary:")
            print(f"Total Threats Found: {summary.get('total_threats_found', 'N/A')}")
            print(f"Risk Level: {summary.get('risk_level', 'N/A')}")
            print(f"Confidence: {summary.get('confidence', 'N/A')}")
            
            similar_threats = report.get('similar_threats', [])
            if similar_threats:
                print(f"\n🔍 Similar Threats ({len(similar_threats)} found):")
                for i, threat in enumerate(similar_threats[:3], 1):  # Show first 3
                    print(f"{i}. Score: {threat.get('similarity_score', 'N/A')}")
                    print(f"   Source: {threat.get('source', 'N/A')}")
                    print(f"   Content: {threat.get('content', 'N/A')[:100]}...")
            
        except Exception as e:
            print(f"❌ Report generation failed: {e}")
    
    async def demo_similar_threats_search(self):
        """Demonstrate similar threats search."""
        print("\n" + "="*50)
        print("🔍 DEMO: Similar Threats Search")
        print("="*50)
        
        query = "malware command and control servers"
        
        try:
            print(f"Search Query: {query}")
            threats = await self.rag_service.search_similar_threats(query, top_k=3)
            
            print(f"\n🔍 Found {len(threats)} similar threats:")
            for i, threat in enumerate(threats, 1):
                print(f"\n{i}. Similarity Score: {threat.get('similarity_score', 'N/A')}")
                print(f"   Source: {threat.get('source', 'N/A')}")
                print(f"   Content: {threat.get('content', 'N/A')[:150]}...")
                
        except Exception as e:
            print(f"❌ Similar threats search failed: {e}")
    
    async def demo_add_sample_data(self):
        """Demonstrate adding sample threat intelligence data."""
        print("\n" + "="*50)
        print("📝 DEMO: Adding Sample Threat Data")
        print("="*50)
        
        sample_threats = [
            {
                "indicator": "192.168.1.100",
                "threat_type": "malware",
                "source": "demo",
                "description": "Suspicious IP address associated with malware command and control",
                "severity": "high",
                "confidence": 0.85,
                "tags": ["malware", "c2", "suspicious"]
            },
            {
                "indicator": "malware.example.com",
                "threat_type": "phishing",
                "source": "demo",
                "description": "Phishing domain used in credential harvesting campaigns",
                "severity": "medium",
                "confidence": 0.92,
                "tags": ["phishing", "credential-harvesting", "domain"]
            },
            {
                "indicator": "CVE-2023-DEMO",
                "threat_type": "exploit",
                "source": "demo",
                "description": "Buffer overflow vulnerability in demo application allowing remote code execution",
                "severity": "critical",
                "confidence": 0.95,
                "tags": ["cve", "buffer-overflow", "rce", "critical"]
            }
        ]
        
        try:
            print("Adding sample threat intelligence data...")
            
            for threat in sample_threats:
                success = await self.db_service.store_threat_data(threat)
                if success:
                    print(f"✅ Added: {threat['indicator']}")
                else:
                    print(f"❌ Failed to add: {threat['indicator']}")
            
            print("\nSample data added successfully!")
            
        except Exception as e:
            print(f"❌ Failed to add sample data: {e}")
    
    async def demo_system_stats(self):
        """Demonstrate getting system statistics."""
        print("\n" + "="*50)
        print("📊 DEMO: System Statistics")
        print("="*50)
        
        try:
            stats = self.rag_service.get_stats()
            
            print("🔧 RAG System Configuration:")
            print(f"Vector Store: {stats.get('vector_store_provider', 'N/A')}")
            print(f"Embedding Provider: {stats.get('embedding_provider', 'N/A')}")
            print(f"LLM Provider: {stats.get('llm_provider', 'N/A')}")
            print(f"LLM Model: {stats.get('llm_model', 'N/A')}")
            
            retrieval_settings = stats.get('retrieval_settings', {})
            print(f"\n⚙️ Retrieval Settings:")
            print(f"Top K: {retrieval_settings.get('top_k', 'N/A')}")
            print(f"Similarity Threshold: {retrieval_settings.get('similarity_threshold', 'N/A')}")
            print(f"Chunk Size: {retrieval_settings.get('chunk_size', 'N/A')}")
            print(f"Chunk Overlap: {retrieval_settings.get('chunk_overlap', 'N/A')}")
            
        except Exception as e:
            print(f"❌ Failed to get stats: {e}")
    
    async def run_demo(self):
        """Run the complete demo."""
        print("🎯 Threat Intelligence RAG Demo")
        print("="*50)
        
        # Initialize services
        if not await self.initialize():
            return
        
        # Run demos
        await self.demo_system_stats()
        await self.demo_add_sample_data()
        await self.demo_simple_query()
        await self.demo_threat_analysis()
        await self.demo_threat_report()
        await self.demo_similar_threats_search()
        
        print("\n" + "="*50)
        print("🎉 Demo completed successfully!")
        print("="*50)


async def main():
    """Main function to run the demo."""
    demo = RAGDemo()
    await demo.run_demo()


if __name__ == "__main__":
    # Run the demo
    asyncio.run(main()) 