"""
Database Management for RBAC

Handles database connections, sessions, and initialization for the RBAC system.
"""

from typing import Generator, Optional
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from contextlib import contextmanager
import logging

from .models import Base

logger = logging.getLogger(__name__)


class RBACDatabase:
    """Database manager for the RBAC system."""
    
    def __init__(self, database_url: str, echo: bool = False):
        """
        Initialize the database manager.
        
        Args:
            database_url: Database connection URL
            echo: Enable SQL query logging
        """
        self.database_url = database_url
        self.engine = None
        self.SessionLocal = None
        self._initialize_engine(echo)
    
    def _initialize_engine(self, echo: bool = False):
        """Initialize the SQLAlchemy engine."""
        try:
            # Create engine with appropriate configuration
            if "sqlite" in self.database_url.lower():
                # SQLite configuration
                self.engine = create_engine(
                    self.database_url,
                    echo=echo,
                    connect_args={"check_same_thread": False},
                    poolclass=StaticPool
                )
            else:
                # PostgreSQL/MySQL configuration
                self.engine = create_engine(
                    self.database_url,
                    echo=echo,
                    pool_pre_ping=True,
                    pool_recycle=300
                )
            
            # Create session factory
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine
            )
            
            logger.info(f"Database engine initialized: {self.database_url}")
            
        except Exception as e:
            logger.error(f"Failed to initialize database engine: {e}")
            raise
    
    def create_tables(self):
        """Create all database tables."""
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create database tables: {e}")
            raise
    
    def drop_tables(self):
        """Drop all database tables."""
        try:
            Base.metadata.drop_all(bind=self.engine)
            logger.info("Database tables dropped successfully")
        except Exception as e:
            logger.error(f"Failed to drop database tables: {e}")
            raise
    
    def get_session(self) -> Session:
        """Get a new database session."""
        if not self.SessionLocal:
            raise RuntimeError("Database not initialized")
        return self.SessionLocal()
    
    @contextmanager
    def get_session_context(self) -> Generator[Session, None, None]:
        """Get a database session with automatic cleanup."""
        session = self.get_session()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    def check_connection(self) -> bool:
        """Check if the database connection is working."""
        try:
            with self.get_session_context() as session:
                session.execute("SELECT 1")
            return True
        except Exception as e:
            logger.error(f"Database connection check failed: {e}")
            return False
    
    def get_database_info(self) -> dict:
        """Get database information."""
        try:
            with self.get_session_context() as session:
                # Get database version
                if "sqlite" in self.database_url.lower():
                    result = session.execute("SELECT sqlite_version()")
                    version = result.scalar()
                elif "postgresql" in self.database_url.lower():
                    result = session.execute("SELECT version()")
                    version = result.scalar()
                elif "mysql" in self.database_url.lower():
                    result = session.execute("SELECT VERSION()")
                    version = result.scalar()
                else:
                    version = "Unknown"
                
                return {
                    "database_url": self.database_url,
                    "version": version,
                    "connected": self.check_connection()
                }
        except Exception as e:
            logger.error(f"Failed to get database info: {e}")
            return {
                "database_url": self.database_url,
                "version": "Unknown",
                "connected": False,
                "error": str(e)
            }
    
    def close(self):
        """Close the database connection."""
        if self.engine:
            self.engine.dispose()
            logger.info("Database connection closed")


# Global database instance
rbac_database: Optional[RBACDatabase] = None


def get_database() -> RBACDatabase:
    """Get the global database instance."""
    global rbac_database
    if rbac_database is None:
        raise RuntimeError("Database not initialized. Call initialize_database() first.")
    return rbac_database


def initialize_database(database_url: str, echo: bool = False) -> RBACDatabase:
    """Initialize the global database instance."""
    global rbac_database
    rbac_database = RBACDatabase(database_url, echo)
    return rbac_database


def get_db_session() -> Generator[Session, None, None]:
    """Dependency to get a database session."""
    database = get_database()
    with database.get_session_context() as session:
        yield session


# Database event listeners for logging
@event.listens_for(Session, "after_begin")
def receive_after_begin(session, transaction, connection):
    """Log when a transaction begins."""
    logger.debug("Database transaction began")


@event.listens_for(Session, "after_commit")
def receive_after_commit(session):
    """Log when a transaction is committed."""
    logger.debug("Database transaction committed")


@event.listens_for(Session, "after_rollback")
def receive_after_rollback(session):
    """Log when a transaction is rolled back."""
    logger.debug("Database transaction rolled back")


# Database initialization utilities
def initialize_rbac_database(database_url: str, create_tables: bool = True, echo: bool = False) -> RBACDatabase:
    """
    Initialize the RBAC database system.
    
    Args:
        database_url: Database connection URL
        create_tables: Whether to create tables automatically
        echo: Enable SQL query logging
        
    Returns:
        Initialized database instance
    """
    # Initialize database
    database = initialize_database(database_url, echo)
    
    # Create tables if requested
    if create_tables:
        database.create_tables()
    
    # Test connection
    if not database.check_connection():
        raise RuntimeError("Failed to connect to database")
    
    logger.info("RBAC database system initialized successfully")
    return database


def reset_rbac_database(database_url: str, echo: bool = False) -> RBACDatabase:
    """
    Reset the RBAC database (drop and recreate all tables).
    
    Args:
        database_url: Database connection URL
        echo: Enable SQL query logging
        
    Returns:
        Initialized database instance
    """
    # Initialize database
    database = initialize_database(database_url, echo)
    
    # Drop and recreate tables
    database.drop_tables()
    database.create_tables()
    
    # Test connection
    if not database.check_connection():
        raise RuntimeError("Failed to connect to database")
    
    logger.info("RBAC database system reset successfully")
    return database 