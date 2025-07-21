
import os
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, DateTime
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
from sqlalchemy.sql import func
from dotenv import load_dotenv
import logging

# It's good practice to load environment variables at the start
load_dotenv()

logger = logging.getLogger(__name__)

# --- Database Connection Setup ---
# Reads connection details from environment variables
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "password")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "vulnprism_sast")

DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

try:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base = declarative_base()
    logger.info("Successfully connected to the database.")
except Exception as e:
    logger.error("Failed to connect to the database: %s", e, exc_info=True)
    # Exit or handle gracefully if the database connection is critical for startup
    engine = None
    SessionLocal = None
    Base = object # Fallback to a plain object if Base cannot be created

# --- SQLAlchemy Models ---
# Defines the structure of the database tables

if Base is not object:
    class Scan(Base):
        __tablename__ = "scans"
        id = Column(Integer, primary_key=True, index=True)
        scan_id = Column(String, unique=True, index=True, default=lambda: str(uuid.uuid4()))
        target = Column(String, index=True) # e.g., git URL or filename
        status = Column(String, default="completed")
        created_at = Column(DateTime(timezone=True), server_default=func.now())
        
        vulnerabilities = relationship("Vulnerability", back_populates="scan")

    class Vulnerability(Base):
        __tablename__ = "vulnerabilities"
        id = Column(Integer, primary_key=True, index=True)
        rule = Column(String, index=True)
        description = Column(Text)
        impact = Column(String)
        fix = Column(Text)
        file = Column(String)
        line = Column(String) # Using String to accommodate 'N/A'
        severity = Column(String, index=True)
        risk_score = Column(Integer)
        
        scan_id = Column(Integer, ForeignKey("scans.id"))
        scan = relationship("Scan", back_populates="vulnerabilities")

    def init_db():
        """Creates all tables in the database."""
        try:
            Base.metadata.create_all(bind=engine)
            logger.info("Database tables initialized successfully.")
        except Exception as e:
            logger.error("Could not initialize database tables: %s", e)

else:
    def init_db():
        logger.error("Cannot initialize DB models because database connection failed.")

# --- Database Interaction Functions ---
def get_db():
    """Provides a database session for a single request."""
    if not SessionLocal:
        return None
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
