import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    
    TIGERGRAPH_HOST = os.getenv("TIGERGRAPH_HOST")
    TIGERGRAPH_USERNAME = os.getenv("TIGERGRAPH_USERNAME")
    TIGERGRAPH_PASSWORD = os.getenv("TIGERGRAPH_PASSWORD")
    TIGERGRAPH_GRAPHNAME = os.getenv("TIGERGRAPH_GRAPHNAME")
    TIGERGRAPH_SECRET = os.getenv("TIGERGRAPH_SECRET") 
    

    GROQ_API_KEY = os.getenv("GROQ_API_KEY")
    
 
    
    # Simulation defaults
    REDTEAM_ITERATIONS = 100
    MAX_PATH_LENGTH = 5