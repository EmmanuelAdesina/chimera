# chimera/core/research_gate.py

class DriftGuard:
    """
    Hard limits to prevent research rabbit holes.
    """
    
    MAX_SEARCHES_PER_MISSION = 5
    MAX_TIME_PER_SEARCH = 60
    MAX_PAGES_PER_SEARCH = 3
    MAX_LINK_DEPTH = 0  # NEVER follow links from search results
    
    def __init__(self):
        self.search_count = 0
        self.total_research_time = 0
    
    def allow_search(self) -> bool:
        return self.search_count < self.MAX_SEARCHES_PER_MISSION
    
    def allow_page_fetch(self, url: str) -> bool:
        # Block known time-wasters
        blocked_domains = {
            "stackoverflow.com",  # Too generic, causes drift
            "reddit.com",
            "youtube.com",
            "medium.com",  # Often surface-level
        }
        return not any(d in url for d in blocked_domains)
    
    def enforce_time_box(self, func):
        """Decorator: kill any search after MAX_TIME_PER_SEARCH seconds."""
        import functools
        import signal
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            def timeout_handler(signum, frame):
                raise TimeoutError(f"Search exceeded {self.MAX_TIME_PER_SEARCH}s")
            
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(self.MAX_TIME_PER_SEARCH)
            
            try:
                result = func(*args, **kwargs)
                signal.alarm(0)
                return result
            except TimeoutError:
                return {"error": "TIMEOUT", "partial": True}
        
        return wrapper