import random
from typing import List, TypeVar, Sequence, Dict, Any
from openai.types.chat import ChatCompletion

T = TypeVar('T')

def sample_events(events: Sequence[T], max_samples: int = 60) -> List[T]:
    """
    Randomly sample events from a sequence, returning at most max_samples events.
    
    Args:
        events (Sequence[T]): A sequence of events to sample from
        max_samples (int): Maximum number of events to return, defaults to 60
        
    Returns:
        List[T]: A list containing randomly sampled events, with length min(len(events), max_samples)
    """
    if not events:
        return []
        
    num_samples = min(len(events), max_samples)
    return random.sample(list(events), num_samples)

class TokenCounter:
    def __init__(self):
        self.reset()
    
    def reset(self):
        """Reset token counters for a new query."""
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
    
    def update_from_response(self, response: ChatCompletion):
        """Update token counts from an OpenAI API response."""
        usage = response.usage
        if usage:
            self.prompt_tokens += usage.prompt_tokens
            self.completion_tokens += usage.completion_tokens
            self.total_tokens += usage.total_tokens
    
    def get_usage_str(self) -> str:
        """Get a formatted string of token usage."""
        return f"Tokens used: {self.total_tokens} total (Prompt: {self.prompt_tokens}, Completion: {self.completion_tokens})"

# Global token counter instance
token_counter = TokenCounter() 