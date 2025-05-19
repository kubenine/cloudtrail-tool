import random
from typing import List, TypeVar, Sequence, Dict, Any, Optional
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
        # Set your custom GPT-4.1 pricing here
        self.model_pricing = {
            "gpt-4.1": {
                "input": 0.002,   # Example: $0.012 per 1K input tokens
                "output": 0.008   # Example: $0.036 per 1K output tokens
            }
        }
    
    def reset(self):
        """Reset token counters for a new query."""
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
        self.current_model = None
    
    def update_from_response(self, response: ChatCompletion):
        """Update token counts from an OpenAI API response."""
        usage = response.usage
        if usage:
            self.prompt_tokens += usage.prompt_tokens
            self.completion_tokens += usage.completion_tokens
            self.total_tokens += usage.total_tokens
            self.current_model = response.model
    
    def get_model_pricing(self) -> Dict[str, float]:
        if not self.current_model:
            return self.model_pricing["gpt-4.1"]
        for model_prefix, pricing in self.model_pricing.items():
            if self.current_model.startswith(model_prefix):
                return pricing
        return self.model_pricing["gpt-4.1"]
    
    def calculate_cost(self) -> Dict[str, float]:
        """Calculate the cost breakdown in USD based on token usage."""
        pricing = self.get_model_pricing()
        input_cost = (self.prompt_tokens / 1000) * pricing["input"]
        output_cost = (self.completion_tokens / 1000) * pricing["output"]
        total_cost = input_cost + output_cost
        
        return {
            "input_cost": input_cost,
            "output_cost": output_cost,
            "total_cost": total_cost
        }
    
    def get_usage_str(self) -> str:
        """Get a formatted string of token usage and cost."""
        costs = self.calculate_cost()
        
        usage_parts = [
            "📊 Token Usage and Cost Breakdown:",
            f"• Input Tokens: {self.prompt_tokens:,} (${costs['input_cost']:.4f})",
            f"• Output Tokens: {self.completion_tokens:,} (${costs['output_cost']:.4f})",
            f"• Total Tokens: {self.total_tokens:,}",
            f"• Total Cost: ${costs['total_cost']:.4f}",
            "\n💰 gpt-4.1 Pricing:",
            f"• Input: ${self.model_pricing['gpt-4.1']['input']} per 1K tokens",
            f"• Output: ${self.model_pricing['gpt-4.1']['output']} per 1K tokens"
        ]
        
        if self.total_tokens > 3000:
            usage_parts.insert(0, "⚠️ High token usage - Results limited to 60 events")
            
        return "\n".join(usage_parts)

# Global token counter instance
token_counter = TokenCounter() 