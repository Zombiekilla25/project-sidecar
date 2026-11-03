import random
class ReconnectPolicy:
    def __init__(self, minimum=1.0, maximum=30.0, jitter=0.1): self.minimum=minimum; self.maximum=maximum; self.jitter=jitter; self.attempt=0
    def next_delay(self):
        base=min(self.maximum,self.minimum*(2**self.attempt)); self.attempt+=1
        return base*random.uniform(1-self.jitter,1+self.jitter)
    def reset(self): self.attempt=0
