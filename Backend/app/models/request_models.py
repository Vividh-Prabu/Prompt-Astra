from pydantic import BaseModel, Field, field_validator

class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="Prompt text to analyze")

    @field_validator("prompt")
    @classmethod
    def prompt_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Prompt cannot be empty or contain only whitespace.")
        return value
