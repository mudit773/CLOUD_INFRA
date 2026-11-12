FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY ast_extractor.py converter.py findings_generator.py main.py parser.py relationships_extractor.py schema_validator.py security_analyzer.py llm_service.py server.py ./
COPY input/terraform ./input/terraform

RUN mkdir -p /app/input/uploads /app/output

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
