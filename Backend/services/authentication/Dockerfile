FROM python:3.12-slim

WORKDIR /app

# Step 1: bring in common-helpers first
COPY common-helpers/ /app/common-helpers/
RUN pip install --no-cache-dir /app/common-helpers

# Step 2: bring in this service's code
COPY services/authentication/ /app/

# Step 3: install this service's own dependencies
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]