FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends tar curl iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Only the application + its views ship in the image (NOT the answer key).
COPY app.py /app/app.py
COPY templates /app/templates
COPY static /app/static

# An internal credential present in the process environment (RCE/LFI/SSRF prize).
ENV INTERNAL_API_KEY=ik_live_9f3c7a2b1e8d4c6f_soc

EXPOSE 5004
CMD ["python", "app.py"]
