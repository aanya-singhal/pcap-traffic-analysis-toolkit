# App image: Python + TShark, so the receiver can both run the dashboard and
# capture its own interface for the live demo.
FROM python:3.11-slim

# TShark (from the tshark package) is needed by PyShark for both file parsing
# and live capture. DEBIAN_FRONTEND avoids the interactive "should dumpcap be
# usable by non-root?" prompt; we run as root in the container so it's moot.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Bind to all interfaces inside the container; debug off for the demo.
ENV HOST=0.0.0.0 \
    PORT=5001 \
    FLASK_DEBUG=0

EXPOSE 5001
CMD ["python", "app.py"]
