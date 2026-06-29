FROM python:3.8.5-buster

# Application code lives here and stays read-only at runtime.
WORKDIR /app

COPY requirements.txt .

RUN python3 -m venv .venv \
    && . .venv/bin/activate \
    && pip install --upgrade setuptools wheel \
    && pip install -r requirements.txt

COPY . /app/

# Create the non-root runtime user (UID/GID 10001) and a writable
# data directory it owns. The application writes its SQLite database
# (relative path "database.db") into the working directory, so the
# working directory is set to this owned, writable location while the
# code remains under /app and is reached via PYTHONPATH.
RUN groupadd -g 10001 appuser \
    && useradd -u 10001 -g 10001 -m appuser \
    && mkdir -p /data \
    && chown -R 10001:10001 /data

ENV PYTHONPATH=/app

WORKDIR /data

EXPOSE 5000

# Absolute path to the venv interpreter, because the working
# directory is now /data, not /app.
CMD ["/app/.venv/bin/python", "-m", "flask", "run", "--host=0.0.0.0"]