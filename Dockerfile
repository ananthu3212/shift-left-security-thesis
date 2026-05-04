FROM python:3.8.5-buster

WORKDIR /app

COPY requirements.txt .

RUN python3 -m venv .venv \
    && . .venv/bin/activate \
    && pip install --upgrade setuptools wheel \
    && pip install -r requirements.txt

COPY . /app/

EXPOSE 5000

CMD [".venv/bin/python", "-m", "flask", "run", "--host=0.0.0.0"]
