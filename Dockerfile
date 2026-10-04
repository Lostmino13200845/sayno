# SAYNO public server. Build: docker build -t sayno .   Run: docker run -p 8765:8765 sayno
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 SAYNO_PUBLIC=1 PORT=8765
RUN useradd --create-home --uid 10001 sayno
WORKDIR /app
COPY --chown=sayno:sayno server ./server
COPY --chown=sayno:sayno static ./static
COPY --chown=sayno:sayno config.example.json ./config.example.json
USER sayno
EXPOSE 8765
HEALTHCHECK --interval=60s --timeout=5s CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8765')+'/healthz',timeout=4)"
CMD ["python", "server/app.py"]
