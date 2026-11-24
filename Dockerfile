FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    TZ=Asia/Shanghai

# 零第三方依赖，只需要标准库
COPY proxy-check.py core.py server.py ./
COPY static ./static

RUN mkdir -p /app/data

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8787/health',timeout=4).status==200 else 1)"

CMD ["python3", "server.py", "--bind", "0.0.0.0", "--port", "8787"]
