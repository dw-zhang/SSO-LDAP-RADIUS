FROM python:3.12-alpine
# docker CLI + compose 插件：供面板「LDAP 对接」页重建 RADIUS 容器（依赖挂载的 docker.sock）
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk add --no-cache docker-cli docker-cli-compose
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    -i https://pypi.tuna.tsinghua.edu.cn/simple
COPY app.py .
COPY dictionary .
COPY templates/ templates/
ENV PORT=8082
EXPOSE 8082
CMD ["python", "app.py"]
