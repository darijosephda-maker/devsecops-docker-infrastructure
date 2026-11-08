FROM alpine:latest
RUN apk add --no-cache python3 py3-pip docker-cli
RUN pip3 install flask flask-cors --break-system-packages
WORKDIR /app
COPY app.py .
EXPOSE 5000
CMD ["python3", "app.py"]
