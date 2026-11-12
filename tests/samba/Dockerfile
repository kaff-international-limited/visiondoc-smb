FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends samba && rm -rf /var/lib/apt/lists/* && useradd fixture && mkdir -p /share/nested && printf 'synthetic test document\n' > /share/first.txt && cp /share/first.txt /share/nested/renamed.txt && chmod -R a+rX /share
COPY smb.conf /etc/samba/smb.conf
COPY start.sh /start.sh
CMD ["sh", "/start.sh"]
