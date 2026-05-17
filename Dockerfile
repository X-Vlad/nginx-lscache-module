FROM ubuntu:24.04

ARG NGINX_VERSION=1.30.1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcre2-dev \
    libpcre3-dev \
    zlib1g-dev \
    libssl-dev \
    wget \
    curl \
    apache2-utils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download and extract nginx source
RUN wget -q https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
    && tar xzf nginx-${NGINX_VERSION}.tar.gz \
    && rm nginx-${NGINX_VERSION}.tar.gz

# Copy module source
COPY *.c *.h config /module/

# Build nginx with module
RUN cd /nginx-${NGINX_VERSION} \
    && ./configure \
        --with-compat \
        --with-http_ssl_module \
        --with-http_realip_module \
        --add-dynamic-module=/module \
    && make -j$(nproc) modules \
    && make -j$(nproc) \
    && make install

# Install module
RUN mkdir -p /usr/local/nginx/modules \
    && cp /nginx-${NGINX_VERSION}/objs/ngx_http_lscache_module.so \
          /usr/local/nginx/modules/

# Cache root used by the test config (lscache_path).
# Use explicit args (not brace expansion) because Ubuntu's /bin/sh is dash.
RUN mkdir -p /var/cache/nginx/lscache/data \
             /var/cache/nginx/lscache/tags \
             /var/cache/nginx/lscache/hosts \
             /var/cache/nginx/lscache/vary \
             /var/cache/nginx/lscache/tmp \
    && rm -rf '/var/cache/nginx/lscache/{data,tags,hosts,vary,tmp}' \
    && chown -R nobody:nogroup /var/cache/nginx/lscache

# Copy test files
COPY t/ /tests/t/

RUN chmod +x /tests/t/run_tests.sh /tests/t/helpers.sh /tests/t/*.t.sh \
        2>/dev/null || true

WORKDIR /tests

ENV NGINX_BIN=/usr/local/nginx/sbin/nginx
ENV NGINX_PREFIX=/usr/local/nginx

EXPOSE 8181

CMD ["/tests/t/run_tests.sh"]
