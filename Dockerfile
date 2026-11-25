FROM apache/apisix:3.21.0-ubuntu

COPY plugins/wasm/query-param-filter/*.wasm /usr/local/apisix/plugins/wasm/
COPY plugins/wasm/secure-urls/*.wasm /usr/local/apisix/plugins/wasm/