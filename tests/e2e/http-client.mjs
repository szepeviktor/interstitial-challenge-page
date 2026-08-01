import http from 'node:http';

export class HttpClient {
    constructor({ hostname = '127.0.0.1', port, authority = `localhost:${port}` }) {
        this.hostname = hostname;
        this.port = port;
        this.authority = authority;
    }

    request({
        method = 'GET',
        path = '/',
        headers = {},
        body = '',
        timeout = 10_000,
    } = {}) {
        const payload = Buffer.isBuffer(body) ? body : Buffer.from(body);
        const requestHeaders = {
            Host: this.authority,
            Connection: 'close',
            ...headers,
        };

        if (payload.length > 0 && !hasHeader(requestHeaders, 'content-length')) {
            requestHeaders['Content-Length'] = String(payload.length);
        }

        return new Promise((resolve, reject) => {
            const request = http.request({
                hostname: this.hostname,
                port: this.port,
                method,
                path,
                headers: requestHeaders,
                agent: false,
                timeout,
                joinDuplicateHeaders: false,
            }, (response) => {
                const chunks = [];

                response.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
                response.on('end', () => {
                    resolve({
                        status: response.statusCode ?? 0,
                        headers: normalizeHeaders(response.headers),
                        rawHeaders: response.rawHeaders,
                        body: Buffer.concat(chunks),
                        text: Buffer.concat(chunks).toString('utf8'),
                    });
                });
            });

            request.on('timeout', () => request.destroy(new Error(`Request timed out after ${timeout} ms`)));
            request.on('error', reject);

            if (payload.length > 0) {
                request.write(payload);
            }

            request.end();
        });
    }
}

export function formBody(values) {
    return new URLSearchParams(values).toString();
}

export function firstCookie(response, name) {
    for (const value of response.headers['set-cookie'] ?? []) {
        const pair = value.split(';', 1)[0];

        if (pair.startsWith(`${name}=`)) {
            return pair;
        }
    }

    return '';
}

function hasHeader(headers, expectedName) {
    return Object.keys(headers).some((name) => name.toLowerCase() === expectedName);
}

function normalizeHeaders(headers) {
    const normalized = {};

    for (const [name, value] of Object.entries(headers)) {
        normalized[name] = Array.isArray(value) ? value : [String(value)];
    }

    return normalized;
}
