import net from 'node:net';

export class RedisClient {
    constructor({ host = '127.0.0.1', port = 6379 } = {}) {
        this.host = host;
        this.port = port;
    }

    command(...arguments_) {
        const payload = encodeCommand(arguments_);

        return new Promise((resolve, reject) => {
            const socket = net.createConnection({ host: this.host, port: this.port });
            let response = Buffer.alloc(0);

            socket.setTimeout(5_000);
            socket.on('connect', () => socket.write(payload));
            socket.on('data', (chunk) => {
                response = Buffer.concat([response, chunk]);

                try {
                    const parsed = parseValue(response, 0);

                    if (parsed !== null) {
                        socket.end();
                        resolve(parsed.value);
                    }
                } catch (error) {
                    socket.destroy();
                    reject(error);
                }
            });
            socket.on('timeout', () => socket.destroy(new Error('Redis command timed out.')));
            socket.on('error', reject);
        });
    }
}

function encodeCommand(arguments_) {
    const chunks = [Buffer.from(`*${arguments_.length}\r\n`)];

    for (const argument of arguments_) {
        const value = Buffer.from(String(argument));
        chunks.push(Buffer.from(`$${value.length}\r\n`), value, Buffer.from('\r\n'));
    }

    return Buffer.concat(chunks);
}

function parseValue(buffer, offset) {
    if (offset >= buffer.length) {
        return null;
    }

    const prefix = String.fromCharCode(buffer[offset]);
    const line = readLine(buffer, offset + 1);

    if (line === null) {
        return null;
    }

    if (prefix === '+') {
        return { value: line.value, offset: line.offset };
    }

    if (prefix === '-') {
        throw new Error(`Redis error: ${line.value}`);
    }

    if (prefix === ':') {
        return { value: Number(line.value), offset: line.offset };
    }

    if (prefix === '$') {
        const length = Number(line.value);

        if (length === -1) {
            return { value: null, offset: line.offset };
        }

        if (buffer.length < line.offset + length + 2) {
            return null;
        }

        return {
            value: buffer.subarray(line.offset, line.offset + length).toString('utf8'),
            offset: line.offset + length + 2,
        };
    }

    if (prefix === '*') {
        const length = Number(line.value);
        const values = [];
        let itemOffset = line.offset;

        for (let index = 0; index < length; index += 1) {
            const item = parseValue(buffer, itemOffset);

            if (item === null) {
                return null;
            }

            values.push(item.value);
            itemOffset = item.offset;
        }

        return { value: values, offset: itemOffset };
    }

    throw new Error(`Unsupported Redis response prefix: ${prefix}`);
}

function readLine(buffer, offset) {
    const end = buffer.indexOf('\r\n', offset);

    if (end === -1) {
        return null;
    }

    return {
        value: buffer.subarray(offset, end).toString('utf8'),
        offset: end + 2,
    };
}
