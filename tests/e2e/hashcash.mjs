import { createHash, randomBytes } from 'node:crypto';

export function parseChallenge(html) {
    const match = html.match(/window\.HC=(\{.+?\});/s);

    if (match === null) {
        throw new Error('Challenge configuration was not found in the response.');
    }

    return JSON.parse(match[1]);
}

export function solveChallenge(challenge, now = new Date()) {
    const date = [
        String(now.getUTCFullYear()).slice(-2),
        String(now.getUTCMonth() + 1).padStart(2, '0'),
        String(now.getUTCDate()).padStart(2, '0'),
        String(now.getUTCHours()).padStart(2, '0'),
        String(now.getUTCMinutes()).padStart(2, '0'),
        String(now.getUTCSeconds()).padStart(2, '0'),
    ].join('');
    const random = randomBytes(12).toString('base64').replace(/=+$/u, '');

    for (let counter = 0; ; counter += 1) {
        const encodedCounter = Buffer.from(String(counter)).toString('base64').replace(/=+$/u, '');
        const stamp = [
            '1',
            String(challenge.bits),
            date,
            challenge.resource,
            challenge.token,
            random,
            encodedCounter,
        ].join(':');
        const digest = createHash('sha1').update(stamp).digest();

        if (leadingZeroBits(digest) >= challenge.bits) {
            return stamp;
        }
    }
}

function leadingZeroBits(buffer) {
    let bits = 0;

    for (const byte of buffer) {
        if (byte === 0) {
            bits += 8;
            continue;
        }

        return bits + Math.clz32(byte) - 24;
    }

    return bits;
}
