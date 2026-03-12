(() => {
    if (!window.HC) {
        return;
    }

    const btn = document.getElementById('hc_btn');
    const stampEl = document.getElementById('hc_stamp');
    const form = document.getElementById('hc');
    if (!btn || !stampEl || !form) {
        return;
    }

    const toHex = (b) => Array.from(new Uint8Array(b)).map((x) => x.toString(16).padStart(2, '0')).join('');
    const sha1 = async (s) => toHex(await crypto.subtle.digest('SHA-1', new TextEncoder().encode(s)));
    const leadingZeroBits = (hex) => {
        let bits = 0;
        for (let i = 0; i < hex.length; i += 1) {
            const n = parseInt(hex[i], 16);
            if (n === 0) {
                bits += 4;
                continue;
            }
            if (n >= 8) return bits;
            if (n >= 4) return bits + 1;
            if (n >= 2) return bits + 2;
            return bits + 3;
        }
        return bits;
    };

    const randB64 = () => {
        const bytes = new Uint8Array(8);
        crypto.getRandomValues(bytes);
        return btoa(String.fromCharCode(...bytes)).replace(/=+$/g, '');
    };

    const counterB64 = (n) => btoa(String.fromCharCode(...String(n))).replace(/=+$/g, '');

    const dateStamp = () => {
        const d = new Date();
        const yy = String(d.getUTCFullYear()).slice(-2);
        const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
        const dd = String(d.getUTCDate()).padStart(2, '0');
        const hh = String(d.getUTCHours()).padStart(2, '0');
        const mi = String(d.getUTCMinutes()).padStart(2, '0');
        const ss = String(d.getUTCSeconds()).padStart(2, '0');
        return `${yy}${mm}${dd}${hh}${mi}${ss}`;
    };

    btn.onclick = async () => {
        btn.disabled = true;
        btn.textContent = 'Working...';
        const bits = Number(window.HC.bits || 20);
        const resource = String(window.HC.resource || '');
        const date = dateStamp();
        const rand = randB64();
        let counter = 0;
        while (true) {
            const stamp = `1:${bits}:${date}:${resource}::${rand}:${counterB64(counter)}`;
            const hash = await sha1(stamp);
            if (leadingZeroBits(hash) >= bits) {
                stampEl.value = stamp;
                form.submit();
                break;
            }
            counter += 1;
            if (counter % 200 === 0) {
                await new Promise((r) => setTimeout(r, 0));
            }
        }
    };
})();
