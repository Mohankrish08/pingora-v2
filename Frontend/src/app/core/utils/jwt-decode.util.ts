export interface DecodedJwtOuter {
    enc?: string;
    claims?: Record<string, any>;
    jti: string;
    exp: number;
}

export function decodeJwtPayload(token: string): DecodedJwtOuter | null {
    try {
        const payloadSegment = token.split('.')[1];
        if (!payloadSegment) return null;

        const base64 = payloadSegment.replace(/-/g, '+').replace(/_/g, '/');
        const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
        const json = decodeURIComponent(
            atob(padded)
            .split('')
            .map(c => '%' + c.charCodeAt(0).toString(16).padStart(2, '0'))
            .join('')
        )
        return JSON.parse(json);
    } catch {
        return null;
    }
}