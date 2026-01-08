/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.jsonc`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

export default {
    async fetch(request: Request, env: Env, ctx: ExecutionContext<unknown>): Promise<Response> {
        try {
            const isValid = await verifySignature(request, env);
            if (!isValid) {
                return new Response("Invalid Signature", { status: 403 });
            }

            const url = new URL(request.url);
            const method = request.method;

            // メモリ節約のためにReadableStream
            return new Response(`Verified ${method} for ${url.pathname}`, { status: 200 });
        } catch (e) {
            const error = e as Error;
            return new Response(error.message, { status: 500 });
        }
    },
} satisfies ExportedHandler<Env>;

interface Env {
    ACCESS_KEY: string;
    SECRET_KEY: string;
    REGION: string;
}

async function verifySignature(request: Request, env: Env): Promise<boolean> {
    const url = new URL(request.url);
    const headers = request.headers;

    const isQueryAuth = url.searchParams.has("X-Amz-Algorithm");
    const authHeader = headers.get("Authorization") ?? "";
    const algorithm = isQueryAuth ? url.searchParams.get("X-Amz-Algorithm") : authHeader.split(" ")[0];

    if (!algorithm || !algorithm.includes("AWS4-HMAC-SHA256")) return false;

    const datetime = (isQueryAuth ? url.searchParams.get("X-Amz-Date") : headers.get("x-amz-date")) ?? "";
    const date = datetime.substring(0, 8);

    const canonicalRequest = await createCanonicalRequest(request, isQueryAuth);
    const hashedCanonicalRequest = await sha256(canonicalRequest);

    const credentialScope = `${date}/${env.REGION}/s3/aws4_request`;
    const stringToSign = ["AWS4-HMAC-SHA256", datetime, credentialScope, hashedCanonicalRequest].join("\n");

    const signingKey = await getSigningKey(env.SECRET_KEY, date, env.REGION, "s3");
    const signature = await hmacSha256(signingKey, stringToSign);
    const signatureHex = bufToHex(signature);

    let expectedSignature = "";
    if (isQueryAuth) {
        expectedSignature = url.searchParams.get("X-Amz-Signature") ?? "";
    } else {
        const match = authHeader.match(/Signature=([a-f0-9]+)/);
        expectedSignature = match ? match[1] : "";
    }

    return signatureHex === expectedSignature;
}

async function createCanonicalRequest(request: Request, isQueryAuth: boolean): Promise<string> {
    const url = new URL(request.url);

    const searchParams = Array.from(url.searchParams.entries())
        .filter(([key]) => key !== "X-Amz-Signature")
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, val]) => `${encodeURIComponent(key)}=${encodeURIComponent(val)}`)
        .join("&");

    let signedHeadersList: string[] = [];
    if (isQueryAuth) {
        signedHeadersList = (url.searchParams.get("X-Amz-SignedHeaders") ?? "host").split(";");
    } else {
        const authHeader = request.headers.get("Authorization") ?? "";
        const match = authHeader.match(/SignedHeaders=([^,]+)/);
        signedHeadersList = match ? match[1].split(";") : ["host"];
    }

    const canonicalHeaders = signedHeadersList.map((h) => `${h}:${request.headers.get(h)?.trim() ?? ""}\n`).join("");

    const signedHeaders = signedHeadersList.join(";");
    const payloadHash = request.headers.get("x-amz-content-sha256") ?? "UNSIGNED-PAYLOAD";

    return [request.method, url.pathname, searchParams, canonicalHeaders, signedHeaders, payloadHash].join("\n");
}

async function getSigningKey(secret: string, date: string, region: string, service: string): Promise<ArrayBuffer> {
    const kDate = await hmacSha256("AWS4" + secret, date);
    const kRegion = await hmacSha256(kDate, region);
    const kService = await hmacSha256(kRegion, service);
    return await hmacSha256(kService, "aws4_request");
}

async function hmacSha256(key: string | ArrayBuffer, data: string): Promise<ArrayBuffer> {
    const keyData = typeof key === "string" ? new TextEncoder().encode(key) : key;
    const cryptoKey = await crypto.subtle.importKey("raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(data));
}

async function sha256(data: string): Promise<string> {
    const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
    return bufToHex(hash);
}

function bufToHex(buf: ArrayBuffer): string {
    return Array.from(new Uint8Array(buf))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}
