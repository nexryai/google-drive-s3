/**
 * S3-Compatible API Server on Cloudflare Workers
 * Supports both Header-based and Presigned URL authentication
 */

export default {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        try {
            const isValid = await verifySignature(request, env);
            if (!isValid) {
                return new Response("Invalid Signature", { status: 403 });
            }

            const url = new URL(request.url);
            const method = request.method;

            // ここでバックエンドストレージとの接続処理を実装
            // 例: R2, KV, または外部ストレージへのプロキシ
            
            if (method === "PUT" || method === "POST") {
                // ストリーミングアップロード処理
                // await uploadToBackend(request.body, url.pathname);
                return new Response(`Verified ${method} for ${url.pathname}`, { status: 200 });
            } else if (method === "GET") {
                // ストリーミングダウンロード処理
                // const stream = await downloadFromBackend(url.pathname);
                // return new Response(stream, { status: 200 });
                return new Response(`Verified ${method} for ${url.pathname}`, { status: 200 });
            } else if (method === "DELETE") {
                return new Response(`Verified ${method} for ${url.pathname}`, { status: 204 });
            }

            return new Response("Method not allowed", { status: 405 });
        } catch (e) {
            const error = e as Error;
            console.error("Error:", error);
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

    // Query-based auth (Presigned URL) かどうか判定
    const isQueryAuth = url.searchParams.has("X-Amz-Algorithm");
    
    let algorithm: string;
    if (isQueryAuth) {
        algorithm = url.searchParams.get("X-Amz-Algorithm") ?? "";
    } else {
        const authHeader = headers.get("Authorization") ?? "";
        algorithm = authHeader.split(" ")[0];
    }

    if (!algorithm || !algorithm.includes("AWS4-HMAC-SHA256")) {
        return false;
    }

    // 日時情報の取得
    const datetime = (isQueryAuth 
        ? url.searchParams.get("X-Amz-Date") 
        : headers.get("x-amz-date")) ?? "";
    
    if (!datetime) return false;
    
    const date = datetime.substring(0, 8);

    // Canonical Request の生成
    const canonicalRequest = await createCanonicalRequest(request, isQueryAuth);
    const hashedCanonicalRequest = await sha256(canonicalRequest);

    // String to Sign の生成
    const credentialScope = `${date}/${env.REGION}/s3/aws4_request`;
    const stringToSign = [
        "AWS4-HMAC-SHA256",
        datetime,
        credentialScope,
        hashedCanonicalRequest
    ].join("\n");

    // 署名の計算
    const signingKey = await getSigningKey(env.SECRET_KEY, date, env.REGION, "s3");
    const signature = await hmacSha256(signingKey, stringToSign);
    const signatureHex = bufToHex(signature);

    // 期待される署名の取得
    let expectedSignature = "";
    if (isQueryAuth) {
        expectedSignature = url.searchParams.get("X-Amz-Signature") ?? "";
    } else {
        const authHeader = headers.get("Authorization") ?? "";
        const match = authHeader.match(/Signature=([a-f0-9]+)/);
        expectedSignature = match ? match[1] : "";
    }

    return signatureHex === expectedSignature;
}

async function createCanonicalRequest(request: Request, isQueryAuth: boolean): Promise<string> {
    const url = new URL(request.url);
    
    // HTTPメソッド
    const method = request.method;
    
    // Canonical URI (パス部分)
    const canonicalUri = url.pathname || "/";
    
    // Canonical Query String
    const params = Array.from(url.searchParams.entries())
        .filter(([key]) => key !== "X-Amz-Signature") // 署名自体は除外
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, val]) => `${encodeRFC3986(key)}=${encodeRFC3986(val)}`)
        .join("&");
    
    // Signed Headers の取得
    let signedHeadersList: string[];
    if (isQueryAuth) {
        signedHeadersList = (url.searchParams.get("X-Amz-SignedHeaders") ?? "host").split(";");
    } else {
        const authHeader = request.headers.get("Authorization") ?? "";
        const match = authHeader.match(/SignedHeaders=([^,\s]+)/);
        signedHeadersList = match ? match[1].split(";") : ["host"];
    }
    
    // Canonical Headers の生成
    const canonicalHeaders = signedHeadersList
        .map(h => {
            const headerName = h.toLowerCase();
            let headerValue = "";
            
            if (headerName === "host") {
                // ホストヘッダーはポート番号を除外 (標準ポートの場合)
                const host = url.hostname;
                const port = url.port;
                if ((url.protocol === "https:" && port === "443") || 
                    (url.protocol === "http:" && port === "80") ||
                    !port) {
                    headerValue = host;
                } else {
                    headerValue = `${host}:${port}`;
                }
            } else {
                headerValue = request.headers.get(headerName)?.trim() ?? "";
            }
            
            return `${headerName}:${headerValue}\n`;
        })
        .join("");
    
    const signedHeaders = signedHeadersList.join(";");
    
    // Payload Hash
    const payloadHash = request.headers.get("x-amz-content-sha256") ?? 
                       (isQueryAuth ? "UNSIGNED-PAYLOAD" : "UNSIGNED-PAYLOAD");
    
    return [
        method,
        canonicalUri,
        params,
        canonicalHeaders,
        signedHeaders,
        payloadHash
    ].join("\n");
}

// RFC3986に準拠したURLエンコーディング
function encodeRFC3986(str: string): string {
    return encodeURIComponent(str)
        .replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

async function getSigningKey(
    secret: string,
    date: string,
    region: string,
    service: string
): Promise<ArrayBuffer> {
    const kDate = await hmacSha256("AWS4" + secret, date);
    const kRegion = await hmacSha256(kDate, region);
    const kService = await hmacSha256(kRegion, service);
    return await hmacSha256(kService, "aws4_request");
}

async function hmacSha256(
    key: string | ArrayBuffer,
    data: string
): Promise<ArrayBuffer> {
    const keyData = typeof key === "string" ? new TextEncoder().encode(key) : key;
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyData,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );
    return await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(data));
}

async function sha256(data: string): Promise<string> {
    const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
    return bufToHex(hash);
}

function bufToHex(buf: ArrayBuffer): string {
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}