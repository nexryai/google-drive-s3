/**
 * S3-Compatible API Server on Cloudflare Workers
 * Backend: Google Drive with streaming support
 */

export default {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        try {
            if (request.method === "OPTIONS") {
                return new Response(null, { status: 204 });
            }

            const url = new URL(request.url);
            const method = request.method;

            // パスからバケット名とオブジェクトキーを抽出
            const pathParts = url.pathname.split("/").filter((p) => p);
            const bucket = pathParts[0] || "";
            const objectKey = pathParts.slice(1).join("/");

            if (!isValidPath(bucket, objectKey)) {
                return new Response("Invalid path", { status: 400 });
            }

            if (!isAllowedBucket(bucket, env)) {
                return new Response("Access denied to this bucket", { status: 403 });
            }

            const isValid = await verifySignature(request, env);
            if (!isValid) {
                return new Response("Invalid Signature", { status: 403 });
            }

            const accessToken = await getAccessToken(env);

            if (method === "PUT" || method === "POST") {
                // ストリーミングアップロード
                if (!objectKey) {
                    return new Response("Object key required", { status: 400 });
                }

                const contentType = request.headers.get("Content-Type") || "application/octet-stream";
                const result = await streamUploadToDrive(accessToken, request.body, bucket, objectKey, contentType, env);

                return new Response(JSON.stringify(result), {
                    status: 200,
                    headers: {
                        "Content-Type": "application/json",
                        ETag: `"${result.id}"`, // Google DriveのファイルIDをETagとして使用
                    },
                });
            } else if (method === "GET") {
                // ストリーミングダウンロード
                if (!objectKey) {
                    // バケット（フォルダ）の一覧を返す
                    const files = await listFiles(accessToken, bucket, env);
                    return new Response(generateListBucketResult(files, bucket), {
                        status: 200,
                        headers: { "Content-Type": "application/xml" },
                    });
                }

                try {
                    const fileStream = await streamDownloadFromDrive(accessToken, bucket, objectKey, env);

                    return new Response(fileStream.body, {
                        status: 200,
                        headers: {
                            "Content-Type": fileStream.contentType,
                            "Content-Length": fileStream.size.toString(),
                            ETag: `"${fileStream.id}"`,
                        },
                    });
                } catch (e) {
                    const error = e as Error;
                    if (error.message === "File not found") {
                        return new Response("NoSuchKey", { status: 404 });
                    }
                    throw e;
                }
            } else if (method === "DELETE") {
                // ファイル削除
                if (!objectKey) {
                    return new Response("Object key required", { status: 400 });
                }

                try {
                    await deleteFromDrive(accessToken, bucket, objectKey, env);
                    return new Response(null, { status: 204 });
                } catch (e) {
                    const error = e as Error;
                    if (error.message === "File not found") {
                        return new Response(null, { status: 404 });
                    }
                    throw e;
                }
            } else if (method === "HEAD") {
                // メタデータ取得
                if (!objectKey) {
                    return new Response(null, { status: 400 });
                }

                try {
                    const metadata = await getFileMetadata(accessToken, bucket, objectKey, env);
                    return new Response(null, {
                        status: 200,
                        headers: {
                            "Content-Type": metadata.mimeType,
                            "Content-Length": metadata.size.toString(),
                            ETag: `"${metadata.id}"`,
                        },
                    });
                } catch (e) {
                    const error = e as Error;
                    if (error.message === "File not found") {
                        return new Response(null, { status: 404 });
                    }
                    throw e;
                }
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
    GOOGLE_CLIENT_ID: string;
    GOOGLE_CLIENT_SECRET: string;
    GOOGLE_REFRESH_TOKEN: string;
    AUTH_KV: KVNamespace;
    FOLDER_CACHE: KVNamespace;
    ALLOWED_BUCKETS?: string;
}

interface GoogleDriveFile {
    id: string;
    name: string;
    mimeType: string;
    size: string;
    modifiedTime?: string;
}

interface GoogleDriveSearchResponse {
    files?: GoogleDriveFile[];
}

// ========================================
// Security Functions
// ========================================

function isValidPath(bucket: string, objectKey: string): boolean {
    // バケット名の検証
    if (!bucket || bucket.includes("..") || bucket.includes("/") || bucket.includes("\\")) {
        return false;
    }

    // オブジェクトキーの検証
    if (objectKey) {
        // ".." を含むパスを拒否
        if (objectKey.includes("..")) {
            return false;
        }

        // バックスラッシュを含むパスを拒否 (Windowsスタイルのパス)
        if (objectKey.includes("\\")) {
            return false;
        }

        // 絶対パスを拒否
        if (objectKey.startsWith("/")) {
            return false;
        }

        // パスの各コンポーネントを検証
        const parts = objectKey.split("/");
        for (const part of parts) {
            // 空のコンポーネントや "." を拒否
            if (!part || part === "." || part === "..") {
                return false;
            }

            // NULLバイトを拒否
            if (part.includes("\0")) {
                return false;
            }
        }
    }

    return true;
}

function isAllowedBucket(bucket: string, env: Env): boolean {
    console.log(bucket);
    // 許可リストが設定されていない場合はすべて拒否
    if (!env.ALLOWED_BUCKETS) {
        return false;
    }

    const allowedBuckets = env.ALLOWED_BUCKETS.split(",")
        .map((b) => b.trim())
        .filter((b) => b);

    // 空の許可リストの場合もすべて拒否
    if (allowedBuckets.length === 0) {
        return false;
    }

    // バケット名が許可リストに含まれているかチェック
    return allowedBuckets.includes(bucket);
}

// ========================================
// Google Drive API Functions
// ========================================

async function getAccessToken(env: Env): Promise<string> {
    const cacheKey = "google_access_token";

    const cachedToken = await env.AUTH_KV.get(cacheKey);
    if (cachedToken) {
        return cachedToken;
    }

    const response = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
            client_id: env.GOOGLE_CLIENT_ID,
            client_secret: env.GOOGLE_CLIENT_SECRET,
            refresh_token: env.GOOGLE_REFRESH_TOKEN,
            grant_type: "refresh_token",
        }),
    });

    const data: any = await response.json();
    if (!response.ok) {
        throw new Error(`Token Error: ${data.error_description}`);
    }

    await env.AUTH_KV.put(cacheKey, data.access_token, {
        expirationTtl: data.expires_in - 60,
    });

    return data.access_token;
}

async function getOrCreateFolder(accessToken: string, folderName: string, env: Env): Promise<string> {
    // キャッシュを確認
    const cached = await env.FOLDER_CACHE.get(folderName);
    if (cached) return cached;

    // フォルダを検索
    const searchRes = await fetch(`https://www.googleapis.com/drive/v3/files?q=name='${encodeURIComponent(folderName)}' and mimeType='application/vnd.google-apps.folder' and trashed=false`, {
        headers: { Authorization: `Bearer ${accessToken}` },
    });

    const searchData: GoogleDriveSearchResponse = await searchRes.json();

    if (searchData.files && searchData.files.length > 0) {
        const folderId = searchData.files[0].id;
        await env.FOLDER_CACHE.put(folderName, folderId, { expirationTtl: 3600 });
        return folderId;
    }

    // フォルダが存在しない場合は作成
    const createRes = await fetch("https://www.googleapis.com/drive/v3/files", {
        method: "POST",
        headers: {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            name: folderName,
            mimeType: "application/vnd.google-apps.folder",
        }),
    });

    const createData: any = await createRes.json();
    await env.FOLDER_CACHE.put(folderName, createData.id, { expirationTtl: 3600 });
    return createData.id;
}

async function streamUploadToDrive(accessToken: string, stream: ReadableStream | null, bucket: string, objectKey: string, mimeType: string, env: Env): Promise<any> {
    if (!stream) {
        throw new Error("Request body is required");
    }

    // バケット名に対応するフォルダIDを取得
    const folderId = await getOrCreateFolder(accessToken, bucket, env);

    // Resumable uploadの初期化
    const initRes = await fetch("https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable", {
        method: "POST",
        headers: {
            Authorization: `Bearer ${accessToken}`,
            "X-Upload-Content-Type": mimeType,
            "Content-Type": "application/json; charset=UTF-8",
        },
        body: JSON.stringify({
            name: objectKey,
            parents: [folderId],
        }),
    });

    const uploadUrl = initRes.headers.get("Location");
    if (!uploadUrl) {
        throw new Error("Failed to get upload URL");
    }

    // ストリーミングアップロード
    const uploadRes = await fetch(uploadUrl, {
        method: "PUT",
        headers: {
            Authorization: `Bearer ${accessToken}`,
        },
        body: stream,
        duplex: "half",
    } as RequestInit);

    if (!uploadRes.ok) {
        const errorText = await uploadRes.text();
        throw new Error(`Upload failed: ${errorText}`);
    }

    return await uploadRes.json();
}

async function findFileInFolder(accessToken: string, folderId: string, fileName: string): Promise<GoogleDriveFile | null> {
    const searchRes = await fetch(`https://www.googleapis.com/drive/v3/files?q=name='${encodeURIComponent(fileName)}' and '${folderId}' in parents and trashed=false&fields=files(id,name,mimeType,size)`, {
        headers: { Authorization: `Bearer ${accessToken}` },
    });

    const data: GoogleDriveSearchResponse = await searchRes.json();
    return data.files && data.files.length > 0 ? data.files[0] : null;
}

async function streamDownloadFromDrive(accessToken: string, bucket: string, objectKey: string, env: Env): Promise<{ body: ReadableStream; contentType: string; size: number; id: string }> {
    const folderId = await getOrCreateFolder(accessToken, bucket, env);
    const file = await findFileInFolder(accessToken, folderId, objectKey);

    if (!file) {
        throw new Error("File not found");
    }

    const downloadRes = await fetch(`https://www.googleapis.com/drive/v3/files/${file.id}?alt=media`, {
        headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!downloadRes.ok) {
        throw new Error("Download failed");
    }

    return {
        body: downloadRes.body!,
        contentType: file.mimeType || "application/octet-stream",
        size: parseInt(file.size || "0"),
        id: file.id,
    };
}

async function deleteFromDrive(accessToken: string, bucket: string, objectKey: string, env: Env): Promise<void> {
    const folderId = await getOrCreateFolder(accessToken, bucket, env);
    const file = await findFileInFolder(accessToken, folderId, objectKey);

    if (!file) {
        throw new Error("File not found");
    }

    const deleteRes = await fetch(`https://www.googleapis.com/drive/v3/files/${file.id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!deleteRes.ok) {
        throw new Error("Delete failed");
    }
}

async function getFileMetadata(accessToken: string, bucket: string, objectKey: string, env: Env): Promise<{ id: string; mimeType: string; size: number }> {
    const folderId = await getOrCreateFolder(accessToken, bucket, env);
    const file = await findFileInFolder(accessToken, folderId, objectKey);

    if (!file) {
        throw new Error("File not found");
    }

    return {
        id: file.id,
        mimeType: file.mimeType || "application/octet-stream",
        size: parseInt(file.size || "0"),
    };
}

async function listFiles(accessToken: string, bucket: string, env: Env): Promise<GoogleDriveFile[]> {
    const folderId = await getOrCreateFolder(accessToken, bucket, env);

    const listRes = await fetch(`https://www.googleapis.com/drive/v3/files?q='${folderId}' in parents and trashed=false&fields=files(id,name,mimeType,size,modifiedTime)`, {
        headers: { Authorization: `Bearer ${accessToken}` },
    });

    const data: GoogleDriveSearchResponse = await listRes.json();
    return data.files || [];
}

function generateListBucketResult(files: any[], bucket: string): string {
    const contents = files
        .map(
            (f) => `
    <Contents>
        <Key>${escapeXml(f.name)}</Key>
        <LastModified>${f.modifiedTime || new Date().toISOString()}</LastModified>
        <ETag>"${f.id}"</ETag>
        <Size>${f.size || 0}</Size>
        <StorageClass>STANDARD</StorageClass>
    </Contents>`,
        )
        .join("");

    return `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>${escapeXml(bucket)}</Name>
    <Prefix></Prefix>
    <MaxKeys>1000</MaxKeys>
    <IsTruncated>false</IsTruncated>
    ${contents}
</ListBucketResult>`;
}

function escapeXml(str: string): string {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

// ========================================
// AWS Signature V4 Verification
// ========================================

async function verifySignature(request: Request, env: Env): Promise<boolean> {
    const url = new URL(request.url);
    const headers = request.headers;

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

    const datetime = (isQueryAuth ? url.searchParams.get("X-Amz-Date") : headers.get("x-amz-date")) ?? "";

    if (!datetime) return false;

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
        const authHeader = headers.get("Authorization") ?? "";
        const match = authHeader.match(/Signature=([a-f0-9]+)/);
        expectedSignature = match ? match[1] : "";
    }

    return signatureHex === expectedSignature;
}

async function createCanonicalRequest(request: Request, isQueryAuth: boolean): Promise<string> {
    const url = new URL(request.url);

    const method = request.method;
    const canonicalUri = url.pathname || "/";

    const params = Array.from(url.searchParams.entries())
        .filter(([key]) => key !== "X-Amz-Signature")
        .sort(([a], [b]) => {
            if (a < b) return -1;
            if (a > b) return 1;
            return 0;
        })
        .map(([key, val]) => `${encodeRFC3986(key)}=${encodeRFC3986(val)}`)
        .join("&");

    let signedHeadersList: string[];
    if (isQueryAuth) {
        signedHeadersList = (url.searchParams.get("X-Amz-SignedHeaders") ?? "host").split(";");
    } else {
        const authHeader = request.headers.get("Authorization") ?? "";
        const match = authHeader.match(/SignedHeaders=([^,\s]+)/);
        signedHeadersList = match ? match[1].split(";") : ["host"];
    }

    const canonicalHeaders = signedHeadersList
        .map((h) => {
            const headerName = h.toLowerCase();
            let headerValue = "";

            if (headerName === "host") {
                headerValue = url.hostname;
                const port = url.port;
                if (port && !((url.protocol === "https:" && port === "443") || (url.protocol === "http:" && port === "80"))) {
                    headerValue += `:${port}`;
                }
            } else {
                headerValue = request.headers.get(headerName)?.trim() ?? "";
            }

            return `${headerName}:${headerValue}\n`;
        })
        .join("");

    const signedHeaders = signedHeadersList.join(";");
    const payloadHash = request.headers.get("x-amz-content-sha256") ?? (isQueryAuth ? "UNSIGNED-PAYLOAD" : "UNSIGNED-PAYLOAD");

    return [method, canonicalUri, params, canonicalHeaders, signedHeaders, payloadHash].join("\n");
}

function encodeRFC3986(str: string): string {
    return encodeURIComponent(str).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
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
