import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { AwsClient } from "aws4fetch";
import { beforeEach, describe, expect, it, vi } from "vitest";

import worker from "../src/index";

const ENV = {
    ACCESS_KEY: "test-access-key",
    SECRET_KEY: "test-secret-key",
    REGION: "auto",
    GOOGLE_CLIENT_ID: "test-client-id",
    GOOGLE_CLIENT_SECRET: "test-client-secret",
    GOOGLE_REFRESH_TOKEN: "test-refresh-token",
    AUTH_KV: createMockKV(),
    FOLDER_CACHE: createMockKV(),
    ALLOWED_BUCKETS: "test-bucket,empty-bucket,my-bucket",
};

const CTX = {
    waitUntil: vi.fn(),
    passThroughOnException: vi.fn(),
};

function createMockKV() {
    const storage = new Map<string, string>();
    return {
        get: vi.fn(async (key: string) => storage.get(key) || null),
        put: vi.fn(async (key: string, value: string, options?: any) => {
            storage.set(key, value);
        }),
        delete: vi.fn(async (key: string) => storage.delete(key)),
        list: vi.fn(async () => ({ keys: [] })),
    };
}

// Google API のモック
global.fetch = vi.fn(async (url: string | URL | Request, init?: any) => {
    const urlStr = typeof url === "string" ? url : url instanceof URL ? url.toString() : url.url;

    // OAuth トークン取得
    if (urlStr.includes("oauth2.googleapis.com/token")) {
        return new Response(
            JSON.stringify({
                access_token: "mock-access-token",
                expires_in: 3600,
            }),
            { status: 200 },
        );
    }

    // フォルダ検索
    if (urlStr.includes("drive/v3/files") && urlStr.includes("mimeType='application/vnd.google-apps.folder'")) {
        return new Response(
            JSON.stringify({
                files: [{ id: "folder-id-123", name: "test-bucket" }],
            }),
            { status: 200 },
        );
    }

    // ファイル検索
    if (urlStr.includes("drive/v3/files") && urlStr.includes("in parents")) {
        return new Response(
            JSON.stringify({
                files: [
                    {
                        id: "file-id-456",
                        name: "test-file.txt",
                        mimeType: "text/plain",
                        size: "11",
                    },
                ],
            }),
            { status: 200 },
        );
    }

    // Resumable upload 初期化
    if (urlStr.includes("uploadType=resumable") && init?.method === "POST") {
        return new Response(null, {
            status: 200,
            headers: { Location: "https://www.googleapis.com/upload/drive/v3/files/uploadid123" },
        });
    }

    // Resumable upload 実行
    if (urlStr.includes("upload/drive/v3/files/uploadid")) {
        return new Response(
            JSON.stringify({
                id: "new-file-id-789",
                name: "uploaded-file.txt",
                mimeType: "text/plain",
            }),
            { status: 200 },
        );
    }

    // ファイルダウンロード
    if (urlStr.includes("alt=media")) {
        return new Response("Hello World", {
            status: 200,
            headers: { "Content-Type": "text/plain" },
        });
    }

    // ファイル削除
    if (init?.method === "DELETE") {
        return new Response(null, { status: 204 });
    }

    return new Response("Not Found", { status: 404 });
}) as any;

describe("S3 API Server with Google Drive Backend", () => {
    const endpoint = "https://s3-api.example.com";

    beforeEach(() => {
        vi.clearAllMocks();
    });

    // 1. PUT (Upload) テスト
    it("should upload file via PUT with Header Auth", async () => {
        const aws4 = new AwsClient({
            accessKeyId: ENV.ACCESS_KEY,
            secretAccessKey: ENV.SECRET_KEY,
            region: ENV.REGION,
            service: "s3",
        });

        const requestUrl = `${endpoint}/test-bucket/test-file.txt`;
        const signedReq = await aws4.sign(requestUrl, {
            method: "PUT",
            headers: {
                "Content-Type": "text/plain",
                "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
            },
            body: "Hello World",
        });

        const response = await worker.fetch(signedReq, ENV, CTX);
        expect(response.status).toBe(200);

        const result = await response.json();
        expect(result).toHaveProperty("id");
    });

    // 2. GET (Download) テスト
    it("should download file via GET with Header Auth", async () => {
        const aws4 = new AwsClient({
            accessKeyId: ENV.ACCESS_KEY,
            secretAccessKey: ENV.SECRET_KEY,
            region: ENV.REGION,
            service: "s3",
        });

        const requestUrl = `${endpoint}/test-bucket/test-file.txt`;
        const signedReq = await aws4.sign(requestUrl, {
            method: "GET",
            headers: {
                "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
            },
        });

        const response = await worker.fetch(signedReq, ENV, CTX);
        expect(response.status).toBe(200);
        expect(await response.text()).toBe("Hello World");
    });

    // 3. DELETE テスト
    it("should delete file via DELETE", async () => {
        const aws4 = new AwsClient({
            accessKeyId: ENV.ACCESS_KEY,
            secretAccessKey: ENV.SECRET_KEY,
            region: ENV.REGION,
            service: "s3",
        });

        const requestUrl = `${endpoint}/test-bucket/test-file.txt`;
        const signedReq = await aws4.sign(requestUrl, {
            method: "DELETE",
            headers: {
                "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
            },
        });

        const response = await worker.fetch(signedReq, ENV, CTX);
        expect(response.status).toBe(204);
    });

    // 4. HEAD (Metadata) テスト
    it("should get file metadata via HEAD", async () => {
        const aws4 = new AwsClient({
            accessKeyId: ENV.ACCESS_KEY,
            secretAccessKey: ENV.SECRET_KEY,
            region: ENV.REGION,
            service: "s3",
        });

        const requestUrl = `${endpoint}/test-bucket/test-file.txt`;
        const signedReq = await aws4.sign(requestUrl, {
            method: "HEAD",
            headers: {
                "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
            },
        });

        const response = await worker.fetch(signedReq, ENV, CTX);
        expect(response.status).toBe(200);
        expect(response.headers.get("Content-Type")).toBe("text/plain");
        expect(response.headers.get("Content-Length")).toBe("11");
    });

    // 5. Presigned URL テスト
    it("should verify presigned URLs from @aws-sdk/s3-request-presigner", async () => {
        const s3 = new S3Client({
            region: ENV.REGION,
            credentials: {
                accessKeyId: ENV.ACCESS_KEY,
                secretAccessKey: ENV.SECRET_KEY,
            },
        });

        const command = new GetObjectCommand({
            Bucket: "my-bucket",
            Key: "my-bucket/test.png",
        });

        const url = await getSignedUrl(s3, command, { expiresIn: 3600 });
        const parsedUrl = new URL(url);

        const testUrl = new URL(endpoint);
        testUrl.hostname = parsedUrl.hostname;
        testUrl.pathname = parsedUrl.pathname;
        testUrl.search = parsedUrl.search;

        const request = new Request(testUrl.toString(), { method: "GET" });
        const response = await worker.fetch(request, ENV, CTX);

        expect(response.status).toBe(200);
    });

    // 6. 不正な署名のテスト
    it("should reject invalid signatures", async () => {
        const request = new Request(`${endpoint}/hack`, {
            method: "GET",
            headers: {
                Authorization: "AWS4-HMAC-SHA256 Credential=bad/20260108/auto/s3/aws4_request, SignedHeaders=host, Signature=wrong",
                "x-amz-date": "20260108T000000Z",
            },
        });

        const response = await worker.fetch(request, ENV, CTX);
        expect(response.status).toBe(403);
    });

    // 7. バケット一覧テスト (LIST)
    it("should list files in bucket", async () => {
        const aws4 = new AwsClient({
            accessKeyId: ENV.ACCESS_KEY,
            secretAccessKey: ENV.SECRET_KEY,
            region: ENV.REGION,
            service: "s3",
        });

        // ファイル一覧を返すようにモックを更新
        const originalFetch = global.fetch;
        (global.fetch as any) = vi.fn(async (url: string, init?: any) => {
            const urlStr = typeof url === "string" ? url : url.toString();

            if (urlStr.includes("oauth2.googleapis.com/token")) {
                return new Response(
                    JSON.stringify({
                        access_token: "mock-access-token",
                        expires_in: 3600,
                    }),
                    { status: 200 },
                );
            }

            if (urlStr.includes("drive/v3/files") && urlStr.includes("mimeType='application/vnd.google-apps.folder'")) {
                return new Response(
                    JSON.stringify({
                        files: [{ id: "folder-id-123", name: "test-bucket" }],
                    }),
                    { status: 200 },
                );
            }

            if (urlStr.includes("drive/v3/files") && urlStr.includes("in parents")) {
                return new Response(
                    JSON.stringify({
                        files: [
                            { id: "1", name: "file1.txt", size: "100", mimeType: "text/plain", modifiedTime: "2024-01-01T00:00:00Z" },
                            { id: "2", name: "file2.txt", size: "200", mimeType: "text/plain", modifiedTime: "2024-01-02T00:00:00Z" },
                        ],
                    }),
                    { status: 200 },
                );
            }

            return new Response("Not Found", { status: 404 });
        });

        const requestUrl = `${endpoint}/test-bucket/`;
        const signedReq = await aws4.sign(requestUrl, {
            method: "GET",
            headers: {
                "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
            },
        });

        const response = await worker.fetch(signedReq, ENV, CTX);
        expect(response.status).toBe(200);

        const xmlText = await response.text();
        expect(xmlText).toContain("<ListBucketResult");
        expect(xmlText).toContain("file1.txt");
        expect(xmlText).toContain("file2.txt");

        global.fetch = originalFetch;
    });

    // 8. 存在しないファイルのHEADリクエスト (404)
    it("should return 404 for HEAD on non-existent file", async () => {
        const aws4 = new AwsClient({
            accessKeyId: ENV.ACCESS_KEY,
            secretAccessKey: ENV.SECRET_KEY,
            region: ENV.REGION,
            service: "s3",
        });

        // ファイルが見つからないケース
        const originalFetch = global.fetch;
        (global.fetch as any) = vi.fn(async (url: string, init?: any) => {
            const urlStr = typeof url === "string" ? url : url.toString();

            if (urlStr.includes("oauth2.googleapis.com/token")) {
                return new Response(
                    JSON.stringify({
                        access_token: "mock-access-token",
                        expires_in: 3600,
                    }),
                    { status: 200 },
                );
            }

            if (urlStr.includes("drive/v3/files") && urlStr.includes("mimeType='application/vnd.google-apps.folder'")) {
                return new Response(
                    JSON.stringify({
                        files: [{ id: "folder-id-123", name: "test-bucket" }],
                    }),
                    { status: 200 },
                );
            }

            if (urlStr.includes("drive/v3/files") && urlStr.includes("in parents")) {
                // ファイルが存在しない
                return new Response(JSON.stringify({ files: [] }), { status: 200 });
            }

            return new Response("Not Found", { status: 404 });
        });

        const requestUrl = `${endpoint}/test-bucket/non-existent.txt`;
        const signedReq = await aws4.sign(requestUrl, {
            method: "HEAD",
            headers: {
                "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
            },
        });

        const response = await worker.fetch(signedReq, ENV, CTX);
        expect(response.status).toBe(404);

        global.fetch = originalFetch;
    });

    // 9. 存在しないファイルのGETリクエスト (404)
    it("should return 404 for GET on non-existent file", async () => {
        const aws4 = new AwsClient({
            accessKeyId: ENV.ACCESS_KEY,
            secretAccessKey: ENV.SECRET_KEY,
            region: ENV.REGION,
            service: "s3",
        });

        const originalFetch = global.fetch;
        (global.fetch as any) = vi.fn(async (url: string, init?: any) => {
            const urlStr = typeof url === "string" ? url : url.toString();

            if (urlStr.includes("oauth2.googleapis.com/token")) {
                return new Response(
                    JSON.stringify({
                        access_token: "mock-access-token",
                        expires_in: 3600,
                    }),
                    { status: 200 },
                );
            }

            if (urlStr.includes("drive/v3/files") && urlStr.includes("mimeType='application/vnd.google-apps.folder'")) {
                return new Response(
                    JSON.stringify({
                        files: [{ id: "folder-id-123", name: "test-bucket" }],
                    }),
                    { status: 200 },
                );
            }

            if (urlStr.includes("drive/v3/files") && urlStr.includes("in parents")) {
                return new Response(JSON.stringify({ files: [] }), { status: 200 });
            }

            return new Response("Not Found", { status: 404 });
        });

        const requestUrl = `${endpoint}/test-bucket/non-existent.txt`;
        const signedReq = await aws4.sign(requestUrl, {
            method: "GET",
            headers: {
                "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
            },
        });

        const response = await worker.fetch(signedReq, ENV, CTX);
        expect(response.status).toBe(404);
        expect(await response.text()).toBe("NoSuchKey");

        global.fetch = originalFetch;
    });

    // 10. 存在しないファイルのDELETEリクエスト (404)
    it("should return 404 for DELETE on non-existent file", async () => {
        const aws4 = new AwsClient({
            accessKeyId: ENV.ACCESS_KEY,
            secretAccessKey: ENV.SECRET_KEY,
            region: ENV.REGION,
            service: "s3",
        });

        const originalFetch = global.fetch;
        (global.fetch as any) = vi.fn(async (url: string, init?: any) => {
            const urlStr = typeof url === "string" ? url : url.toString();

            if (urlStr.includes("oauth2.googleapis.com/token")) {
                return new Response(
                    JSON.stringify({
                        access_token: "mock-access-token",
                        expires_in: 3600,
                    }),
                    { status: 200 },
                );
            }

            if (urlStr.includes("drive/v3/files") && urlStr.includes("mimeType='application/vnd.google-apps.folder'")) {
                return new Response(
                    JSON.stringify({
                        files: [{ id: "folder-id-123", name: "test-bucket" }],
                    }),
                    { status: 200 },
                );
            }

            if (urlStr.includes("drive/v3/files") && urlStr.includes("in parents")) {
                return new Response(JSON.stringify({ files: [] }), { status: 200 });
            }

            return new Response("Not Found", { status: 404 });
        });

        const requestUrl = `${endpoint}/test-bucket/non-existent.txt`;
        const signedReq = await aws4.sign(requestUrl, {
            method: "DELETE",
            headers: {
                "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
            },
        });

        const response = await worker.fetch(signedReq, ENV, CTX);
        expect(response.status).toBe(404);

        global.fetch = originalFetch;
    });

    // 11. 空のバケット一覧
    it("should return empty list for empty bucket", async () => {
        const aws4 = new AwsClient({
            accessKeyId: ENV.ACCESS_KEY,
            secretAccessKey: ENV.SECRET_KEY,
            region: ENV.REGION,
            service: "s3",
        });

        const originalFetch = global.fetch;
        (global.fetch as any) = vi.fn(async (url: string, init?: any) => {
            const urlStr = typeof url === "string" ? url : url.toString();

            if (urlStr.includes("oauth2.googleapis.com/token")) {
                return new Response(
                    JSON.stringify({
                        access_token: "mock-access-token",
                        expires_in: 3600,
                    }),
                    { status: 200 },
                );
            }

            if (urlStr.includes("drive/v3/files") && urlStr.includes("mimeType='application/vnd.google-apps.folder'")) {
                return new Response(
                    JSON.stringify({
                        files: [{ id: "folder-id-123", name: "empty-bucket" }],
                    }),
                    { status: 200 },
                );
            }

            if (urlStr.includes("drive/v3/files") && urlStr.includes("in parents")) {
                return new Response(JSON.stringify({ files: [] }), { status: 200 });
            }

            return new Response("Not Found", { status: 404 });
        });

        const requestUrl = `${endpoint}/empty-bucket/`;
        const signedReq = await aws4.sign(requestUrl, {
            method: "GET",
            headers: {
                "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
            },
        });

        const response = await worker.fetch(signedReq, ENV, CTX);
        expect(response.status).toBe(200);

        const xmlText = await response.text();
        expect(xmlText).toContain("<ListBucketResult");
        expect(xmlText).not.toContain("<Contents>");

        global.fetch = originalFetch;
    });
});
