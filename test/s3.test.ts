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
            endpoint: `${endpoint}/my-bucket`,
            region: ENV.REGION,
            credentials: {
                accessKeyId: ENV.ACCESS_KEY,
                secretAccessKey: ENV.SECRET_KEY,
            },
        });

        const command = new GetObjectCommand({
            Bucket: "my-bucket",
            Key: "test.png",
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

    // 12. ネストされたフォルダーへのアップロード
    it("should upload file to nested directory structure", async () => {
        const aws4 = new AwsClient({
            accessKeyId: ENV.ACCESS_KEY,
            secretAccessKey: ENV.SECRET_KEY,
            region: ENV.REGION,
            service: "s3",
        });

        const folderIds = {
            bucket: "bucket-id-123",
            dir1: "dir1-id-456",
            dir2: "dir2-id-789",
        };

        const originalFetch = global.fetch;
        (global.fetch as any) = vi.fn(async (url: string, init?: any) => {
            const urlStr = typeof url === "string" ? url : url.toString();

            // OAuth トークン
            if (urlStr.includes("oauth2.googleapis.com/token")) {
                return new Response(
                    JSON.stringify({
                        access_token: "mock-access-token",
                        expires_in: 3600,
                    }),
                    { status: 200 },
                );
            }

            // フォルダ作成 (POST)
            if (urlStr === "https://www.googleapis.com/drive/v3/files" && init?.method === "POST") {
                const body = JSON.parse(init.body);
                if (body.mimeType === "application/vnd.google-apps.folder") {
                    // フォルダ名に応じてIDを返す
                    if (body.name === "dir1") {
                        return new Response(JSON.stringify({ id: folderIds.dir1, name: "dir1" }), { status: 200 });
                    } else if (body.name === "dir2") {
                        return new Response(JSON.stringify({ id: folderIds.dir2, name: "dir2" }), { status: 200 });
                    }
                }
            }

            // フォルダ検索 - バケット (親なし)
            if (urlStr.includes("name='test-bucket'") && urlStr.includes("mimeType='application/vnd.google-apps.folder'") && !urlStr.includes("in parents")) {
                return new Response(
                    JSON.stringify({
                        files: [{ id: folderIds.bucket, name: "test-bucket" }],
                    }),
                    { status: 200 },
                );
            }

            // フォルダ検索 - dir1
            if (urlStr.includes("name='dir1'") && urlStr.includes("mimeType='application/vnd.google-apps.folder'")) {
                if (urlStr.includes(`'${folderIds.bucket}' in parents`)) {
                    return new Response(
                        JSON.stringify({
                            files: [{ id: folderIds.dir1, name: "dir1" }],
                        }),
                        { status: 200 },
                    );
                } else {
                    return new Response(JSON.stringify({ files: [] }), { status: 200 });
                }
            }

            // フォルダ検索 - dir2
            if (urlStr.includes("name='dir2'") && urlStr.includes("mimeType='application/vnd.google-apps.folder'")) {
                if (urlStr.includes(`'${folderIds.dir1}' in parents`)) {
                    return new Response(
                        JSON.stringify({
                            files: [{ id: folderIds.dir2, name: "dir2" }],
                        }),
                        { status: 200 },
                    );
                } else {
                    return new Response(JSON.stringify({ files: [] }), { status: 200 });
                }
            }

            // Resumable upload 初期化
            if (urlStr.includes("uploadType=resumable") && init?.method === "POST") {
                const body = JSON.parse(init.body);
                // 親フォルダがdir2であることを確認
                expect(body.parents).toEqual([folderIds.dir2]);
                expect(body.name).toBe("file.txt");

                return new Response(null, {
                    status: 200,
                    headers: { Location: "https://www.googleapis.com/upload/drive/v3/files/uploadid999" },
                });
            }

            // Resumable upload 実行
            if (urlStr.includes("upload/drive/v3/files/uploadid999")) {
                return new Response(
                    JSON.stringify({
                        id: "nested-file-id-999",
                        name: "file.txt",
                        mimeType: "text/plain",
                    }),
                    { status: 200 },
                );
            }

            console.error("Unhandled URL:", urlStr);
            return new Response(JSON.stringify({ error: "Not Found" }), { status: 404 });
        });

        const requestUrl = `${endpoint}/test-bucket/dir1/dir2/file.txt`;
        const signedReq = await aws4.sign(requestUrl, {
            method: "PUT",
            headers: {
                "Content-Type": "text/plain",
                "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
            },
            body: "Nested content",
        });

        const response = await worker.fetch(signedReq, ENV, CTX);
        expect(response.status).toBe(200);
        const result = await response.json();
        expect(result.id).toBe("nested-file-id-999");
        expect(result.name).toBe("file.txt");

        global.fetch = originalFetch;
    });

    // 13. ネストされたフォルダーからのダウンロード
    it("should download file from nested directory structure", async () => {
        const aws4 = new AwsClient({
            accessKeyId: ENV.ACCESS_KEY,
            secretAccessKey: ENV.SECRET_KEY,
            region: ENV.REGION,
            service: "s3",
        });

        const folderIds = {
            bucket: "bucket-id-123",
            images: "images-id-456",
            photos: "photos-id-789",
        };

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

            // フォルダ作成 (POST)
            if (urlStr === "https://www.googleapis.com/drive/v3/files" && init?.method === "POST") {
                const body = JSON.parse(init.body);
                if (body.mimeType === "application/vnd.google-apps.folder") {
                    if (body.name === "images") {
                        return new Response(JSON.stringify({ id: folderIds.images, name: "images" }), { status: 200 });
                    } else if (body.name === "photos") {
                        return new Response(JSON.stringify({ id: folderIds.photos, name: "photos" }), { status: 200 });
                    }
                }
            }

            // バケット検索
            if (urlStr.includes("name='test-bucket'") && urlStr.includes("mimeType='application/vnd.google-apps.folder'") && !urlStr.includes("in parents")) {
                return new Response(
                    JSON.stringify({
                        files: [{ id: folderIds.bucket, name: "test-bucket" }],
                    }),
                    { status: 200 },
                );
            }

            // images フォルダ検索
            if (urlStr.includes("name='images'") && urlStr.includes("mimeType='application/vnd.google-apps.folder'")) {
                if (urlStr.includes(`'${folderIds.bucket}' in parents`)) {
                    return new Response(
                        JSON.stringify({
                            files: [{ id: folderIds.images, name: "images" }],
                        }),
                        { status: 200 },
                    );
                } else {
                    return new Response(JSON.stringify({ files: [] }), { status: 200 });
                }
            }

            // photos フォルダ検索
            if (urlStr.includes("name='photos'") && urlStr.includes("mimeType='application/vnd.google-apps.folder'")) {
                if (urlStr.includes(`'${folderIds.images}' in parents`)) {
                    return new Response(
                        JSON.stringify({
                            files: [{ id: folderIds.photos, name: "photos" }],
                        }),
                        { status: 200 },
                    );
                } else {
                    return new Response(JSON.stringify({ files: [] }), { status: 200 });
                }
            }

            // ファイル検索 - photo.jpg
            if (urlStr.includes("name='photo.jpg'") && urlStr.includes(`'${folderIds.photos}' in parents`)) {
                return new Response(
                    JSON.stringify({
                        files: [
                            {
                                id: "photo-file-id-999",
                                name: "photo.jpg",
                                mimeType: "image/jpeg",
                                size: "12345",
                            },
                        ],
                    }),
                    { status: 200 },
                );
            }

            // ファイルダウンロード
            if (urlStr.includes("photo-file-id-999") && urlStr.includes("alt=media")) {
                return new Response("Binary image data", {
                    status: 200,
                    headers: { "Content-Type": "image/jpeg" },
                });
            }

            console.error("Unhandled URL:", urlStr);
            return new Response(JSON.stringify({ error: "Not Found" }), { status: 404 });
        });

        const requestUrl = `${endpoint}/test-bucket/images/photos/photo.jpg`;
        const signedReq = await aws4.sign(requestUrl, {
            method: "GET",
            headers: {
                "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
            },
        });

        const response = await worker.fetch(signedReq, ENV, CTX);
        expect(response.status).toBe(200);
        expect(response.headers.get("Content-Type")).toBe("image/jpeg");
        expect(await response.text()).toBe("Binary image data");

        global.fetch = originalFetch;
    });

    // 14. ネストされたフォルダーからの削除
    it("should delete file from nested directory structure", async () => {
        const aws4 = new AwsClient({
            accessKeyId: ENV.ACCESS_KEY,
            secretAccessKey: ENV.SECRET_KEY,
            region: ENV.REGION,
            service: "s3",
        });

        const folderIds = {
            bucket: "bucket-id-123",
            docs: "docs-id-456",
            archive: "archive-id-789",
        };

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

            // フォルダ作成 (POST)
            if (urlStr === "https://www.googleapis.com/drive/v3/files" && init?.method === "POST") {
                const body = JSON.parse(init.body);
                if (body.mimeType === "application/vnd.google-apps.folder") {
                    if (body.name === "docs") {
                        return new Response(JSON.stringify({ id: folderIds.docs, name: "docs" }), { status: 200 });
                    } else if (body.name === "archive") {
                        return new Response(JSON.stringify({ id: folderIds.archive, name: "archive" }), { status: 200 });
                    }
                }
            }

            if (urlStr.includes("name='test-bucket'") && urlStr.includes("mimeType='application/vnd.google-apps.folder'") && !urlStr.includes("in parents")) {
                return new Response(
                    JSON.stringify({
                        files: [{ id: folderIds.bucket, name: "test-bucket" }],
                    }),
                    { status: 200 },
                );
            }

            if (urlStr.includes("name='docs'") && urlStr.includes("mimeType='application/vnd.google-apps.folder'")) {
                if (urlStr.includes(`'${folderIds.bucket}' in parents`)) {
                    return new Response(
                        JSON.stringify({
                            files: [{ id: folderIds.docs, name: "docs" }],
                        }),
                        { status: 200 },
                    );
                } else {
                    return new Response(JSON.stringify({ files: [] }), { status: 200 });
                }
            }

            if (urlStr.includes("name='archive'") && urlStr.includes("mimeType='application/vnd.google-apps.folder'")) {
                if (urlStr.includes(`'${folderIds.docs}' in parents`)) {
                    return new Response(
                        JSON.stringify({
                            files: [{ id: folderIds.archive, name: "archive" }],
                        }),
                        { status: 200 },
                    );
                } else {
                    return new Response(JSON.stringify({ files: [] }), { status: 200 });
                }
            }

            if (urlStr.includes("name='old.pdf'") && urlStr.includes(`'${folderIds.archive}' in parents`)) {
                return new Response(
                    JSON.stringify({
                        files: [
                            {
                                id: "old-pdf-id-999",
                                name: "old.pdf",
                                mimeType: "application/pdf",
                                size: "54321",
                            },
                        ],
                    }),
                    { status: 200 },
                );
            }

            if (urlStr.includes("old-pdf-id-999") && init?.method === "DELETE") {
                return new Response(null, { status: 204 });
            }

            console.error("Unhandled URL:", urlStr);
            return new Response(JSON.stringify({ error: "Not Found" }), { status: 404 });
        });

        const requestUrl = `${endpoint}/test-bucket/docs/archive/old.pdf`;
        const signedReq = await aws4.sign(requestUrl, {
            method: "DELETE",
            headers: {
                "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
            },
        });

        const response = await worker.fetch(signedReq, ENV, CTX);
        expect(response.status).toBe(204);

        global.fetch = originalFetch;
    });

    // 15. 深くネストされたフォルダーのメタデータ取得
    it("should get metadata for file in deeply nested structure", async () => {
        const aws4 = new AwsClient({
            accessKeyId: ENV.ACCESS_KEY,
            secretAccessKey: ENV.SECRET_KEY,
            region: ENV.REGION,
            service: "s3",
        });

        const folderIds = {
            bucket: "bucket-id-123",
            a: "a-id-111",
            b: "b-id-222",
            c: "c-id-333",
            d: "d-id-444",
        };

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

            // フォルダ作成 (POST)
            if (urlStr === "https://www.googleapis.com/drive/v3/files" && init?.method === "POST") {
                const body = JSON.parse(init.body);
                if (body.mimeType === "application/vnd.google-apps.folder") {
                    if (body.name === "a") {
                        return new Response(JSON.stringify({ id: folderIds.a, name: "a" }), { status: 200 });
                    } else if (body.name === "b") {
                        return new Response(JSON.stringify({ id: folderIds.b, name: "b" }), { status: 200 });
                    } else if (body.name === "c") {
                        return new Response(JSON.stringify({ id: folderIds.c, name: "c" }), { status: 200 });
                    } else if (body.name === "d") {
                        return new Response(JSON.stringify({ id: folderIds.d, name: "d" }), { status: 200 });
                    }
                }
            }

            // フォルダ階層の検索
            if (urlStr.includes("name='test-bucket'") && urlStr.includes("mimeType='application/vnd.google-apps.folder'") && !urlStr.includes("in parents")) {
                return new Response(JSON.stringify({ files: [{ id: folderIds.bucket, name: "test-bucket" }] }), { status: 200 });
            }
            if (urlStr.includes("name='a'") && urlStr.includes("mimeType='application/vnd.google-apps.folder'")) {
                if (urlStr.includes(`'${folderIds.bucket}' in parents`)) {
                    return new Response(JSON.stringify({ files: [{ id: folderIds.a, name: "a" }] }), { status: 200 });
                } else {
                    return new Response(JSON.stringify({ files: [] }), { status: 200 });
                }
            }
            if (urlStr.includes("name='b'") && urlStr.includes("mimeType='application/vnd.google-apps.folder'")) {
                if (urlStr.includes(`'${folderIds.a}' in parents`)) {
                    return new Response(JSON.stringify({ files: [{ id: folderIds.b, name: "b" }] }), { status: 200 });
                } else {
                    return new Response(JSON.stringify({ files: [] }), { status: 200 });
                }
            }
            if (urlStr.includes("name='c'") && urlStr.includes("mimeType='application/vnd.google-apps.folder'")) {
                if (urlStr.includes(`'${folderIds.b}' in parents`)) {
                    return new Response(JSON.stringify({ files: [{ id: folderIds.c, name: "c" }] }), { status: 200 });
                } else {
                    return new Response(JSON.stringify({ files: [] }), { status: 200 });
                }
            }
            if (urlStr.includes("name='d'") && urlStr.includes("mimeType='application/vnd.google-apps.folder'")) {
                if (urlStr.includes(`'${folderIds.c}' in parents`)) {
                    return new Response(JSON.stringify({ files: [{ id: folderIds.d, name: "d" }] }), { status: 200 });
                } else {
                    return new Response(JSON.stringify({ files: [] }), { status: 200 });
                }
            }

            // ファイル検索
            if (urlStr.includes("name='deep.txt'") && urlStr.includes(`'${folderIds.d}' in parents`)) {
                return new Response(
                    JSON.stringify({
                        files: [
                            {
                                id: "deep-file-id-999",
                                name: "deep.txt",
                                mimeType: "text/plain",
                                size: "999",
                            },
                        ],
                    }),
                    { status: 200 },
                );
            }

            console.error("Unhandled URL:", urlStr);
            return new Response(JSON.stringify({ error: "Not Found" }), { status: 404 });
        });

        const requestUrl = `${endpoint}/test-bucket/a/b/c/d/deep.txt`;
        const signedReq = await aws4.sign(requestUrl, {
            method: "HEAD",
            headers: {
                "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
            },
        });

        const response = await worker.fetch(signedReq, ENV, CTX);
        expect(response.status).toBe(200);
        expect(response.headers.get("Content-Type")).toBe("text/plain");
        expect(response.headers.get("Content-Length")).toBe("999");
        expect(response.headers.get("ETag")).toBe('"deep-file-id-999"');

        global.fetch = originalFetch;
    });

    // ========================================
    // Public Read Tests
    // ========================================

    const PUBLIC_READ_ENV = {
        ...ENV,
        PUBLIC_READ_BUCKETS: "public-bucket",
        ALLOWED_BUCKETS: "test-bucket,empty-bucket,my-bucket,public-bucket",
    };

    // 16. Public read bucket - unsigned GET should succeed
    it("should allow unsigned GET on public read bucket", async () => {
        const request = new Request(`${endpoint}/public-bucket/test-file.txt`, {
            method: "GET",
        });

        const response = await worker.fetch(request, PUBLIC_READ_ENV, CTX);
        expect(response.status).toBe(200);
        expect(await response.text()).toBe("Hello World");
    });

    // 17. Public read bucket - unsigned HEAD should succeed
    it("should allow unsigned HEAD on public read bucket", async () => {
        const request = new Request(`${endpoint}/public-bucket/test-file.txt`, {
            method: "HEAD",
        });

        const response = await worker.fetch(request, PUBLIC_READ_ENV, CTX);
        expect(response.status).toBe(200);
        expect(response.headers.get("Content-Type")).toBe("text/plain");
        expect(response.headers.get("Content-Length")).toBe("11");
    });

    // 18. Public read bucket - unsigned PUT should be rejected
    it("should reject unsigned PUT on public read bucket", async () => {
        const request = new Request(`${endpoint}/public-bucket/test-file.txt`, {
            method: "PUT",
            headers: { "Content-Type": "text/plain" },
            body: "Hello World",
        });

        const response = await worker.fetch(request, PUBLIC_READ_ENV, CTX);
        expect(response.status).toBe(403);
    });

    // 19. Public read bucket - unsigned DELETE should be rejected
    it("should reject unsigned DELETE on public read bucket", async () => {
        const request = new Request(`${endpoint}/public-bucket/test-file.txt`, {
            method: "DELETE",
        });

        const response = await worker.fetch(request, PUBLIC_READ_ENV, CTX);
        expect(response.status).toBe(403);
    });

    // 20. Non-public bucket - unsigned GET should still be rejected
    it("should reject unsigned GET on non-public bucket", async () => {
        const request = new Request(`${endpoint}/test-bucket/test-file.txt`, {
            method: "GET",
        });

        const response = await worker.fetch(request, PUBLIC_READ_ENV, CTX);
        expect(response.status).toBe(403);
    });

    // 21. Public read bucket - unsigned list (GET without key) should succeed
    it("should allow unsigned list on public read bucket", async () => {
        const request = new Request(`${endpoint}/public-bucket/`, {
            method: "GET",
        });

        const response = await worker.fetch(request, PUBLIC_READ_ENV, CTX);
        expect(response.status).toBe(200);
        const xmlText = await response.text();
        expect(xmlText).toContain("<ListBucketResult");
    });
});
