/**
 * IP & Subnet Matching Helper
 *
 * Cung cấp các tiện ích chuẩn hóa địa chỉ IP, xác thực định dạng IPv4/IPv6/CIDR
 * và kiểm tra IP thuộc Whitelist / CIDR subnet.
 */

import { isIP } from "node:net";

/**
 * Chuẩn hóa địa chỉ IP (loại bỏ IPv4-mapped IPv6 ::ffff:, khoảng trắng và chuyển về chữ thường)
 */
export function normalizeIp(ip: string): string {
  if (!ip || typeof ip !== "string") return "";
  const trimmed = ip.trim().toLowerCase();
  if (trimmed.startsWith("::ffff:")) {
    const mapped = trimmed.slice(7);
    if (mapped.includes(".")) {
      return mapped;
    }
  }
  return trimmed;
}

/**
 * Chuyển đổi địa chỉ IPv4 dạng chuỗi "a.b.c.d" sang số nguyên không dấu 32-bit
 */
function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let res = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const num = parseInt(part, 10);
    if (num < 0 || num > 255) return null;
    res = (res << 8) + num;
  }
  return res >>> 0;
}

/**
 * Kiểm tra xem một địa chỉ IPv4 có nằm trong dải CIDR (e.g., "192.168.1.0/24", "10.0.0.0/8") hay không
 */
export function isIpv4InCidr(ip: string, cidr: string): boolean {
  const [range, prefixStr] = cidr.split("/");
  if (!range || !prefixStr) return false;

  const prefix = parseInt(prefixStr, 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;

  const ipInt = ipv4ToInt(ip);
  const rangeInt = ipv4ToInt(range);
  if (ipInt === null || rangeInt === null) return false;

  if (prefix === 0) return true;

  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (rangeInt & mask);
}

/**
 * Phân tích chuỗi IPv6 (bao gồm dạng nén :: hoặc IPv4-embedded) sang số nguyên BigInt 128-bit.
 */
function ipv6ToBigInt(ip: string): bigint | null {
  if (!ip || isIP(ip) !== 6) return null;

  const parseSegmentList = (seg: string): number[] | null => {
    if (!seg) return [];
    const parts = seg.split(":");
    const words: number[] = [];
    for (let i = 0; i < parts.length; i += 1) {
      const part = parts[i];
      if (part.includes(".")) {
        if (i !== parts.length - 1) return null;
        const v4Int = ipv4ToInt(part);
        if (v4Int === null) return null;
        words.push((v4Int >>> 16) & 0xffff, v4Int & 0xffff);
      } else {
        if (!/^[0-9a-f]{1,4}$/i.test(part)) return null;
        words.push(parseInt(part, 16));
      }
    }
    return words;
  };

  let hextets: number[];
  if (ip.includes("::")) {
    const halves = ip.split("::");
    if (halves.length !== 2) return null;
    const left = parseSegmentList(halves[0]);
    const right = parseSegmentList(halves[1]);
    if (!left || !right) return null;
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    hextets = [...left, ...Array<number>(missing).fill(0), ...right];
  } else {
    const parsed = parseSegmentList(ip);
    if (!parsed || parsed.length !== 8) return null;
    hextets = parsed;
  }

  let result = 0n;
  for (const h of hextets) {
    result = (result << 16n) | BigInt(h);
  }
  return result;
}

/**
 * Kiểm tra xem một địa chỉ IPv6 có nằm trong dải CIDR (e.g., "2001:db8::/32", "fe80::/10") hay không.
 */
export function isIpv6InCidr(ip: string, cidr: string): boolean {
  const parts = cidr.split("/");
  if (parts.length !== 2) return false;
  const [range, prefixStr] = parts;
  if (!range || !prefixStr || !/^\d+$/.test(prefixStr)) return false;

  const prefix = parseInt(prefixStr, 10);
  if (Number.isNaN(prefix) || prefix < 0 || prefix > 128) return false;

  const ipInt = ipv6ToBigInt(ip);
  const rangeInt = ipv6ToBigInt(range);
  if (ipInt === null || rangeInt === null) return false;

  if (prefix === 0) return true;

  const allOnes = (1n << 128n) - 1n;
  const mask = (allOnes << BigInt(128 - prefix)) & allOnes;
  return (ipInt & mask) === (rangeInt & mask);
}

/**
 * Kiểm tra định dạng hợp lệ của địa chỉ IPv4, IPv6 hoặc dải CIDR (IPv4 /0..32, IPv6 /0..128).
 */
export function isValidIpOrCidr(value: string): boolean {
  if (!value || typeof value !== "string") return false;
  const trimmed = value.trim();
  if (!trimmed) return false;

  if (!trimmed.includes("/")) {
    return isIP(trimmed) !== 0;
  }

  const parts = trimmed.split("/");
  if (parts.length !== 2) return false;
  const [address, prefixStr] = parts;
  if (!address || !prefixStr || !/^\d+$/.test(prefixStr)) return false;

  const prefix = Number(prefixStr);
  const version = isIP(address);
  if (version === 4) {
    return prefix >= 0 && prefix <= 32;
  }
  if (version === 6) {
    return prefix >= 0 && prefix <= 128;
  }
  return false;
}

/**
 * Kiểm tra xem clientIp có khớp với bất kỳ địa chỉ / dải CIDR nào trong whitelist hay không
 *
 * Hỗ trợ:
 * - Khớp chính xác IPv4 ("127.0.0.1", "118.69.123.45")
 * - Khớp chính xác IPv6 ("::1", "fe80::1")
 * - Dải IPv4 CIDR ("10.0.0.0/8", "172.16.0.0/12", "192.168.1.0/24", "118.69.123.0/24")
 * - Dải IPv6 CIDR ("2001:db8::/32", "fe80::/10")
 */
export function isIpInWhitelist(
  clientIp: string,
  whitelist: (string | unknown)[],
): boolean {
  if (!clientIp || !Array.isArray(whitelist) || whitelist.length === 0) {
    return false;
  }

  const normalizedClient = normalizeIp(clientIp);
  if (!normalizedClient) return false;

  for (const item of whitelist) {
    if (typeof item !== "string") continue;
    const entry = normalizeIp(item);
    if (!entry) continue;

    // 1. Khớp chính xác
    if (normalizedClient === entry) {
      return true;
    }

    // 2. Khớp CIDR subnet (chỉ áp dụng nếu entry có chứa '/')
    if (entry.includes("/")) {
      const clientVersion = isIP(normalizedClient);
      if (clientVersion === 4 && isIpv4InCidr(normalizedClient, entry)) {
        return true;
      }
      if (clientVersion === 6 && isIpv6InCidr(normalizedClient, entry)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Trích xuất địa chỉ IP của Client một cách an toàn và chuẩn hóa.
 * (SEC-19: Chống IP spoofing qua header X-Forwarded-For không tin cậy)
 */
export function getClientIp(req: {
  ip?: string;
  socket?: { remoteAddress?: string };
}): string {
  const raw = req.ip || req.socket?.remoteAddress || "";
  return normalizeIp(raw);
}
