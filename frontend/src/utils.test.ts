import { describe, expect, it } from "vitest";

import { formatBytes, isPublicIp, shortId } from "./utils";

describe("presentation utilities", () => {
  it("formats byte units", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(2048)).toBe("2.00 KB");
  });

  it("classifies common private and public addresses", () => {
    expect(isPublicIp("10.44.44.21")).toBe(false);
    expect(isPublicIp("192.168.1.1")).toBe(false);
    expect(isPublicIp("fe80::7a8c:77ff:feb6:6e4e")).toBe(false);
    expect(isPublicIp("ff02::fb")).toBe(false);
    expect(isPublicIp("8.8.8.8")).toBe(true);
    expect(isPublicIp("2606:4700:4700::1111")).toBe(true);
  });

  it("shortens identifiers for dense tables", () => {
    expect(shortId("12345678-abcd")).toBe("12345678");
  });
});
