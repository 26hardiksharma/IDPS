import axios, { AxiosInstance } from "axios";
import { DEFAULT_API_BASE_URL } from "@/lib/constants";

const baseURL = process.env.NEXT_PUBLIC_API_BASE_URL || DEFAULT_API_BASE_URL;

export const apiClient: AxiosInstance = axios.create({
  baseURL,
  timeout: 30000, // 30 seconds for heavy PCAP processing / ML feature extraction
  headers: {
    "Content-Type": "application/json",
    Accept: "application/json",
  },
});

// Response interceptor: ensure errors are sanitized and passed through
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    // Note: To preserve security invariants, we intentionally avoid logging full
    // packet evidence or raw payloads in client console output.
    return Promise.reject(error);
  }
);
