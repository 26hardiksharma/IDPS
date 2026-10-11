import axios, { AxiosError } from "axios";
import { ApiErrorResponse } from "@/types/api";

export interface ParsedApiError {
  message: string;
  statusCode?: number;
  code?: string;
  isNetworkError: boolean;
  isTimeout: boolean;
}

export function parseApiError(error: unknown): ParsedApiError {
  if (axios.isAxiosError(error)) {
    const axiosErr = error as AxiosError<ApiErrorResponse>;

    if (axiosErr.code === "ECONNABORTED") {
      return {
        message: "Request timed out. The IDPS backend may be processing large PCAP data.",
        statusCode: 408,
        code: "TIMEOUT",
        isNetworkError: false,
        isTimeout: true,
      };
    }

    if (!axiosErr.response) {
      return {
        message:
          "Unable to connect to the XAI-IDPS backend. Ensure FastAPI is running at " +
          (process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8000"),
        code: "NETWORK_ERROR",
        isNetworkError: true,
        isTimeout: false,
      };
    }

    const serverDetail = axiosErr.response.data?.detail;
    const message =
      typeof serverDetail === "string"
        ? serverDetail
        : axiosErr.message || "An unexpected API error occurred.";

    return {
      message,
      statusCode: axiosErr.response.status,
      code: axiosErr.response.data?.code,
      isNetworkError: false,
      isTimeout: false,
    };
  }

  if (error instanceof Error) {
    return {
      message: error.message,
      isNetworkError: false,
      isTimeout: false,
    };
  }

  return {
    message: "An unknown error occurred while communicating with the IDPS service.",
    isNetworkError: false,
    isTimeout: false,
  };
}
