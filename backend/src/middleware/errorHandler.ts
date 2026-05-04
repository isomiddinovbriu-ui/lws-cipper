import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';

export interface ApiError extends Error {
  statusCode?: number;
  details?: unknown;
}

/**
 * Global error handler middleware
 */
export function errorHandler(
  err: ApiError,
  req: Request,
  res: Response,
  _next: NextFunction
): void {
  const statusCode = err.statusCode ?? 500;
  const message = err.message ?? 'Internal Server Error';

  logger.error(`[${req.method}] ${req.path} - ${statusCode}: ${message}`, {
    stack: err.stack,
    details: err.details,
  });

  const body: Record<string, unknown> = { message, statusCode };
  if (process.env.NODE_ENV !== 'production') body.stack = err.stack;
  if (err.details !== undefined) body.details = err.details;

  res.status(statusCode).json({ success: false, error: body });
}

/**
 * 404 handler - must be registered after all routes
 */
export function notFoundHandler(req: Request, res: Response): void {
  res.status(404).json({
    success: false,
    error: {
      message: `Route ${req.method} ${req.path} not found`,
      statusCode: 404,
    },
  });
}

/**
 * Factory for creating API errors with status codes
 */
export function createError(message: string, statusCode = 400, details?: unknown): ApiError {
  const error = new Error(message) as ApiError;
  error.statusCode = statusCode;
  error.details = details;
  return error;
}
