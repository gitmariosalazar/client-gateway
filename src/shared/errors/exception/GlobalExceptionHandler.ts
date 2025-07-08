import {
  Catch,
  RpcExceptionFilter,
  ArgumentsHost,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { RpcException } from '@nestjs/microservices';
import { ApiResponse } from '../responses/ApiResponse';
import { statusCode } from 'src/settings/environments/status-code';

@Catch(RpcException)
export class RcpCustomExceptionFilter
  implements RpcExceptionFilter<RpcException>
{
  private readonly logger = new Logger(RcpCustomExceptionFilter.name);

  catch(exception: RpcException, host: ArgumentsHost): Observable<any> {
    const ctx = host.switchToRpc();
    const response = ctx.getContext();

    const errorResponse = exception.getError();
    this.logger.error(`Caught RpcException: ${JSON.stringify(errorResponse)}`);
    if (errorResponse instanceof AggregateError) {
      const errorDetails = errorResponse.errors || [];
      const connectionErrors = errorDetails.filter(
        (err: any) => err.code === 'ECONNREFUSED',
      );

      if (connectionErrors.length > 0) {
        this.logger.error('Connection refused error detected:');
        connectionErrors.forEach((err: any) => {
          this.logger.error(`Failed to connect to ${err.address}:${err.port}`);
        });

        const apiResponse = new ApiResponse(
          [
            'Connection refused by target service. Please check the service availability.',
          ],
          null,
          response.req.url,
        );
        apiResponse.status_code = statusCode.SERVICE_UNAVAILABLE;
        return response.status(statusCode.SERVICE_UNAVAILABLE).json({
          time: new Date().toISOString(),
          message:
            typeof apiResponse.message === 'string'
              ? [apiResponse.message]
              : apiResponse.message,
          url: apiResponse.url,
          data: apiResponse.data,
          status_code: apiResponse.status_code,
        });
      }
    }

    const err = errorResponse as any;
    if (
      typeof err === 'object' &&
      err?.error?.statusCode === statusCode.SERVICE_UNAVAILABLE &&
      err?.error?.message === 'Target microservice is not responding'
    ) {
      this.logger.warn('Timeout: Target microservice is not responding');

      const apiResponse = new ApiResponse(
        [err.error.message],
        null,
        response.req.url,
      );
      apiResponse.status_code = statusCode.SERVICE_UNAVAILABLE;

      return response.status(statusCode.SERVICE_UNAVAILABLE).json({
        time: new Date().toISOString(),
        message: apiResponse.message,
        url: apiResponse.url,
        data: apiResponse.data,
        status_code: apiResponse.status_code,
      });
    }

    let apiResponse = new ApiResponse(
      ['An unknown error occurred'],
      null,
      response.req.url,
    );
    let httpStatusCode = 500;

    if (typeof errorResponse === 'object' && errorResponse !== null) {
      const { statusCode: code, message } = errorResponse as {
        statusCode: number;
        message: string;
      };
      httpStatusCode = code || 500;
      apiResponse = new ApiResponse(message, null, response.req.url);
      apiResponse.status_code = httpStatusCode;
    } else if (typeof errorResponse === 'string') {
      apiResponse = new ApiResponse(
        [errorResponse || 'An unknown error occurred'],
        null,
        response.req.url,
      );
      apiResponse.status_code = httpStatusCode;
    } else {
      apiResponse.status_code = httpStatusCode;
    }

    return response.status(httpStatusCode).json({
      time: new Date().toISOString(),
      message:
        typeof apiResponse.message === 'string'
          ? [apiResponse.message]
          : apiResponse.message,
      url: apiResponse.url,
      data: apiResponse.data,
      status_code: apiResponse.status_code,
    });
  }
}
